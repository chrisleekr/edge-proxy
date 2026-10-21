package main

import (
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Mock microservices for the capacity test (scripts/capacity-max.sh). Each
// answers its routes with the latency and size of a real service, and sends
// Server-Timing with the time it spent, so the load test can subtract it and
// measure what the edge adds to each request.

// filler is the shared response body; handlers write a prefix of it, so a
// response costs no allocation for its body.
var filler = []byte(strings.Repeat("abcdefghijklmnopqrstuvwxyz012345", 1<<15)) // 1 MiB

// lognormal draws a latency with the given median and 99th percentile, the
// usual shape of service latency: most requests near the median, a long tail.
func lognormal(median, p99 time.Duration) time.Duration {
	sigma := math.Log(float64(p99)/float64(median)) / 2.3263                   // z for p99
	return time.Duration(float64(median) * math.Exp(sigma*rand.NormFloat64())) //nolint:gosec // mock latency needs no cryptographic randomness
}

func between(lo, hi int) int { return lo + rand.IntN(hi-lo+1) } //nolint:gosec // mock sizes need no cryptographic randomness

// reply waits d, as the service's own work, then answers status with n bytes.
// Server-Timing covers the time from start, which callers set after reading
// any request body: moving the body through the edge counts as edge time.
func reply(w http.ResponseWriter, r *http.Request, start time.Time, d time.Duration, status, n int, contentType string) {
	select {
	case <-time.After(d):
	case <-r.Context().Done():
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.Header().Set("Server-Timing", fmt.Sprintf("app;dur=%.3f", float64(time.Since(start))/float64(time.Millisecond)))
	w.WriteHeader(status)
	_, _ = w.Write(filler[:n])
}

const jsonType, htmlType = "application/json", "text/html; charset=utf-8"

// services maps each service name to its handler.
var services = map[string]http.HandlerFunc{
	// catalog: read-heavy product API.
	"catalog": func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		switch r.URL.Path {
		case "/api/items":
			reply(w, r, start, lognormal(15*time.Millisecond, 120*time.Millisecond), 200, between(2<<10, 8<<10), jsonType)
		case "/api/fast":
			reply(w, r, start, time.Millisecond, 200, 200, jsonType)
		case "/api/slow":
			reply(w, r, start, time.Duration(between(300, 2000))*time.Millisecond, 200, 4<<10, jsonType)
		default:
			http.NotFound(w, r)
		}
	},
	// orders: writes with request bodies, and the failure cases.
	"orders": func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/orders":
			_, _ = io.Copy(io.Discard, r.Body)
			reply(w, r, time.Now(), lognormal(30*time.Millisecond, 100*time.Millisecond), 201, 512, jsonType)
		case "/api/flaky":
			status := 200
			if rand.IntN(50) == 0 { //nolint:gosec // 2% failures, not a secret
				status = 503
			}
			reply(w, r, time.Now(), 10*time.Millisecond, status, 256, jsonType)
		case "/api/timeout":
			// Longer than the route's upstream timeout, so the edge answers 504.
			reply(w, r, time.Now(), 5*time.Second, 200, 256, jsonType)
		default:
			http.NotFound(w, r)
		}
	},
	// account: sign-in and signed-in pages.
	"account": func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login" && r.Method == http.MethodPost:
			_, _ = io.Copy(io.Discard, r.Body)
			reply(w, r, time.Now(), lognormal(50*time.Millisecond, 150*time.Millisecond), 200, 256, jsonType)
		case strings.HasPrefix(r.URL.Path, "/private/"):
			// The edge requires a verified token here; a request that
			// arrives without its subject means the edge let it through.
			if r.Header.Get("X-Edge-Auth-Sub") == "" {
				http.Error(w, "edge forwarded a private request with no verified subject", http.StatusInternalServerError)
				return
			}
			reply(w, r, time.Now(), lognormal(10*time.Millisecond, 60*time.Millisecond), 200, 1<<10, jsonType)
		default:
			http.NotFound(w, r)
		}
	},
	// content: pages and static files.
	"content": func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		switch {
		case strings.HasPrefix(r.URL.Path, "/pages/"):
			reply(w, r, start, lognormal(10*time.Millisecond, 50*time.Millisecond), 200, 30<<10, htmlType)
		case strings.HasPrefix(r.URL.Path, "/static/"):
			n := 100 << 10
			if rand.IntN(10) == 0 { //nolint:gosec // one file in ten is 1 MiB
				n = len(filler)
			}
			reply(w, r, start, time.Millisecond, 200, n, "application/octet-stream")
		default:
			http.NotFound(w, r)
		}
	},
}

func service(args []string) error {
	if len(args) != 1 || services[args[0]] == nil {
		return fmt.Errorf("usage: tools service catalog|orders|account|content")
	}
	srv := &http.Server{Addr: ":8080", Handler: services[args[0]], ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}
