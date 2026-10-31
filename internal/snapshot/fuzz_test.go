package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// The edge decodes and compiles whatever the poller downloads. A panic there
// would stop config updates, or crash a cold start, so no input may panic.
// Anything that compiles must also survive the cache file round trip.
func FuzzDecodeAndCompile(f *testing.F) {
	good, err := json.Marshal(validEnvelope())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"exported_at":"2026-01-01T00:00:00Z","active":{"schema":1,"version":1}}`))
	f.Add([]byte(`{"active":{"config_rules":[{"id":"a","expression":{"field":"ssl","operator":"is_true"},"settings":{"locale":true}}]}}`))
	// The bot detection fields: crawler ranges, a count rule, a distinct
	// rule, a block setting and the block kill switch.
	bots := validEnvelope()
	bots.Candidate, bots.CanaryPercent, bots.CanaryExpiresAt = nil, 0, time.Time{}
	bots.VerifiedBots = []BotSet{{Source: "https://bots.example.com/googlebot.json", Prefixes: []string{"66.249.64.0/27", "2001:4860:4801:10::/64"}}}
	bots.Active.RateLimitRules[1].CountStatuses = []string{"4xx"}
	bots.Active.RateLimitRules = append(bots.Active.RateLimitRules, RateLimitRule{ID: "crawl", Expression: mustParse(`starts_with(http.request.uri.path, "/products/")`),
		Algorithm: "distinct", DistinctOf: "query:id", Limit: 100, Period: dur("1m"), Key: []string{"ip"}, OnMissingKey: "skip", Action: "block", FailMode: "open"})
	bots.Active.ConfigRules[0].Settings.Block = new("log")
	bots.Active.KillSwitch.Block = true
	b, err := json.Marshal(bots)
	if err != nil {
		f.Fatal(err)
	}
	if _, errs := CompileEnvelope(bots, testDeployment); errs != nil {
		f.Fatalf("bot seed doesn't compile: %v", expr.Issues(errs))
	}
	f.Add(b)
	// A rule that expires, as autopilot publishes it.
	var m map[string]any
	if err := json.Unmarshal(good, &m); err != nil {
		f.Fatal(err)
	}
	m["active"].(map[string]any)["rate_limit_rules"].([]any)[1].(map[string]any)["expires_at"] = "2026-11-01T00:00:00Z"
	expiring, err := json.Marshal(m)
	if err != nil {
		f.Fatal(err)
	}
	if e, err := Decode(bytes.NewReader(expiring)); err != nil {
		f.Fatalf("expires_at seed doesn't decode: %v", err)
	} else if _, errs := CompileEnvelope(e, testDeployment); errs != nil {
		f.Fatalf("expires_at seed doesn't compile: %v", expr.Issues(errs))
	}
	f.Add(expiring)
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		s, errs := CompileEnvelope(e, testDeployment)
		if (s == nil) == (errs == nil) {
			t.Fatalf("snapshot %v with errors %v", s != nil, errs)
		}
		if s == nil {
			return
		}
		cached, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("compiled snapshot doesn't marshal: %v", err)
		}
		e2, err := Decode(bytes.NewReader(cached))
		if err != nil {
			t.Fatalf("cache file doesn't decode: %v", err)
		}
		if _, errs := CompileEnvelope(e2, testDeployment); errs != nil {
			t.Fatalf("cache file doesn't compile: %v", expr.Issues(errs))
		}
	})
}

// largestConfig is near MaxConfigBytes, with every phase at its rule limit.
func largestConfig() *Config {
	c := validConfig()
	cidrs := make([]string, 250)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	ips := mustParse(`ip.src in {` + strings.Join(cidrs, " ") + `}`)
	c.ConfigRules, c.RateLimitRules, c.RequestHeaderRules = nil, nil, nil
	for i := range MaxRulesPerPhase {
		c.ConfigRules = append(c.ConfigRules, ConfigRule{ID: fmt.Sprintf("c%d", i), Expression: ips, Settings: Settings{BodyLimit: new(int64(1))}})
		c.RateLimitRules = append(c.RateLimitRules, RateLimitRule{ID: fmt.Sprintf("r%d", i), Expression: ips, Algorithm: "fixed_window", Limit: 1, Period: dur("1s"), Key: []string{"ip"}, OnMissingKey: "skip", Action: "log", FailMode: "open"})
		r := HeaderRule{ID: fmt.Sprintf("h%d", i), Expression: ips}
		for range 20 {
			r.Ops = append(r.Ops, HeaderOp{Op: "set", Name: "X-A", Value: strings.Repeat("v", 1000) + "{{client_ip}}"})
		}
		c.RequestHeaderRules = append(c.RequestHeaderRules, r)
	}
	return c
}

// Memory the edge holds for the largest allowed config, decoded and
// compiled. During a canary it holds two, so twice this must
// fit the container's memory budget.
func BenchmarkCompileLargest(b *testing.B) {
	data, err := json.Marshal(&Envelope{ExportedAt: validEnvelope().ExportedAt, Active: largestConfig()})
	if err != nil {
		b.Fatal(err)
	}
	var keep *Snapshot
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for b.Loop() {
		e, err := Decode(bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}
		s, errs := CompileEnvelope(e, testDeployment)
		if errs != nil {
			b.Fatal(expr.Issues(errs))
		}
		keep = s
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	b.ReportMetric(float64(len(data))/(1<<20), "snapshot-MB")
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), "retained-MB")
	runtime.KeepAlive(keep)
}

// StatusSet.Has, a bit lookup on the request path, agrees with a plain
// range check for any ranges count_statuses can hold and any status code.
func FuzzStatusSetMatchesRanges(f *testing.F) {
	f.Add(uint16(304), uint16(0), uint16(300), uint16(99), 404) // "404" and "4xx"
	f.Add(uint16(0), uint16(399), uint16(63), uint16(0), 163)   // one range across every word
	f.Add(uint16(27), uint16(0), uint16(28), uint16(0), -1)     // two adjacent codes, a negative status
	f.Add(uint16(399), uint16(0), uint16(399), uint16(0), 500)  // 499 only, the first 5xx
	f.Fuzz(func(t *testing.T, a, aLen, b, bLen uint16, code int) {
		// Ranges within 100 to 499, as statusRange returns them.
		rng := func(off, n uint16) [2]int {
			lo := 100 + int(off)%400
			return [2]int{lo, lo + int(n)%(500-lo)}
		}
		ranges := [][2]int{rng(a, aLen), rng(b, bLen)}
		var s StatusSet
		for _, r := range ranges {
			s.add(r[0], r[1])
		}
		in := func(c int) bool {
			for _, r := range ranges {
				if r[0] <= c && c <= r[1] {
					return true
				}
			}
			return false
		}
		for _, c := range []int{code, 99, 100, 163, 164, 499, 500, 600} {
			if s.Has(c) != in(c) {
				t.Fatalf("Has(%d) = %v with ranges %v", c, s.Has(c), ranges)
			}
		}
		for c := 100; c < 500; c++ {
			if s.Has(c) != in(c) {
				t.Fatalf("Has(%d) = %v with ranges %v", c, s.Has(c), ranges)
			}
		}
	})
}
