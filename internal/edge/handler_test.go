package edge

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// A normal request reaches the upstream with forwarding headers built only
// from trusted values, and nothing the client could forge.
func TestProxiedRequestCarriesTrustedHeadersOnly(t *testing.T) {
	h := newHarness(t, map[string]string{"VIEWER_HEADERS": "ip.src.continent=X-Viewer-Continent"})
	h.load(envelope(testConfig(1)))
	resp := h.do(http.MethodGet, "/v1/items?ok=1&bad=%zz", nil,
		"CloudFront-Viewer-Country", "au", "X-Viewer-Continent", "oc", "CloudFront-Viewer-ASN", "64500", "CloudFront-Forwarded-Proto", "https",
		"X-Edge-Auth-Sub", "admin", "X-Forwarded-For", "6.6.6.6", "Forwarded", "for=6.6.6.6", "X-Request-Id", "upstream-id.1")
	if body := readBody(t, resp); resp.StatusCode != 200 || body != "upstream ok" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	got := h.lastApp
	want := map[string]string{
		"X-Forwarded-For":           "198.51.100.7",
		"X-Forwarded-Proto":         "https",
		"X-Forwarded-Host":          "api.example.com",
		"X-Edge-Client-Ip":          "198.51.100.7",
		"X-Edge-Geo-Country":        "AU",
		"X-Edge-Geo-Continent":      "OC",
		"X-Viewer-Continent":        "",
		"X-Edge-Geo-Asn":            "64500",
		"X-Request-Id":              "upstream-id.1",
		"X-Edge-Auth-Sub":           "",
		"Forwarded":                 "",
		"Cloudfront-Viewer-Address": "",
		"Cloudfront-Viewer-Country": "",
	}
	for k, v := range want {
		if got.Header.Get(k) != v {
			t.Errorf("upstream %s = %q, want %q", k, got.Header.Get(k), v)
		}
	}
	if got.Host != "api.example.com" || got.URL.RawQuery != "ok=1" {
		t.Errorf("upstream host %q query %q", got.Host, got.URL.RawQuery)
	}
}

// Step 2 rejects anything it can't trust, with the bad_request template.
func TestStep2Rejections(t *testing.T) {
	h := newHarness(t, map[string]string{"INGRESS_SECRET_HEADER": "X-Origin-Secret", "INGRESS_SECRET_VALUES": "s3cret"})
	h.load(envelope(testConfig(1)))
	cases := []struct {
		name   string
		method string
		target string
		hdrs   []string
		reason reason
	}{
		{"missing ingress secret", "GET", "/", nil, reasonIngressSecret},
		{"missing client IP header", "GET", "/", []string{"X-Origin-Secret", "s3cret", "CloudFront-Viewer-Address", ""}, reasonClientIP},
		{"encoded backslash", "GET", "/a%5Cb", []string{"X-Origin-Secret", "s3cret"}, reasonPath},
		{"lowercase method", "post", "/", []string{"X-Origin-Secret", "s3cret"}, reasonMethod},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := h.srv.m.rejected[tc.reason].Load()
			edgeError(t, h.do(tc.method, tc.target, nil, tc.hdrs...), 400, "bad_request")
			if h.srv.m.rejected[tc.reason].Load() != before+1 {
				t.Errorf("reason %s not counted", reasonNames[tc.reason])
			}
		})
	}
	if h.lastApp != nil {
		t.Fatal("a rejected request reached the upstream")
	}
}

// GitLab names a project as group%2Fproject: the upstream receives it
// unchanged.
func TestEncodedSlashReachesUpstreamUnchanged(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	resp := h.do("GET", "/api/v4/projects/group%2Fproject?state=opened", nil)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if got := h.lastApp.RequestURI; got != "/api/v4/projects/group%2Fproject?state=opened" {
		t.Fatalf("upstream got %q", got)
	}
}

// A target with %2F next to dot-segments and a byte a path can't carry raw
// reaches the upstream with every escape intact; only "|" is encoded. Go's
// client would otherwise decode %2F and send /admin/../secret%7C. Sent raw:
// Go's client would normalize the target.
func TestEncodedSlashPassesThroughOnTheWire(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	conn, err := net.Dial("tcp", h.front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /admin%2F..%2Fsecret| HTTP/1.1\r\nHost: api.example.com\r\nCloudFront-Viewer-Address: 198.51.100.7:1\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if got := h.lastApp.RequestURI; got != "/admin%2F..%2Fsecret%7C" {
		t.Fatalf("upstream got %q", got)
	}
}

// A peer outside TRUSTED_PROXIES can't choose its client IP.
func TestUntrustedPeerIsRejected(t *testing.T) {
	h := newHarness(t, map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8"})
	h.load(envelope(testConfig(1)))
	resp := h.do("GET", "/", nil, "X-Request-Id", "chosen-by-attacker")
	if resp.Header.Get("X-Request-Id") == "chosen-by-attacker" {
		t.Error("untrusted peer chose the request id")
	}
	edgeError(t, resp, 400, "bad_request")
}

// A request id that could break a JSON or HTML template is replaced.
func TestUnsafeRequestIDIsReplaced(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	for _, id := range []string{`x","admin":true,"y":"`, "<script>", strings.Repeat("a", 129)} {
		resp := h.do("GET", "/a%5Cb", nil, "X-Request-Id", id)
		if resp.Header.Get("X-Request-Id") == id {
			t.Errorf("request id %q accepted", id)
		}
		edgeError(t, resp, 400, "bad_request")
	}
}

// Before any snapshot loads the edge answers 503 in plain text; it has no
// templates yet.
func TestNoSnapshotYet(t *testing.T) {
	h := newHarness(t, nil)
	resp := h.do("GET", "/", nil)
	if resp.StatusCode != 503 || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Retry-After") != "1" || !strings.Contains(readBody(t, resp), "Service Unavailable") {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
}

// Every host goes to the one upstream with its Host unchanged: the load
// balancer behind the edge routes it, so the edge needs no list of hosts.
func TestAnyHostGoesToTheUpstream(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Host+" "+r.URL.Path) }
	for _, host := range []string{"api.example.com", "shop.example.net", "new-app.example.org:8443"} {
		if body := readBody(t, h.do("GET", "/users", nil, "Host", host)); body != host+" /users" {
			t.Errorf("Host %s: upstream got %q", host, body)
		}
	}
}

// Overload is shed with a fast 503 before any work (step 1); streams have
// their own cap and can't starve ordinary requests.
func TestOverloadIsShed(t *testing.T) {
	h := newHarness(t, map[string]string{"MAX_INFLIGHT": "1", "MAX_STREAMS": "1"})
	h.load(envelope(testConfig(1)))
	entered, release := make(chan struct{}, 4), make(chan struct{})
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	}
	done := make(chan struct{}, 2)
	go func() { h.do("GET", "/slow", nil).Body.Close(); done <- struct{}{} }()
	<-entered
	m := edgeError(t, h.do("GET", "/", nil), 503, "overloaded")
	if m["retry_after"] != 1.0 {
		t.Errorf("retry_after = %v", m["retry_after"])
	}
	// The stream cap is separate: one SSE request still gets in.
	go func() { h.do("GET", "/events", nil, "Accept", "text/event-stream").Body.Close(); done <- struct{}{} }()
	<-entered
	edgeError(t, h.do("GET", "/events", nil, "Accept", "text/event-stream"), 503, "overloaded")
	if h.srv.m.rejected[reasonStreamsOverloaded].Load() != 1 || h.srv.m.rejected[reasonOverloaded].Load() != 1 {
		t.Errorf("overload reasons not counted")
	}
	close(release)
	<-done
	<-done
}

// Bodies over the limit are refused: by Content-Length before contacting the
// upstream, or mid-stream when the length isn't declared.
func TestBodyLimit(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			return
		}
		_, _ = io.WriteString(w, "read all")
	}
	edgeError(t, h.do("POST", "/", strings.NewReader(strings.Repeat("x", 1025))), 413, "payload_too_large")
	if h.lastApp != nil {
		t.Fatal("declared oversize body reached the upstream")
	}
	chunked := io.MultiReader(strings.NewReader(strings.Repeat("x", 2048)))
	edgeError(t, h.do("POST", "/", io.NopCloser(chunked)), 413, "payload_too_large")
	// A config rule raises the limit for uploads.
	if body := readBody(t, h.do("POST", "/upload", strings.NewReader(strings.Repeat("x", 4096)))); body != "read all" {
		t.Fatalf("upload: %q", body)
	}
}

// A client that stops sending its body is cut off at the read deadline
// instead of holding a connection forever.
func TestSlowBody(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("partial"))
		time.Sleep(1500 * time.Millisecond)
		pw.Close()
	}()
	resp := h.do("POST", "/", pr)
	resp.Body.Close()
	if resp.StatusCode != 400 || h.srv.m.rejected[reasonBodyTimeout].Load() != 1 {
		t.Fatalf("status %d, body_timeout %d", resp.StatusCode, h.srv.m.rejected[reasonBodyTimeout].Load())
	}
}

// The upstream timeout bounds the wait for response headers only, so a
// stream may run longer than it once headers arrive.
func TestUpstreamTimeout(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	// One handler for both cases: swapping it while the slow call still
	// runs would race.
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/slow" {
			time.Sleep(1500 * time.Millisecond)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		for i := range 3 {
			_, _ = io.WriteString(w, "data: "+string(rune('a'+i))+"\n\n")
			http.NewResponseController(w).Flush()
			time.Sleep(600 * time.Millisecond)
		}
	}
	edgeError(t, h.do("GET", "/admin/slow", nil), 504, "gateway_timeout")
	body := readBody(t, h.do("GET", "/admin/events", nil, "Accept", "text/event-stream"))
	if strings.Count(body, "data:") != 3 {
		t.Fatalf("stream cut short: %q", body)
	}
}

// An unreachable upstream is a 502, a dial timeout a 504; neither is retried.
func TestUpstreamDown(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.app.Close()
	edgeError(t, h.do("GET", "/admin/x", nil), 502, "bad_gateway")

	h.srv.edge.rp.Transport = &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, timeoutErr{}
	}}
	edgeError(t, h.do("GET", "/admin/x", nil), 504, "gateway_timeout")
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "dial timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// A client that leaves is recorded, and the edge doesn't try to answer it.
func TestClientGone(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	entered := make(chan struct{})
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }
	ctx, cancel := context.WithCancel(t.Context())
	req, _ := http.NewRequestWithContext(ctx, "GET", h.front.URL+"/", nil)
	req.Host = "api.example.com"
	req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:1")
	go func() { <-entered; cancel() }()
	if _, err := h.front.Client().Do(req); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.srv.m.rejected[reasonClientGone].Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.srv.m.rejected[reasonClientGone].Load() != 1 {
		t.Fatal("client_gone not recorded")
	}
}

// WebSocket upgrades pass through, both directions.
func TestWebSocketUpgrade(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.appHandler = echoUpgrade
	conn := dialUpgrade(t, h.front.Listener.Addr().String())
	defer conn.Close()
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q %v", buf, err)
	}
}

// A bug that panics while serving one request costs that request a 503, not
// the replica.
func TestPanicIsContained(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	working := h.srv.edge.rp.Transport
	h.srv.edge.rp.Transport = panicTransport{}
	edgeError(t, h.do("GET", "/", nil), 503, "unavailable")
	if h.srv.m.rejected[reasonPanic].Load() != 1 || len(h.logs.lines("request panic recovered")) != 1 {
		t.Fatal("panic not recorded")
	}
	h.srv.edge.rp.Transport = working
	if readBody(t, h.do("GET", "/admin/x", nil)) != "upstream ok" {
		t.Fatal("replica not serving after a panic")
	}
}

// A panic after the response started can't become a 503; it is still
// counted, and the client sees the response cut off.
func TestPanicAfterHeaders(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.srv.edge.rp.Transport = bodyPanicTransport{}
	req, _ := http.NewRequest("GET", h.front.URL+"/", nil)
	req.Host = "api.example.com"
	req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:1")
	if resp, err := h.front.Client().Do(req); err == nil {
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	waitFor(t, func() bool { return h.srv.m.rejected[reasonPanic].Load() == 1 })
}

type bodyPanicTransport struct{}

func (bodyPanicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: panicBody{}, Request: r}, nil
}

type panicBody struct{}

func (panicBody) Read([]byte) (int, error) { panic("body bug") }
func (panicBody) Close() error             { return nil }

type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) { panic("transport bug") }

// An upstream that dies mid-response aborts that response (net/http's
// ErrAbortHandler), and the replica keeps serving.
func TestUpstreamDiesMidResponse(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(testConfig(1)))
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "partial")
		http.NewResponseController(w).Flush()
		conn, _, _ := http.NewResponseController(w).Hijack()
		conn.Close()
	}
	req, _ := http.NewRequest("GET", h.front.URL+"/", nil)
	req.Host = "api.example.com"
	req.Header.Set("CloudFront-Viewer-Address", "198.51.100.7:1")
	// Depending on timing the client sees the abort before or after headers.
	if resp, err := h.front.Client().Do(req); err == nil {
		if _, err := io.ReadAll(resp.Body); err == nil {
			t.Fatal("truncated response looked complete")
		}
		resp.Body.Close()
	}
	h.appHandler = func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }
	if readBody(t, h.do("GET", "/", nil)) != "ok" {
		t.Fatal("replica not serving after an aborted response")
	}
}

// During a canary, a stable slice of clients gets the candidate until it
// expires; everyone else stays on the active version.
func TestCanaryCohort(t *testing.T) {
	h := newHarness(t, nil)
	cand := testConfig(2)
	cand.RequestHeaderRules = append(cand.RequestHeaderRules, snapshot.HeaderRule{ID: "canary-mark", Expression: mustParse(`http.request.uri.path eq "/v1/x"`),
		Ops: []snapshot.HeaderOp{{Op: "set", Name: "X-Version", Value: "candidate"}}})
	e := envelope(testConfig(1))
	e.Candidate, e.CanaryPercent, e.CanaryExpiresAt = cand, 50, time.Now().Add(time.Hour)
	h.load(e)
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, cmp.Or(r.Header.Get("X-Version"), "upstream ok"))
	}

	in, out := ipWithCohort(t, true, 5000), ipWithCohort(t, false, 5000)
	for range 3 {
		if readBody(t, h.do("GET", "/v1/x", nil, "CloudFront-Viewer-Address", in+":1")) != "candidate" {
			t.Fatal("in-cohort client not on the candidate")
		}
		if readBody(t, h.do("GET", "/v1/x", nil, "CloudFront-Viewer-Address", out+":1")) != "upstream ok" {
			t.Fatal("out-of-cohort client on the candidate")
		}
	}
	// Per-version stats feed the guard's comparison.
	ld := h.srv.store.load()
	if ld.active.stats.requests.Load() != 3 || ld.candidate.stats.requests.Load() != 3 {
		t.Fatalf("stats active %d candidate %d", ld.active.stats.requests.Load(), ld.candidate.stats.requests.Load())
	}

	e.CanaryExpiresAt = time.Now().Add(-time.Second)
	h.load(e)
	if readBody(t, h.do("GET", "/v1/x", nil, "CloudFront-Viewer-Address", in+":1")) != "upstream ok" {
		t.Fatal("expired canary still served")
	}
}

// IPv6 clients are bucketed by /64, so one subscriber stays in one cohort.
func TestCohortByIPv6Prefix(t *testing.T) {
	a, b := netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2:ffff::9")
	if cohortOf(a) != cohortOf(b) {
		t.Fatal("same /64 split across cohorts")
	}
}

// A response kind validation accepts but the edge doesn't know would be
// served with the bad_request template.
func TestEdgeKnowsEveryResponseKind(t *testing.T) {
	want := slices.Sorted(maps.Keys(snapshot.ResponseStatuses()))
	if got := slices.Sorted(slices.Values(kindNames[:])); !slices.Equal(got, want) {
		t.Fatalf("edge kinds %v, validation accepts %v", got, want)
	}
}
