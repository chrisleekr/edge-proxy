package edge

import (
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

const (
	htmlType = "text/html; charset=utf-8"
	textType = "text/plain; charset=utf-8"
	jsonType = "application/problem+json"
)

// bodiesConfig gives every kind a problem+json default plus HTML and text
// variants, and refuses /blocked with a 403.
func bodiesConfig(version int64) *snapshot.Config {
	c := testConfig(version)
	for k, r := range c.Global.Responses {
		r.ContentType = jsonType
		r.Variants = []snapshot.Variant{
			{ContentType: htmlType, Body: "<h1>" + k + " {{status}}</h1>"},
			{ContentType: textType, Body: k + " {{status}}"},
		}
		c.Global.Responses[k] = r
	}
	c.ConfigRules = append(c.ConfigRules, snapshot.ConfigRule{ID: "blocked", Expression: mustParse(`http.request.uri.path eq "/blocked"`), Settings: snapshot.Settings{Block: new("block")}})
	return c
}

// The edge sends the body the request's Accept prefers and never a 406.
func TestEdgeAnswerFollowsAccept(t *testing.T) {
	h := newHarness(t, nil)
	h.load(envelope(bodiesConfig(1)))
	const chrome = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
	cases := []struct {
		name, accept, contentType, bodyStart string
	}{
		{"a browser opening a page gets HTML", chrome, htmlType, "<h1>forbidden 403"},
		{"no Accept gets the default", "", jsonType, `{"error":"forbidden"`},
		{"Accept */* gets the default", "*/*", jsonType, `{"error":"forbidden"`},
		{"application/json does not match a problem+json default", "application/json", jsonType, `{"error":"forbidden"`},
		{"text/html refused with q=0 falls back to the default", "text/html;q=0, */*", jsonType, `{"error":"forbidden"`},
		{"the higher q wins over the order", "text/plain;q=0.5, text/html;q=0.4", textType, "forbidden 403"},
		{"media types are case-insensitive", "TEXT/HTML", htmlType, "<h1>forbidden 403"},
		{"a malformed q drops that range", "text/html;q=abc, */*", jsonType, `{"error":"forbidden"`},
		{"nothing acceptable gets the default, not 406", "image/png", jsonType, `{"error":"forbidden"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hs []string
			if tc.accept != "" {
				hs = []string{"Accept", tc.accept}
			}
			resp := h.do("GET", "/blocked", nil, hs...)
			if resp.StatusCode != 403 || resp.Header.Get("Content-Type") != tc.contentType {
				t.Errorf("status %d, Content-Type %q; want 403, %q", resp.StatusCode, resp.Header.Get("Content-Type"), tc.contentType)
			}
			if got := resp.Header.Values("Vary"); !slices.Equal(got, []string{"Accept"}) {
				t.Errorf("Vary = %v, want [Accept]", got)
			}
			if resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
			}
			body := readBody(t, resp)
			if !strings.HasPrefix(body, tc.bodyStart) {
				t.Errorf("body %q, want prefix %q", body, tc.bodyStart)
			}
			if resp.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Errorf("Content-Length %q, body is %d bytes", resp.Header.Get("Content-Length"), len(body))
			}
		})
	}
}

// A template with one body sends the same headers as before variants: no Vary.
func TestSingleBodyTemplateSendsNoVary(t *testing.T) {
	h := newHarness(t, nil)
	c := bodiesConfig(1)
	r := c.Global.Responses["forbidden"]
	r.Variants = nil
	c.Global.Responses["forbidden"] = r
	h.load(envelope(c))
	resp := h.do("GET", "/blocked", nil, "Accept", "text/html")
	if resp.Header.Get("Content-Type") != jsonType || resp.Header.Values("Vary") != nil {
		t.Errorf("Content-Type %q, Vary %v", resp.Header.Get("Content-Type"), resp.Header.Values("Vary"))
	}
	if body := readBody(t, resp); !strings.HasPrefix(body, `{"error":"forbidden"`) {
		t.Errorf("body %q", body)
	}
}

// The overload shed runs at step 1, before rules, and still picks by Accept.
func TestOverloadShedFollowsAccept(t *testing.T) {
	h := newHarness(t, map[string]string{"MAX_INFLIGHT": "1"})
	h.load(envelope(bodiesConfig(1)))
	entered, release := make(chan struct{}, 1), make(chan struct{})
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	}
	done := make(chan struct{})
	go func() { h.do("GET", "/slow", nil).Body.Close(); close(done) }()
	<-entered
	resp := h.do("GET", "/", nil, "Accept", "text/html,*/*;q=0.8")
	close(release)
	<-done
	if resp.StatusCode != 503 || resp.Header.Get("Content-Type") != htmlType || !slices.Equal(resp.Header.Values("Vary"), []string{"Accept"}) {
		t.Errorf("status %d, Content-Type %q, Vary %v", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Values("Vary"))
	}
	if body := readBody(t, resp); body != "<h1>overloaded 503</h1>" {
		t.Errorf("body %q", body)
	}
}

// A CORS route whose allowed origin varies already sends Vary: Origin, and
// the Accept-dependent body adds Accept to it.
func TestVaryAcceptKeepsCORSVaryOrigin(t *testing.T) {
	h := newHarness(t, nil)
	c := corsConfig()
	for k, r := range c.Global.Responses {
		r.ContentType = jsonType
		r.Variants = []snapshot.Variant{{ContentType: htmlType, Body: "<h1>" + k + "</h1>"}}
		c.Global.Responses[k] = r
	}
	r := rlRule("cors-closed", `starts_with(http.request.uri.path, "/app/")`, "sliding_window", 1, "ip")
	r.FailMode = "closed"
	c.RateLimitRules = []snapshot.RateLimitRule{r}
	h.load(envelope(c))
	resp := h.do("GET", "/app/x", nil, "Origin", "https://b.example", "Accept", "text/html")
	if resp.StatusCode != 503 || resp.Header.Get("Content-Type") != htmlType {
		t.Errorf("status %d, Content-Type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if got := resp.Header.Values("Vary"); !slices.Equal(got, []string{"Origin", "Accept"}) {
		t.Errorf("Vary = %v, want [Origin Accept]", got)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://b.example" {
		t.Errorf("CORS headers lost: %v", resp.Header)
	}
	resp.Body.Close()
}

func bodyOf(mt string) snapshot.Body { return snapshot.Body{ContentType: mt, MediaType: mt} }

func TestPickBodyCases(t *testing.T) {
	bodies := []snapshot.Body{bodyOf("application/problem+json"), bodyOf("text/html"), bodyOf("text/plain")}
	cases := []struct {
		name, accept string
		want         int
	}{
		{"empty Accept", "", 0},
		{"exact type", "text/plain", 2},
		{"type wildcard prefers the earlier body on a tie", "text/*", 1},
		{"exact beats the wildcard that also matches", "text/*;q=0.1, text/plain;q=0.9", 2},
		{"most specific range sets q, not the first", "text/plain;q=0, text/*", 1},
		{"empty q drops the range", "text/html;q=, text/plain", 2},
		{"q above 1 drops the range", "text/html;q=1.5, text/plain;q=0.1", 2},
		{"more than three decimals drops the range", "text/html;q=0.1234, text/plain;q=0.1", 2},
		{"letters in q drop the range", "text/html;q=abc, text/plain;q=0.1", 2},
		{"a letter after the decimal point drops the range", "text/html;q=0.5x, text/plain;q=0.1", 2},
		{"q of 1 with decimals is allowed", "text/plain;q=1.000", 2},
		{"q of 1.001 is refused", "text/html;q=1.001, text/plain;q=0.1", 2},
		{"upper case Q is read", "text/html;Q=0.1, text/plain;Q=0.5", 2},
		{"an empty parameter before q is skipped", "text/plain;;q=1, text/html;q=0.5", 2},
		{"a parameter that is not q is skipped", "text/html;level=1;q=0.2, text/plain;q=0.3", 2},
		{"a wildcard subtype with a concrete type does not match another type", "*/html", 0},
		{"a range with no slash is ignored", "text, text/plain;q=0.1", 2},
		{"a missing q on a lone */* keeps the default", "*/*", 0},
		{"everything refused keeps the default", "text/html;q=0, text/plain;q=0", 0},
		{"an Accept over the cap is not parsed and gets the default", strings.Repeat("a/a,", 64) + "text/plain", 0},
		{"a long Accept that refuses HTML after the cap still gets the default", strings.Repeat("a/a,", 60) + "ab/abc,text/html;q=0", 0},
		{"a range inside the cap counts", strings.Repeat("a/a,", 60) + "text/plain", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickBody(tc.accept, bodies); got != tc.want {
				t.Errorf("pickBody(%q) = %d, want %d", tc.accept, got, tc.want)
			}
		})
	}
}

func TestMaxBodiesHoldsEveryContentType(t *testing.T) {
	if maxBodies < len(snapshot.ContentTypes) {
		t.Fatalf("maxBodies %d is below the %d content types a template can hold", maxBodies, len(snapshot.ContentTypes))
	}
}

func TestPickBodyAllocatesNothing(t *testing.T) {
	bodies := []snapshot.Body{bodyOf("application/problem+json"), bodyOf("text/html"), bodyOf("text/plain")}
	const chrome = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	if n := testing.AllocsPerRun(100, func() { pickBody(chrome, bodies) }); n != 0 {
		t.Errorf("%v allocations per call, want 0", n)
	}
}

// qRe is the RFC 9110 qvalue grammar.
var qRe = regexp.MustCompile(`^(0(\.[0-9]{0,3})?|1(\.0{0,3})?)$`)

// refPick is pickBody written plainly: split, then a body at a time.
func refPick(accept string, bodies []snapshot.Body) int {
	if len(accept) > maxAccept {
		return 0
	}
	type rng struct {
		typ, sub string
		q        float64
	}
	var ranges []rng
	for part := range strings.SplitSeq(accept, ",") {
		fields := strings.Split(part, ";")
		typ, sub, ok := strings.Cut(strings.TrimSpace(fields[0]), "/")
		if !ok {
			continue
		}
		q, valid := 1.0, true
		for _, p := range fields[1:] {
			p = strings.TrimSpace(p)
			if len(p) < 2 || (p[0] != 'q' && p[0] != 'Q') || p[1] != '=' {
				continue
			}
			if !qRe.MatchString(p[2:]) {
				valid = false
			} else if f, err := strconv.ParseFloat(p[2:], 64); err != nil {
				valid = false
			} else {
				q = f
			}
			break
		}
		if valid {
			ranges = append(ranges, rng{typ, sub, q})
		}
	}
	best, bestQ := 0, -1.0
	for i, b := range bodies {
		typ, sub, _ := strings.Cut(b.MediaType, "/")
		spec, q := 0, 0.0
		for _, r := range ranges {
			s := 0
			switch {
			case r.typ == "*" && r.sub == "*":
				s = 1
			case !strings.EqualFold(r.typ, typ):
			case r.sub == "*":
				s = 2
			case strings.EqualFold(r.sub, sub):
				s = 3
			}
			if s > spec {
				spec, q = s, r.q
			}
		}
		if q > bestQ {
			best, bestQ = i, q
		}
	}
	return best
}

func FuzzPickBody(f *testing.F) {
	bodies := []snapshot.Body{bodyOf("application/problem+json"), bodyOf("text/html"), bodyOf("text/plain"), bodyOf("application/json")}
	for _, s := range []string{
		"", "*/*", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/plain;q=0.5, text/html;q=0.4",
		"TEXT/HTML;Q=0.3", "text/html;q=0, */*", "text/*;q=0.1, text/plain;q=0.9", "text/html;q=1.5", "text/html;q=0.1234",
		"text/html;;q=1", "*/html", "text", "text/html;q=", strings.Repeat("a/a,", 64),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, accept string) {
		for n := 1; n <= len(bodies); n++ {
			got := pickBody(accept, bodies[:n])
			if got < 0 || got >= n {
				t.Fatalf("index %d out of range for %d bodies", got, n)
			}
			if want := refPick(accept, bodies[:n]); got != want {
				t.Fatalf("pickBody(%q, %d bodies) = %d, reference says %d", accept, n, got, want)
			}
		}
	})
}

func BenchmarkPickBody(b *testing.B) {
	bodies := []snapshot.Body{bodyOf("application/problem+json"), bodyOf("text/html"), bodyOf("text/plain")}
	for name, accept := range map[string]string{
		"chrome page": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"worst case":  strings.Repeat("a/a,", maxAccept/4),
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				pickBody(accept, bodies)
			}
		})
	}
}
