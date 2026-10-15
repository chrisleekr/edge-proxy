package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

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
