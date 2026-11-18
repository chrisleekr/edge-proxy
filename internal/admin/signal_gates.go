package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// maxGateVersions bounds the gate cache; versions never change, so a clear
// only costs a reload.
const maxGateVersions = 256

// gateCache holds each version's signal gates.
type gateCache struct {
	mu sync.Mutex
	m  map[int64][]string
}

// signalGates is, per expr.Signals index, what lets the signal fire under c:
// "" when it cannot, else a value that differs when the set of requests that
// carry it differs. A signal's stored count is only comparable between
// minutes with the same gate: 0 under a closed gate is not normal traffic.
// It reads what Compile produced, since only Compile knows the deployment's
// default for trusted CDN headers.
func signalGates(c *snapshot.Compiled) []string {
	trusted := map[string]bool{"cf-bot-score": c.CDN.BotScore, "cf-verified-bot": c.CDN.VerifiedBot, "cloudfront-viewer-tls": c.CDN.TLS, "cf-ipcountry": c.CDN.Country}
	out := make([]string, len(expr.Signals))
	for i, d := range expr.Signals {
		out[i] = "on"
		if d.NeedsFloor {
			out[i] = ""
			if c.ChromiumFloor > 0 || c.FirefoxFloor > 0 {
				out[i] = fmt.Sprintf("chromium=%d firefox=%d", c.ChromiumFloor, c.FirefoxFloor)
			}
		}
		for _, h := range d.NeedsHeaders {
			if !trusted[h] {
				out[i] = ""
			}
		}
	}
	return out
}

// versionGates is signalGates of each version. A version that is gone or no
// longer compiles maps to nil, which matches no gate.
func (s *Server) versionGates(ctx context.Context, q querier, versions []int64) (map[int64][]string, error) {
	out := make(map[int64][]string, len(versions))
	for _, v := range versions {
		s.gates.mu.Lock()
		g, ok := s.gates.m[v]
		s.gates.mu.Unlock()
		if !ok {
			vr, err := s.loadVersion(ctx, q, v)
			var p *problem
			switch {
			case errors.As(err, &p) && p.Status == http.StatusNotFound:
			case err != nil:
				return nil, err
			default:
				if c, _, errs := snapshot.Compile(&vr.Config, s.cfg.Deployment); errs == nil {
					g = signalGates(c)
				}
			}
			s.gates.mu.Lock()
			if len(s.gates.m) >= maxGateVersions {
				s.gates.m = nil
			}
			if s.gates.m == nil {
				s.gates.m = map[int64][]string{}
			}
			s.gates.m[v] = g
			s.gates.mu.Unlock()
		}
		out[v] = g
	}
	return out, nil
}

// sameGates reports whether a and b are both open and equal for every signal
// in groups.
func sameGates(a, b []string, groups [][]int) bool {
	if a == nil || b == nil {
		return false
	}
	for _, g := range groups {
		for _, i := range g {
			if a[i] == "" || a[i] != b[i] {
				return false
			}
		}
	}
	return true
}

// activeGates is the active version's gates, nil with no active version.
func (s *Server) activeGates(ctx context.Context, q querier) ([]string, error) {
	av, err := activeVersion(ctx, q)
	if err != nil || av == nil {
		return nil, err
	}
	g, err := s.versionGates(ctx, q, []int64{*av})
	return g[*av], err
}
