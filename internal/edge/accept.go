package edge

import (
	"strings"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// maxAccept bounds the Accept length parsed when picking a template body:
// every edge answer in a flood parses it, and the client picks its length. A
// longer Accept is not parsed, because cutting it could turn a refusal such as
// text/html;q=0 into a preference. Chrome sends about 135 bytes when it opens
// a page.
const maxAccept = 256

// maxBodies is the most bodies a template has, one per content type. A test
// keeps it at least len(snapshot.ContentTypes).
const maxBodies = 4

// pickBody returns the index of the body accept prefers (RFC 9110 §12.5.1):
// each body takes the q-value of its most specific matching range, and the
// highest q above 0 wins. Ties and no match go to the earlier body, so
// bodies[0], the default, is sent rather than a 406, and so is an accept longer
// than maxAccept. One pass over accept serves every body.
func pickBody(accept string, bodies []snapshot.Body) int {
	if len(accept) > maxAccept {
		return 0
	}
	var spec, q [maxBodies]int
	for accept != "" {
		var r string
		r, accept, _ = strings.Cut(accept, ",")
		mt, params, _ := strings.Cut(r, ";")
		rt, rs, ok := strings.Cut(strings.TrimSpace(mt), "/")
		if !ok {
			continue
		}
		w, ok := qvalue(params)
		if !ok {
			continue
		}
		for i, b := range bodies {
			// The most specific range decides; the first one on a tie.
			if s := specificity(rt, rs, b.MediaType); s > spec[i] {
				spec[i], q[i] = s, w
			}
		}
	}
	best := 0
	for i := 1; i < len(bodies); i++ {
		if q[i] > q[best] {
			best = i
		}
	}
	return best
}

// specificity ranks how the range rt/rs matches mediaType: 3 exact, 2 type/*,
// 1 */*, 0 no match. Media types are case-insensitive (RFC 9110 §8.3.1).
func specificity(rt, rs, mediaType string) int {
	typ, sub, _ := strings.Cut(mediaType, "/")
	switch {
	case rt == "*" && rs == "*":
		return 1
	case !strings.EqualFold(rt, typ):
		return 0
	case rs == "*":
		return 2
	case strings.EqualFold(rs, sub):
		return 3
	}
	return 0
}

// qvalue reads the weight from a range's parameters in thousandths: 1000
// when absent, ok false when malformed, which drops the range
// (RFC 9110 §12.4.2: "0" ["." 0*3DIGIT] or "1" ["." 0*3("0")]).
func qvalue(params string) (int, bool) {
	for params != "" {
		var p string
		p, params, _ = strings.Cut(params, ";")
		p = strings.TrimSpace(p)
		if len(p) < 2 || (p[0] != 'q' && p[0] != 'Q') || p[1] != '=' {
			continue
		}
		v := p[2:]
		if v == "" || len(v) > 5 || (v[0] != '0' && v[0] != '1') || (len(v) > 1 && v[1] != '.') {
			return 0, false
		}
		n := int(v[0]-'0') * 1000
		for i, scale := 2, 100; i < len(v); i, scale = i+1, scale/10 {
			if v[i] < '0' || v[i] > '9' {
				return 0, false
			}
			n += int(v[i]-'0') * scale
		}
		if n > 1000 {
			return 0, false
		}
		return n, true
	}
	return 1000, true
}
