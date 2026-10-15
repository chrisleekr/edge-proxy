package edge

import (
	"net/http"
	"net/textproto"
	"strings"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

type forwardMode uint8

const (
	forwardAll forwardMode = iota
	forwardAllowlist
	forwardDenylist
)

type opKind uint8

const (
	opSet opKind = iota
	opAppend
	opRemove
	opCopy
	opRename
	opForward
)

// forwardModes and opKinds map validated names. A name missing here would
// run as the zero value, so a test checks each matches its snapshot list.
var (
	forwardModes = map[string]forwardMode{"all": forwardAll, "allowlist": forwardAllowlist, "denylist": forwardDenylist}
	opKinds      = map[string]opKind{"set": opSet, "append": opAppend, "remove": opRemove, "copy": opCopy, "rename": opRename, "forward": opForward}
)

// forwardFilter is a compiled forward setting.
type forwardFilter struct {
	mode  forwardMode
	names map[string]bool
}

func compileForward(f snapshot.Forward) *forwardFilter {
	ff := &forwardFilter{mode: forwardModes[f.Mode], names: map[string]bool{}}
	for _, n := range f.Names {
		ff.names[textproto.CanonicalMIMEHeaderKey(n)] = true
	}
	return ff
}

// apply keeps or drops headers. Headers validation reserves (Connection,
// Upgrade and Te, which ReverseProxy sets before Rewrite) are always kept.
func (f *forwardFilter) apply(h http.Header) {
	switch f.mode {
	case forwardAllowlist:
		for k := range h {
			if !f.names[k] && !snapshot.Reserved(k) {
				delete(h, k)
			}
		}
	case forwardDenylist:
		for k := range f.names {
			delete(h, k)
		}
	}
}

// headerOp is one compiled operation of a header rule.
type headerOp struct {
	op       opKind
	name, to string // canonical; name is also "from" for copy and rename
	value    snapshot.Template
	forward  *forwardFilter
}

type headerPlan struct {
	forward *forwardFilter // global
	ops     [][]headerOp   // by rule
}

func compileHeaders(c *snapshot.Compiled) headerPlan {
	p := headerPlan{forward: compileForward(c.Config.Global.RequestHeaders.Forward), ops: make([][]headerOp, len(c.Config.RequestHeaderRules))}
	for i, r := range c.Config.RequestHeaderRules {
		for k, op := range r.Ops {
			ho := headerOp{op: opKinds[op.Op], name: textproto.CanonicalMIMEHeaderKey(op.Name), value: c.HeaderValues[i][k]}
			switch ho.op {
			case opCopy, opRename:
				ho.name, ho.to = textproto.CanonicalMIMEHeaderKey(op.From), textproto.CanonicalMIMEHeaderKey(op.To)
			case opForward:
				ho.forward = compileForward(snapshot.Forward{Mode: op.Mode, Names: op.Names})
			}
			p.ops[i] = append(p.ops[i], ho)
		}
	}
	return p
}

// upstreamHeaders is step 9 on h: drop client copies of edge-managed
// headers, run the header rules, then set the locale header, which no rule
// can override. Simulate runs it too, so config tests see what
// the upstream gets.
func upstreamHeaders(c *snapshot.Compiled, plan *headerPlan, st *reqState, h http.Header, strip []string) {
	for _, name := range strip {
		delete(h, name)
	}
	for k := range h {
		if strings.HasPrefix(k, "X-Edge-") {
			delete(h, k)
		}
	}
	headerPhase(c, plan, &st.fields, h, st.placeholder)
	if l := st.fields.loc; l != nil {
		h.Set(l.header, st.fields.localeValue())
	}
}

// headerPhase is step 9 on out, the upstream request's headers: the forward
// filter (the last matching rule's forward op wins), then every matching
// rule's other operations in order. Edge-managed headers are set after it,
// so no rule can override them.
func headerPhase(c *snapshot.Compiled, plan *headerPlan, req expr.Request, out http.Header, value func(snapshot.Placeholder) string) {
	var buf [16]int
	matched := buf[:0]
	fw := plan.forward
	for i, m := range c.HeaderRules {
		if !m(req) {
			continue
		}
		matched = append(matched, i)
		for k := range plan.ops[i] {
			if op := &plan.ops[i][k]; op.forward != nil {
				fw = op.forward
			}
		}
	}
	fw.apply(out)
	var vb [256]byte
	for _, i := range matched {
		for k := range plan.ops[i] {
			op := &plan.ops[i][k]
			switch op.op {
			case opSet:
				out.Set(op.name, string(op.value.Render(vb[:0], value)))
			case opAppend:
				out.Add(op.name, string(op.value.Render(vb[:0], value)))
			case opRemove:
				out.Del(op.name)
			case opCopy, opRename:
				// The target always ends up as the source: a client can't
				// supply its own value by omitting the source header.
				if vs := out[op.name]; vs != nil {
					out[op.to] = append([]string(nil), vs...)
				} else {
					out.Del(op.to)
				}
				if op.op == opRename {
					out.Del(op.name)
				}
			}
		}
	}
}

// headerSafe drops control characters from a value taken from the request
// or a token: CR or LF would split the header, and the transport rejects
// other controls (RFC 9110 §5.5). Bytes 0x80 and up (obs-text) are kept.
func headerSafe(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x20 && c != 0x7f || c == '\t' {
			b = append(b, c)
		}
	}
	return string(b)
}

// placeholder resolves a header-rule placeholder from the request's fields.
// Values a client or a token supplies are made header-safe.
func (st *reqState) placeholder(ph snapshot.Placeholder) string {
	f := &st.fields
	switch ph.Name {
	case "header":
		return headerSafe(f.r.Header.Get(ph.Arg))
	case "client_ip":
		return st.client.ip.String()
	case "jwt_claim":
		v, _ := first(f.claims[ph.Arg])
		return headerSafe(v)
	case "country":
		return st.client.country
	case "locale":
		return f.localeValue()
	default: // request_id
		return st.requestID
	}
}
