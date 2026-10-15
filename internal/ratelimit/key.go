package ratelimit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// PartKind is one key characteristic.
type PartKind uint8

// Key characteristics, one per snapshot.KeyKinds entry.
const (
	PartIP PartKind = iota
	PartHeader
	PartCookie
	PartQuery
	PartClaim
	PartHost
	PartMethod
	PartCountry
	PartASNum
	PartLocale
	PartConstant
)

// partKinds maps a validated key kind. A kind missing here would key on the
// client IP, so a test checks it matches snapshot.KeyKinds.
var partKinds = map[string]PartKind{
	"ip": PartIP, "header": PartHeader, "cookie": PartCookie, "query": PartQuery,
	"jwt_claim": PartClaim, "host": PartHost, "method": PartMethod, "country": PartCountry,
	"asnum": PartASNum, "locale": PartLocale, "constant": PartConstant,
}

// OnMissing is what a rule does when a key characteristic is absent.
type OnMissing uint8

// OnMissing values for on_missing_key fallback_ip, skip and reject.
const (
	MissingFallbackIP OnMissing = iota
	MissingSkip
	MissingReject
)

// FailMode is what a rule does when Valkey can't answer.
type FailMode uint8

// FailMode values for fail_mode local, open and closed.
const (
	FailLocal FailMode = iota
	FailOpen
	FailClosed
)

// onMissingOf, shadowOf and failModeOf map validated names. A name missing
// here would run as the zero value, so a test checks each matches its
// snapshot list.
var (
	onMissingOf = map[string]OnMissing{"fallback_ip": MissingFallbackIP, "skip": MissingSkip, "reject": MissingReject}
	shadowOf    = map[string]bool{"block": false, "log": true}
	failModeOf  = map[string]FailMode{"local": FailLocal, "open": FailOpen, "closed": FailClosed}
)

// Part is a parsed characteristic. Name is set for header, cookie, query and
// jwt_claim; header names are canonical, so a lookup is a map read.
type Part struct {
	Kind PartKind
	Name string
}

// Rule is a rate-limit rule prepared once per snapshot.
type Rule struct {
	ID           string
	Params       Params
	Parts        []Part
	OnMissingKey OnMissing
	Shadow       bool // action: log
	FailMode     FailMode
	prefix       string
}

// Compile prepares the rules of one validated config.
func Compile(rs []snapshot.RateLimitRule) []Rule {
	out := make([]Rule, len(rs))
	for i, r := range rs {
		shadow := shadowOf[r.Action]
		p := paramsOf(r, shadow)
		rule := Rule{
			ID: r.ID, Params: p, OnMissingKey: onMissingOf[r.OnMissingKey], Shadow: shadow, FailMode: failModeOf[r.FailMode],
			// The hash tag spreads subjects of one rule across cluster slots.
			prefix: "rl:" + r.Algorithm + ":" + strconv.FormatInt(p.Period, 10) + ":" + r.ID + ":{",
		}
		for _, k := range r.Key {
			kind, name, _ := strings.Cut(k, ":")
			if kind == "header" {
				name = textproto.CanonicalMIMEHeaderKey(name)
			}
			rule.Parts = append(rule.Parts, Part{Kind: partKinds[kind], Name: name})
		}
		out[i] = rule
	}
	return out
}

// Subject starts a subject for the rule's characteristics, written next
// with AppendValue, AppendIP and AppendInt. The first byte separates it from
// FallbackSubject, so client-chosen values can never land in the bucket of
// another client's IP.
func Subject(b []byte) []byte { return append(b[:0], 1) }

// FallbackSubject is the client IP alone, for on_missing_key: fallback_ip.
func FallbackSubject(b []byte, ip netip.Addr) []byte { return AppendIP(append(b[:0], 2), ip) }

// Key is the Valkey key for one subject. Only a hash of the subject is
// stored, which bounds key size and keeps raw values out of Valkey.
func (r *Rule) Key(subject []byte) string {
	sum := sha256.Sum256(subject)
	var b [128]byte
	k := append(b[:0], r.prefix...)
	k = base64.RawURLEncoding.AppendEncode(k, sum[:16])
	return string(append(k, '}'))
}

// AppendValue appends one length-prefixed value, so ("ab","c") and
// ("a","bc") hash differently.
func AppendValue(subject []byte, v string) []byte {
	subject = binary.AppendUvarint(subject, uint64(len(v)))
	return append(subject, v...)
}

// AppendInt appends a number, such as an AS number, as 8 bytes.
func AppendInt(subject []byte, v int64) []byte {
	return binary.BigEndian.AppendUint64(append(subject, 8), uint64(v)) //nolint:gosec // bit pattern only; any int64 maps to a distinct value
}

// AppendIP appends a client address. IPv6 is cut to /64, so one subscriber
// can't rotate through its prefix for fresh buckets.
func AppendIP(subject []byte, ip netip.Addr) []byte {
	if ip.Is4() {
		a := ip.As4()
		return append(append(subject, 4), a[:]...)
	}
	a := ip.As16()
	return append(append(subject, 8), a[:8]...)
}
