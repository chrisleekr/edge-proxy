// Package envparse reads deployment config from environment variables. It
// collects every problem instead of stopping at the first, so a broken
// deployment fails at startup with a complete list. The edge and admin
// share it, so both report the same problem the same way.
package envparse

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Parser reads variables through Get and records problems.
type Parser struct {
	Get  func(string) string
	errs []error
}

// Fail records a problem with one variable.
func (p *Parser) Fail(name, msg string) { p.errs = append(p.errs, fmt.Errorf("%s: %s", name, msg)) }

// Err joins every recorded problem; nil when there were none.
func (p *Parser) Err() error { return errors.Join(p.errs...) }

// Str returns the variable, or def when it is unset or empty.
func (p *Parser) Str(name, def string) string {
	if v := p.Get(name); v != "" {
		return v
	}
	return def
}

// List splits a comma-separated value, trimming spaces and dropping empties.
func (p *Parser) List(name string) []string {
	var out []string
	for s := range strings.SplitSeq(p.Get(name), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Prefixes reads a list of CIDRs or single IPs.
func (p *Parser) Prefixes(name string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range p.List(name) {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				p.Fail(name, fmt.Sprintf("%q is not an IP or CIDR", s))
				continue
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, pfx.Masked())
	}
	return out
}

// Duration reads a positive Go duration, or returns def when unset.
func (p *Parser) Duration(name string, def time.Duration) time.Duration {
	v := p.Get(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		p.Fail(name, fmt.Sprintf("%q must be a positive Go duration such as 30s or 168h", v))
		return def
	}
	return d
}

// Integer reads a positive integer, or returns def when unset.
func (p *Parser) Integer(name string, def int) int {
	v := p.Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		p.Fail(name, fmt.Sprintf("%q must be a positive integer", v))
		return def
	}
	return n
}

// Fraction reads a number from 0 to 1, or returns def when unset.
func (p *Parser) Fraction(name string, def float64) float64 {
	v := p.Get(name)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 || f > 1 {
		p.Fail(name, fmt.Sprintf("%q must be a number from 0 to 1", v))
		return def
	}
	return f
}

// Bool reads "true" or "false"; unset is false.
func (p *Parser) Bool(name string) bool {
	switch v := p.Get(name); v {
	case "", "false":
		return false
	case "true":
		return true
	default:
		p.Fail(name, fmt.Sprintf("%q must be true or false", v))
		return false
	}
}
