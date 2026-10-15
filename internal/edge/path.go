package edge

import (
	"errors"
	"net/http"
	"path"
	"strings"
	"unicode/utf8"
)

var (
	errAmbiguousPath = errors.New("path has an encoded slash, a backslash, NUL, a \"..\" segment or a parameter on a dot-segment")
	errBadPath       = errors.New("request target is not an absolute path")
	errMethodCase    = errors.New("method is not uppercase")
)

// matchPath returns the path rules match on: percent-decoded once (Go's
// url.URL.Path), path parameters (";x") dropped, "//" collapsed and "."
// removed. The forwarded path is never changed. Encodings upstreams
// disagree on, and ".." segments, are rejected rather than guessed.
func matchPath(r *http.Request) (string, error) {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/") {
		// OPTIONS *, CONNECT and empty targets: nothing to proxy.
		return "", errBadPath
	}
	// Path is decoded, so a raw or encoded backslash or NUL shows up there.
	// An encoded slash shows up only in the raw target: URL.EscapedPath
	// re-encodes the decoded path when the raw one has a character such as
	// "{" or "|", which would hide it. Invalid UTF-8 (overlong "/" as
	// %c0%af) is read as "/" by some servers.
	raw, _, _ := strings.Cut(r.RequestURI, "?")
	if strings.ContainsAny(p, "\\\x00") || strings.Contains(raw, "%2F") || strings.Contains(raw, "%2f") || !utf8.ValidString(p) {
		return "", errAmbiguousPath
	}
	p, ok := dropParams(p)
	// An upstream that doesn't resolve ".." routes /admin/../public under
	// /admin while a resolved path would match /public. Dropping "." or
	// "//" only moves a path into a prefix it was already under.
	if !ok || strings.Contains(p+"/", "/../") {
		return "", errAmbiguousPath
	}
	c := path.Clean(p)
	// Clean drops a trailing slash, but /admin/ and /admin are different routes.
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c, nil
}

// dropParams removes ";..." from each segment. Tomcat and Spring route
// /admin;jsessionid=1 to /admin, so a rule on /admin must match it too.
// It fails when that turns a segment into "." or "..": other servers read
// "..;x" as a name, so the edge and the upstream would resolve different paths.
func dropParams(p string) (string, bool) {
	if !strings.Contains(p, ";") {
		return p, true
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		name, _, found := strings.Cut(s, ";")
		if found && (name == "." || name == "..") {
			return "", false
		}
		segs[i] = name
	}
	return strings.Join(segs, "/"), true
}

// checkMethod rejects non-uppercase methods. Go's server accepts any token,
// so "post" would slip past a rule on "POST" at an upstream that folds case.
func checkMethod(m string) error {
	if strings.ToUpper(m) != m {
		return errMethodCase
	}
	return nil
}
