package edge

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"
)

var (
	errAmbiguousPath = errors.New("path has a backslash, NUL, invalid UTF-8, a \"..\" segment or a parameter on a dot-segment")
	errBadPath       = errors.New("request target is not an absolute path")
	errMethodCase    = errors.New("method is not uppercase")
)

// matchPath returns the path rules match on: percent-decoded once (Go's
// url.URL.Path) except %2F, path parameters (";x") dropped, "//" collapsed
// and "." removed. The forwarded path keeps every escape. %2F stays inside
// its segment, as the gateway behind the edge routes it when it leaves
// escaped slashes unchanged (Envoy KEEP_UNCHANGED, its default). Encodings
// upstreams disagree on, and ".." segments, are rejected rather than guessed.
// A gateway that decodes twice is not modeled: %252e%252e matches as "%2e%2e".
func matchPath(r *http.Request) (string, error) {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/") {
		// OPTIONS *, CONNECT and empty targets: nothing to proxy.
		return "", errBadPath
	}
	// Path is decoded, so a raw or encoded backslash or NUL shows up there.
	// Invalid UTF-8 (overlong "/" as %c0%af) is read as "/" by some servers.
	if strings.ContainsAny(p, "\\\x00") || !utf8.ValidString(p) {
		return "", errAmbiguousPath
	}
	// An encoded slash shows up only in RawPath, the path as sent: Go keeps
	// it whenever it differs from the default encoding, which never has %2F.
	// URL.EscapedPath would re-encode the decoded path when the raw one has
	// a character such as "{" or "|", hiding it.
	if strings.Contains(r.URL.RawPath, "%2F") || strings.Contains(r.URL.RawPath, "%2f") {
		var ok bool
		if p, ok = keepEncodedSlash(r.URL.RawPath); !ok {
			return "", errAmbiguousPath
		}
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

// keepEncodedSlash decodes each segment of an escaped path but writes a
// decoded "/" back as %2F, so "group%2Fproject" stays one segment. It fails
// when %2F hides a "." or ".." part: a gateway that decodes %2F (nginx
// location matching) resolves /public/..%2Fadmin to /admin, while rules
// would see a path under /public.
func keepEncodedSlash(escaped string) (string, bool) {
	segs := strings.Split(escaped, "/")
	for i, s := range segs {
		d, _ := url.PathUnescape(s) // the server already parsed the whole path
		if strings.Contains(d, "/") {
			for part := range strings.SplitSeq(d, "/") {
				// A gateway that strips ";x", as dropParams does, sees "..;x" as "..".
				if name, _, _ := strings.Cut(part, ";"); name == "." || name == ".." {
					return "", false
				}
			}
		}
		segs[i] = strings.ReplaceAll(d, "/", "%2F")
	}
	return strings.Join(segs, "/"), true
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
