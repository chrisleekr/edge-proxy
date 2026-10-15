package edge

import (
	"hash/maphash"
	"net/http"
	"sync"

	"golang.org/x/text/language"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// maxAcceptLanguage is the longest Accept-Language header that is parsed;
// longer ones get the default.
const maxAcceptLanguage = 256

// maxLocaleCache bounds each snapshot's locale cache.
const maxLocaleCache = 10_000

// localeResolver picks a supported locale from Accept-Language with the
// snapshot's matcher, caching by the raw header.
type localeResolver struct {
	m         language.Matcher
	supported []string
	def       string
	header    string // output header
	cache     [16]localeShard
}

type localeShard struct {
	mu sync.RWMutex
	m  map[string]string
}

var localeSeed = maphash.MakeSeed()

// newLocaleResolver returns nil when no locales are supported.
func newLocaleResolver(c *snapshot.Compiled) *localeResolver {
	l := c.Config.Global.Locale
	if c.Locale == nil {
		return nil
	}
	// Canonical once here, so Header.Set doesn't allocate to canonicalize it per request.
	r := &localeResolver{m: c.Locale, supported: l.Supported, def: l.Default, header: http.CanonicalHeaderKey(l.OutputHeader)}
	if r.header == "" {
		r.header = "X-Edge-Locale"
	}
	for i := range r.cache {
		r.cache[i].m = map[string]string{}
	}
	return r
}

func (l *localeResolver) resolve(al string) string {
	if al == "" || len(al) > maxAcceptLanguage {
		return l.def
	}
	s := &l.cache[maphash.String(localeSeed, al)%uint64(len(l.cache))]
	s.mu.RLock()
	v, ok := s.m[al]
	s.mu.RUnlock()
	if ok {
		return v
	}
	v = l.match(al)
	s.mu.Lock()
	// When full, new strings are matched but not stored.
	if len(s.m) < maxLocaleCache/len(l.cache) {
		s.m[al] = v
	}
	s.mu.Unlock()
	return v
}

func (l *localeResolver) match(al string) string {
	tags, _, err := language.ParseAcceptLanguage(al)
	if err != nil || len(tags) == 0 {
		return l.def
	}
	_, i, conf := l.m.Match(tags...)
	if conf == language.No {
		return l.def
	}
	return l.supported[i]
}
