package router

import (
	"net"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

type Router struct {
	exact map[string]*wafcore.Site
	wild  []wildcard
}
type wildcard struct {
	suffix string
	site   *wafcore.Site
}

func New(s *wafcore.Snapshot) *Router {
	r := &Router{exact: map[string]*wafcore.Site{}}
	if s == nil {
		return r
	}
	for i := range s.Sites {
		site := &s.Sites[i]
		for _, d := range site.Domains {
			h := NormalizeHost(d)
			if strings.HasPrefix(h, "*.") {
				r.wild = append(r.wild, wildcard{suffix: h[1:], site: site})
			} else {
				r.exact[h] = site
			}
		}
	}
	sort.Slice(r.wild, func(i, j int) bool { return len(r.wild[i].suffix) > len(r.wild[j].suffix) })
	return r
}
func NormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		if i := strings.Index(host, "]"); i > 0 {
			host = host[1:i]
		}
	} else if strings.Count(host, ":") == 1 {
		if i := strings.LastIndex(host, ":"); i >= 0 {
			if _, err := net.LookupPort("tcp", host[i+1:]); err == nil {
				host = host[:i]
			}
		}
	}
	host = strings.TrimSuffix(host, ".")
	if !utf8.ValidString(host) {
		return ""
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		encoded, err := punycodeLabel(label)
		if err != nil {
			return ""
		}
		labels[i] = encoded
	}
	return strings.Join(labels, ".")
}
func (r *Router) Route(host string) *wafcore.Site {
	h := NormalizeHost(host)
	if s := r.exact[h]; s != nil {
		return s
	}
	for _, w := range r.wild {
		if strings.HasSuffix(h, w.suffix) && h != strings.TrimPrefix(w.suffix, ".") {
			return w.site
		}
	}
	return nil
}
func (r *Router) Resolve(c *reqctx.RequestCtx) (*wafcore.Site, int) {
	site := r.Route(c.Host)
	if site == nil {
		return nil, http.StatusMisdirectedRequest
	}
	if c.SNI != "" && NormalizeHost(c.SNI) != NormalizeHost(c.Host) {
		return nil, http.StatusMisdirectedRequest
	}
	switch site.Status {
	case "active":
		c.Site = site
		c.Entitlements = site.Entitlements
		return site, 0
	case "suspended":
		return site, http.StatusPaymentRequired
	case "pending":
		return site, http.StatusForbidden
	default:
		return site, http.StatusForbidden
	}
}
