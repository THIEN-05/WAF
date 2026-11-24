package router

import (
	"net"
	"net/http"
	"sort"
	"strconv"
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
	switch {
	case strings.HasPrefix(host, "["):
		if h, port, err := net.SplitHostPort(host); err == nil {
			if !validHostPort(port) || net.ParseIP(h) == nil {
				return ""
			}
			host = h
		} else if strings.HasSuffix(host, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
			if net.ParseIP(host) == nil {
				return ""
			}
		} else {
			return ""
		}
	case strings.Count(host, ":") > 1:
		return "" // IPv6 authorities must use brackets.
	case strings.Contains(host, ":"):
		h, port, err := net.SplitHostPort(host)
		if err != nil || h == "" || !validHostPort(port) {
			return ""
		}
		host = h
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

func validHostPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 0 && n <= 65535
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
