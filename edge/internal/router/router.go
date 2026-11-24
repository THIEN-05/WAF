package router

import (
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
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
	if len(host) > 4096 {
		return ""
	}
	host = strings.ToLower(host)
	parsed, err := url.Parse("//" + host)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	switch {
	case strings.HasPrefix(host, "["):
		if h, port, splitErr := net.SplitHostPort(host); splitErr == nil {
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
		h, port, splitErr := net.SplitHostPort(host)
		if splitErr != nil || h == "" || !validHostPort(port) {
			return ""
		}
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "[" + ip.String() + "]"
		}
		return ip.String()
	}
	if strings.HasSuffix(host, "..") {
		return ""
	}
	host = strings.TrimSuffix(host, ".")
	if !utf8.ValidString(host) {
		return ""
	}
	labels := strings.Split(host, ".")
	wildcard := strings.HasPrefix(host, "*.")
	if wildcard {
		labels = labels[1:]
	}
	if len(labels) == 0 {
		return ""
	}
	for i, label := range labels {
		if label == "" {
			return ""
		}
		for _, r := range label {
			if unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune("/\\?#@%[]", r) {
				return ""
			}
		}
		encoded, err := punycodeLabel(label)
		if err != nil {
			return ""
		}
		for _, r := range encoded {
			if !validBasicRune(r) {
				return ""
			}
		}
		if len(encoded) > 63 || strings.HasPrefix(encoded, "-") || strings.HasSuffix(encoded, "-") {
			return ""
		}
		if strings.HasPrefix(encoded, "xn--") {
			decoded, decodeErr := decodePunycodeLabel(encoded)
			canonical, encodeErr := punycodeLabel(decoded)
			if decodeErr != nil || encodeErr != nil || canonical != encoded {
				return ""
			}
		}
		labels[i] = encoded
	}
	canonical := strings.Join(labels, ".")
	if wildcard {
		canonical = "*." + canonical
	}
	if len(canonical) > 253 {
		return ""
	}
	return canonical
}

func validHostPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}
func (r *Router) Route(host string) *wafcore.Site {
	h := NormalizeHost(host)
	if strings.Contains(h, "*") {
		return nil
	}
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
