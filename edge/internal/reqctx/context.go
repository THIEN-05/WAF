package reqctx

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
)

type Action uint8

const (
	ActionAllow Action = iota
	ActionBlock
	ActionChallenge
	ActionRateLimited
	ActionLogOnly
)

type Decision struct {
	Action        Action
	RuleID, Phase string
	Score         int
	RetryAfter    time.Duration
	Tags          []string
	Reason        string
}

func (d Decision) Terminal() bool {
	return d.Action == ActionBlock || d.Action == ActionChallenge || d.Action == ActionRateLimited
}

type RequestCtx struct {
	Request                       *http.Request
	Snapshot                      *wafcore.Snapshot
	Site                          *wafcore.Site
	RequestID                     string
	StartedAt                     time.Time
	ClientIP                      net.IP
	Host, SNI, JA3, JA4           string
	GeoCountry                    string
	GeoASN                        uint32
	GeoResolved                   bool
	WAFScore                      int
	Method, Path, Query, Protocol string
	Entitlements                  wafcore.Entitlements
	decision                      Decision
	parsedQuery                   url.Values
	queryParsed                   bool
	bodyText                      string
	bodyLoaded                    bool
	bodyTruncated                 bool
	bodyReadErr                   error
	skippedPhases                 map[string]struct{}
	tags                          []string
}

var pool = sync.Pool{New: func() any { return &RequestCtx{} }}

func New(r *http.Request, s *wafcore.Snapshot, requestID string, clientIP net.IP) *RequestCtx {
	c := pool.Get().(*RequestCtx)
	c.Request = r
	c.Snapshot = s
	c.RequestID = requestID
	c.StartedAt = time.Now()
	c.ClientIP = clientIP
	c.Host = r.Host
	c.SNI = ""
	if r.TLS != nil {
		c.SNI = r.TLS.ServerName
	}
	c.Method = r.Method
	c.Path = r.URL.Path
	c.Query = r.URL.RawQuery
	c.Protocol = r.Proto
	c.Site = nil
	c.JA3 = ""
	c.JA4 = ""
	c.GeoCountry = ""
	c.GeoASN = 0
	c.GeoResolved = false
	c.WAFScore = 0
	c.Entitlements = wafcore.Entitlements{}
	c.decision = Decision{}
	c.parsedQuery = nil
	c.queryParsed = false
	c.bodyText = ""
	c.bodyLoaded = false
	c.bodyTruncated = false
	c.bodyReadErr = nil
	c.skippedPhases = nil
	c.tags = nil
	return c
}
func Release(c *RequestCtx) {
	c.Request = nil
	c.Snapshot = nil
	c.Site = nil
	c.ClientIP = nil
	c.Host = ""
	c.SNI = ""
	c.RequestID = ""
	c.Path = ""
	c.Query = ""
	c.Protocol = ""
	c.JA3 = ""
	c.JA4 = ""
	c.GeoCountry = ""
	c.GeoASN = 0
	c.GeoResolved = false
	c.WAFScore = 0
	c.Entitlements = wafcore.Entitlements{}
	c.decision = Decision{}
	c.parsedQuery = nil
	c.bodyText = ""
	c.bodyLoaded = false
	c.bodyTruncated = false
	c.bodyReadErr = nil
	c.skippedPhases = nil
	c.tags = nil
	pool.Put(c)
}
func (c *RequestCtx) QueryValues() url.Values {
	if !c.queryParsed {
		c.parsedQuery, _ = url.ParseQuery(c.Query)
		c.queryParsed = true
	}
	return c.parsedQuery
}
func (c *RequestCtx) Decision() Decision     { return c.decision }
func (c *RequestCtx) SetDecision(d Decision) { c.decision = d }

func (c *RequestCtx) String(field string) string {
	switch field {
	case "http.host":
		return c.Host
	case "http.method":
		return c.Method
	case "http.path":
		return c.Path
	case "http.query":
		return c.Query
	case "http.body":
		return c.BodyText()
	case "http.uri":
		if c.Request != nil && c.Request.URL != nil {
			return c.Request.URL.RequestURI()
		}
	case "http.user_agent":
		return c.Header("User-Agent")
	case "http.referer":
		return c.Header("Referer")
	case "ip.geo.country":
		return c.GeoCountry
	case "tls.ja3":
		return c.JA3
	}
	return ""
}

func (c *RequestCtx) Number(field string) float64 {
	switch field {
	case "ip.geo.asn":
		return float64(c.GeoASN)
	case "req.size":
		if c.Request != nil && c.Request.ContentLength > 0 {
			return float64(c.Request.ContentLength)
		}
	case "waf.score":
		return float64(c.WAFScore)
	}
	return 0
}

// BodyText reads a bounded request body once and restores it for the origin.
func (c *RequestCtx) BodyText() string {
	if c.bodyLoaded {
		return c.bodyText
	}
	c.bodyLoaded = true
	if c.Request == nil || c.Request.Body == nil || c.Request.Body == http.NoBody {
		return ""
	}
	limit := int64(8 * 1024)
	if c.Site != nil && c.Site.WAF.BodyLimitKB > 0 {
		limit = int64(c.Site.WAF.BodyLimitKB) * 1024
	}
	if c.Entitlements.MaxBodyBytes > 0 && int64(c.Entitlements.MaxBodyBytes) < limit {
		limit = int64(c.Entitlements.MaxBodyBytes)
	}
	if limit < 1 {
		limit = 8 * 1024
	}
	original := c.Request.Body
	captured, err := io.ReadAll(io.LimitReader(original, limit+1))
	c.bodyReadErr = err
	c.bodyTruncated = int64(len(captured)) > limit
	if c.bodyTruncated {
		c.bodyText = string(captured[:limit])
	} else {
		c.bodyText = string(captured)
	}
	c.Request.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(captured), original), closer: original}
	return c.bodyText
}

func (c *RequestCtx) BodyTruncated() bool  { return c.bodyTruncated }
func (c *RequestCtx) BodyReadError() error { return c.bodyReadErr }
func (c *RequestCtx) BodyLoaded() bool     { return c.bodyLoaded }

type replayBody struct {
	io.Reader
	closer io.Closer
}

func (b *replayBody) Close() error { return b.closer.Close() }

func (c *RequestCtx) SkipPhase(name string) {
	if name == "" {
		return
	}
	if c.skippedPhases == nil {
		c.skippedPhases = make(map[string]struct{})
	}
	c.skippedPhases[name] = struct{}{}
}

func (c *RequestCtx) PhaseSkipped(name string) bool {
	_, ok := c.skippedPhases[name]
	return ok
}

func (c *RequestCtx) AddTag(tag string) {
	if tag == "" || len(c.tags) >= 32 {
		return
	}
	for _, existing := range c.tags {
		if existing == tag {
			return
		}
	}
	c.tags = append(c.tags, tag)
}

func (c *RequestCtx) Tags() []string { return append([]string(nil), c.tags...) }

func (c *RequestCtx) IP(field string) net.IP {
	if field == "ip.src" {
		return c.ClientIP
	}
	return nil
}

func (c *RequestCtx) Header(name string) string {
	if c.Request == nil {
		return ""
	}
	return c.Request.Header.Get(name)
}

func (c *RequestCtx) Cookie(name string) string {
	if c.Request == nil {
		return ""
	}
	cookie, err := c.Request.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}
