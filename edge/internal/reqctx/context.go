package reqctx

import (
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
	Method, Path, Query, Protocol string
	Entitlements                  wafcore.Entitlements
	decision                      Decision
	parsedQuery                   url.Values
	queryParsed                   bool
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
	c.Entitlements = wafcore.Entitlements{}
	c.decision = Decision{}
	c.parsedQuery = nil
	c.queryParsed = false
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
	c.Entitlements = wafcore.Entitlements{}
	c.decision = Decision{}
	c.parsedQuery = nil
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
