package edgecore

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/wafplatform/edge/internal/access"
	"github.com/example/wafplatform/edge/internal/pipeline"
	"github.com/example/wafplatform/edge/internal/proxy"
	"github.com/example/wafplatform/edge/internal/ratelimit"
	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/edge/internal/response"
	"github.com/example/wafplatform/edge/internal/router"
	"github.com/example/wafplatform/pkg/wafcore"
)

type Edge struct {
	runtime      atomic.Pointer[runtimeConfig]
	metrics      pipeline.Metrics
	histogram    *pipeline.Histogram
	pipeline     atomic.Pointer[pipeline.Pipeline]
	trafficMu    sync.Mutex
	banTable     *access.BanTable
	geoResolver  access.GeoResolver
	globalBlocks *access.PrefixTree
	underAttack  access.UnderAttack
	rateLimiter  *ratelimit.Limiter
	ready        atomic.Bool
	via          string
	security     response.SecurityHeaders
	poolFactory  func([]wafcore.Origin, string) *proxy.OriginPool
	poolMu       sync.Mutex
	pools        map[string]*proxy.OriginPool
	healthCtx    context.Context
	healthCancel context.CancelFunc
}

type runtimeConfig struct {
	snapshot *wafcore.Snapshot
	router   *router.Router
}

func New(s *wafcore.Snapshot, via string) *Edge {
	h := pipeline.NewHistogram()
	healthCtx, healthCancel := context.WithCancel(context.Background())
	e := &Edge{via: via, metrics: h, histogram: h, poolFactory: proxy.NewOriginPool, pools: map[string]*proxy.OriginPool{}, healthCtx: healthCtx, healthCancel: healthCancel}
	e.banTable = access.NewBanTable(100_000, time.Now)
	e.rateLimiter = ratelimit.NewLimiter(ratelimit.Config{})
	e.underAttack = access.DisabledUnderAttack{}
	e.installTrafficPipelineLocked()
	if s != nil {
		e.Apply(s)
	}
	e.ready.Store(true)
	return e
}
func (e *Edge) Apply(s *wafcore.Snapshot) {
	e.poolMu.Lock()
	if e.healthCancel != nil {
		e.healthCancel()
	}
	e.healthCtx, e.healthCancel = context.WithCancel(context.Background())
	e.pools = map[string]*proxy.OriginPool{}
	e.poolMu.Unlock()
	e.runtime.Store(&runtimeConfig{snapshot: s, router: router.New(s)})
}
func (e *Edge) SetReady(v bool)                                     { e.ready.Store(v) }
func (e *Edge) SetSecurityHeaders(headers response.SecurityHeaders) { e.security = headers }
func (e *Edge) SetGeoResolver(resolver access.GeoResolver) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	e.geoResolver = resolver
	e.installTrafficPipelineLocked()
}
func (e *Edge) SetGlobalBlocklist(tree *access.PrefixTree) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	e.globalBlocks = tree
	e.installTrafficPipelineLocked()
}
func (e *Edge) SetUnderAttack(attack access.UnderAttack) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	e.underAttack = attack
	e.installTrafficPipelineLocked()
}
func (e *Edge) SetRedisSync(syncer *ratelimit.AsyncRedisSync) {
	e.rateLimiter.SetRedisSync(syncer)
}
func (e *Edge) SetPipeline(p *pipeline.Pipeline) { e.pipeline.Store(p) }

func (e *Edge) installTrafficPipelineLocked() {
	accessPhase := access.NewPhase(e.geoResolver, e.banTable, e.globalBlocks, e.underAttack)
	ratePhase := ratelimit.NewPhase(e.rateLimiter, e.banTable)
	e.pipeline.Store(pipeline.New(e.metrics, accessPhase, ratePhase))
}
func (e *Edge) Close() {
	e.poolMu.Lock()
	if e.healthCancel != nil {
		e.healthCancel()
	}
	e.poolMu.Unlock()
}
func (e *Edge) Metrics() http.Handler { return e.histogram }
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	if r.URL.Path == "/readyz" {
		if !e.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
		return
	}
	state := e.runtime.Load()
	if state == nil || state.snapshot == nil {
		http.Error(w, "no snapshot", http.StatusServiceUnavailable)
		return
	}
	snap := state.snapshot
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		id = requestID()
	}
	clientIP := remoteIP(r.RemoteAddr)
	c := reqctx.New(r, snap, id, clientIP)
	defer reqctx.Release(c)
	tw := &trackingWriter{ResponseWriter: w}
	response.ApplyHeaders(tw.Header(), e.security)
	defer func() {
		if recovered := recover(); recovered != nil {
			e.recoverPanic(tw, c, recovered)
		}
	}()
	_, status := state.router.Resolve(c)
	if status != 0 {
		response.Block(tw, c, status, http.StatusText(status))
		return
	}
	decision := e.pipeline.Load().Run(c)
	if decision.Terminal() {
		e.metrics.Blocked(actionName(decision.Action))
		if decision.Phase == "ratelimit" {
			log.Printf("giới hạn tốc độ request_id=%s rule_id=%s", c.RequestID, decision.RuleID)
		}
		if decision.RetryAfter > 0 {
			retrySeconds := int64((decision.RetryAfter + time.Second - 1) / time.Second)
			if retrySeconds < 1 {
				retrySeconds = 1
			}
			tw.Header().Set("Retry-After", fmt.Sprintf("%d", retrySeconds))
		}
		if decision.Action == reqctx.ActionChallenge {
			response.Challenge(tw, c)
		} else {
			status := http.StatusForbidden
			if decision.Action == reqctx.ActionRateLimited {
				status = http.StatusTooManyRequests
			}
			response.Block(tw, c, status, decision.Reason)
		}
		return
	}
	e.proxySite(tw, c)
}

func (e *Edge) recoverPanic(tw *trackingWriter, c *reqctx.RequestCtx, recovered any) {
	e.metrics.Blocked("panic")
	log.Printf("edge panic request_id=%s: phục hồi sau panic: %v", c.RequestID, recovered)
	if tw.wrote {
		if h, ok := tw.ResponseWriter.(http.Hijacker); ok {
			conn, _, err := h.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
		return
	}
	if c.Site != nil && c.Site.FailMode == "open" {
		func() { defer func() { _ = recover() }(); e.proxySite(tw, c) }()
		return
	}
	status := http.StatusInternalServerError
	if c.Site != nil && c.Site.FailMode == "closed" {
		status = http.StatusServiceUnavailable
	}
	response.Block(tw, c, status, "internal edge error")
}

func (e *Edge) proxySite(w http.ResponseWriter, c *reqctx.RequestCtx) {
	if c.Site == nil {
		return
	}
	e.poolMu.Lock()
	poolKey := fmt.Sprintf("%d:%s", c.Snapshot.Version, c.Site.ID)
	pool := e.pools[poolKey]
	if pool == nil {
		pool = e.poolFactory(c.Site.Origins, e.via)
		pool.ResponseHeaderHook = func(h http.Header) { response.ApplyHeaders(h, e.security) }
		e.pools[poolKey] = pool
		go pool.HealthCheck(e.healthCtx, 10*time.Second)
	}
	e.poolMu.Unlock()
	if err := pool.ValidateOrigins(); err != nil {
		response.Block(w, c, http.StatusBadGateway, err.Error())
		return
	}
	pool.Serve(w, c)
}

func actionName(a reqctx.Action) string {
	switch a {
	case reqctx.ActionBlock:
		return "block"
	case reqctx.ActionChallenge:
		return "challenge"
	case reqctx.ActionRateLimited:
		return "rate_limited"
	default:
		return "other"
	}
}

type trackingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *trackingWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *trackingWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *trackingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if !w.wrote {
			w.WriteHeader(http.StatusOK)
		}
		f.Flush()
	}
}
func (w *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	w.wrote = true
	return h.Hijack()
}
func (w *trackingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func requestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
func remoteIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ParseIP(addr)
	}
	return net.ParseIP(host)
}
