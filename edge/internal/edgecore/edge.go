package edgecore

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/wafplatform/edge/internal/access"
	"github.com/example/wafplatform/edge/internal/bot"
	"github.com/example/wafplatform/edge/internal/pipeline"
	"github.com/example/wafplatform/edge/internal/proxy"
	"github.com/example/wafplatform/edge/internal/ratelimit"
	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/edge/internal/response"
	"github.com/example/wafplatform/edge/internal/router"
	"github.com/example/wafplatform/edge/internal/rules"
	"github.com/example/wafplatform/edge/internal/waf"
	"github.com/example/wafplatform/edge/rulesets"
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
	botManager   atomic.Pointer[bot.ChallengeManager]
	botVerified  bot.VerifiedBotChecker
	botIPTrust   bot.IPReputation
	botFPTrust   bot.FingerprintReputation
	botPhase     atomic.Pointer[bot.Phase]
	managedWAF   []waf.Rule
	poolMu       sync.Mutex
	pools        map[string]*proxy.OriginPool
	healthCtx    context.Context
	healthCancel context.CancelFunc
}

type runtimeConfig struct {
	snapshot *wafcore.Snapshot
	router   *router.Router
	pipeline *pipeline.Pipeline
}

var fallbackRequestIDCounter atomic.Uint64

func New(s *wafcore.Snapshot, via string) *Edge {
	h := pipeline.NewHistogram()
	healthCtx, healthCancel := context.WithCancel(context.Background())
	e := &Edge{via: via, metrics: h, histogram: h, poolFactory: proxy.NewOriginPool, pools: map[string]*proxy.OriginPool{}, healthCtx: healthCtx, healthCancel: healthCancel}
	e.botManager.Store(bot.NewChallengeManager(bot.StaticKeyRing{}))
	e.banTable = access.NewBanTable(100_000, time.Now)
	e.rateLimiter = ratelimit.NewLimiter(ratelimit.Config{})
	e.underAttack = access.DisabledUnderAttack{}
	managed, err := rulesets.LoadEmbedded(wafcore.DefaultLimits().MaxRegexBytes)
	if err != nil {
		panic(fmt.Errorf("load embedded managed WAF rules: %w", err))
	}
	e.managedWAF = managed
	if s != nil {
		if err := e.Apply(s); err != nil {
			log.Printf("snapshot chưa được áp dụng: %v", err)
		}
	}
	e.ready.Store(e.runtime.Load() != nil)
	return e
}
func (e *Edge) Apply(s *wafcore.Snapshot) error {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	if s == nil {
		return fmt.Errorf("snapshot is nil")
	}
	pipe, err := e.buildPipeline(s)
	if err != nil {
		return err
	}
	e.poolMu.Lock()
	if e.healthCancel != nil {
		e.healthCancel()
	}
	e.healthCtx, e.healthCancel = context.WithCancel(context.Background())
	e.pools = map[string]*proxy.OriginPool{}
	e.poolMu.Unlock()
	e.runtime.Store(&runtimeConfig{snapshot: s, router: router.New(s), pipeline: pipe})
	e.ready.Store(true)
	return nil
}
func (e *Edge) SetReady(v bool)                                     { e.ready.Store(v) }
func (e *Edge) SetSecurityHeaders(headers response.SecurityHeaders) { e.security = headers }
func (e *Edge) SetGeoResolver(resolver access.GeoResolver) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	e.geoResolver = resolver
	e.rebuildPipelineLocked()
}
func (e *Edge) SetGlobalBlocklist(tree *access.PrefixTree) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	e.globalBlocks = tree
	e.rebuildPipelineLocked()
}
func (e *Edge) SetUnderAttack(attack access.UnderAttack) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	e.underAttack = attack
	e.rebuildPipelineLocked()
}
func (e *Edge) SetRedisSync(syncer *ratelimit.AsyncRedisSync) {
	e.rateLimiter.SetRedisSync(syncer)
}
func (e *Edge) SetBotChallengeKeys(keys bot.KeyRing) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	if manager := e.botManager.Load(); manager != nil {
		manager.SetKeyRing(keys)
	} else {
		e.botManager.Store(bot.NewChallengeManager(keys))
	}
	e.rebuildPipelineLocked()
}
func (e *Edge) SetVerifiedBotResolver(resolver bot.VerifiedBotChecker) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	e.botVerified = resolver
	e.rebuildPipelineLocked()
}
func (e *Edge) SetBotReputation(ip bot.IPReputation, fingerprints bot.FingerprintReputation) {
	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()
	e.botIPTrust, e.botFPTrust = ip, fingerprints
	e.rebuildPipelineLocked()
}
func (e *Edge) SetPipeline(p *pipeline.Pipeline) { e.pipeline.Store(p) }

func (e *Edge) buildPipeline(snapshot *wafcore.Snapshot) (*pipeline.Pipeline, error) {
	accessPhase := access.NewPhase(e.geoResolver, e.banTable, e.globalBlocks, e.underAttack)
	ratePhase := ratelimit.NewPhase(e.rateLimiter, e.banTable)
	rulesPhase, err := rules.NewPhase(snapshot, ratePhase, nil)
	if err != nil {
		return nil, err
	}
	wafPhase, err := waf.NewPhase(e.managedWAF, nil)
	if err != nil {
		return nil, err
	}
	botPhase := bot.NewPhase(e.botManager.Load(), e.botVerified)
	if e.botIPTrust != nil {
		botPhase.IPTrust = e.botIPTrust
	}
	botPhase.Fingerprints = e.botFPTrust
	e.botPhase.Store(botPhase)
	return pipeline.New(e.metrics, accessPhase, ratePhase, rulesPhase, wafPhase, botPhase), nil
}

func (e *Edge) rebuildPipelineLocked() {
	state := e.runtime.Load()
	if state == nil {
		return
	}
	pipe, err := e.buildPipeline(state.snapshot)
	if err != nil {
		log.Printf("không thể biên dịch pipeline snapshot %d: %v", state.snapshot.Version, err)
		return
	}
	e.runtime.Store(&runtimeConfig{snapshot: state.snapshot, router: state.router, pipeline: pipe})
}
func (e *Edge) Close() {
	e.poolMu.Lock()
	if e.healthCancel != nil {
		e.healthCancel()
	}
	e.poolMu.Unlock()
	if e.histogram != nil {
		e.histogram.Close()
	}
}
func (e *Edge) Metrics() http.Handler { return e.histogram }
func (e *Edge) CanonicalHTTPHost(host string) (string, bool) {
	state := e.runtime.Load()
	if state == nil || state.router == nil {
		return "", false
	}
	name := host
	if strings.Contains(name, ":") {
		parsedHost, port, err := net.SplitHostPort(name)
		if err != nil {
			return "", false
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", false
		}
		name = parsedHost
	}
	if strings.ContainsAny(name, "@/\\?#[]") {
		return "", false
	}
	canonical := router.NormalizeHost(name)
	if canonical == "" || state.router.Route(canonical) == nil {
		return "", false
	}
	return canonical, true
}
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
	id := requestID()
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
	if r.URL.Path == "/__waf/verify" {
		if !c.Site.Entitlements.BotJSChallenge {
			http.NotFound(tw, r)
			return
		}
		e.botManager.Load().ServeVerifyKey(tw, r, c.Site.ID, c.Site.Secrets.ChallengeHMACKeyID, c.ClientIP, c.Header("User-Agent"))
		return
	}
	requestPipeline := state.pipeline
	if override := e.pipeline.Load(); override != nil {
		requestPipeline = override
	}
	var decision reqctx.Decision
	bodyDeadlineSet := false
	if c.Request.Body != nil && c.Request.Body != http.NoBody && needsBodyInspection(c.Site) {
		timeout := time.Second
		if c.Site.WAF.BodyReadTimeoutMS > 0 {
			timeout = time.Duration(c.Site.WAF.BodyReadTimeoutMS) * time.Millisecond
		}
		controller := http.NewResponseController(tw)
		if err := controller.SetReadDeadline(time.Now().Add(timeout)); err == nil {
			bodyDeadlineSet = true
		} else if !errors.Is(err, http.ErrNotSupported) {
			c.MarkBodyReadError(fmt.Errorf("set body read deadline: %w", err))
		}
	}
	func() {
		if bodyDeadlineSet {
			defer func() {
				// Keep an expired socket deadline after a timed-out read so fail-open
				// cannot leave the origin proxy blocked on the unread remainder.
				if !c.BodyReadTimedOut() {
					_ = http.NewResponseController(tw).SetReadDeadline(time.Time{})
				}
			}()
		}
		decision = requestPipeline.Run(c)
	}()
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
			switch {
			case decision.Phase == "bot" && c.BotChallengeToken != "":
				bot.ChallengePage(tw, c.BotChallengeToken)
			case decision.Phase == "bot":
				response.Block(tw, c, http.StatusServiceUnavailable, "challenge unavailable")
			default:
				response.Challenge(tw, c)
			}
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
	if phase := e.botPhase.Load(); phase != nil && tw.status == http.StatusNotFound {
		phase.RecordResponse(c.Site.ID, c.ClientIP, c.Path, tw.status)
	}
}

func needsBodyInspection(site *wafcore.Site) bool {
	if site == nil {
		return false
	}
	for _, rule := range site.Rules {
		if wafcore.ExpressionUsesField(rule.Expression, "http.body") {
			return true
		}
	}
	return site.WAF.Mode != "off"
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
	wrote  bool
	status int
}

func (w *trackingWriter) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		w.status = code
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
		copy(b[:8], "wafedge0")
		binary.BigEndian.PutUint64(b[8:], fallbackRequestIDCounter.Add(1))
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
