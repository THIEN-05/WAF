package edgecore

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	"github.com/example/wafplatform/edge/internal/telemetry"
	"github.com/example/wafplatform/edge/internal/waf"
	"github.com/example/wafplatform/edge/rulesets"
	"github.com/example/wafplatform/pkg/wafcore"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

type Edge struct {
	runtime         atomic.Pointer[runtimeConfig]
	metrics         pipeline.Metrics
	promMetrics     *telemetry.PrometheusMetrics
	auditMetrics    *pipeline.Histogram
	logShipper      *telemetry.Shipper
	pipeline        atomic.Pointer[pipeline.Pipeline]
	trafficMu       sync.Mutex
	telemetryEdgeID string
	telemetryRegion string
	banTable        *access.BanTable
	geoResolver     access.GeoResolver
	globalBlocks    *access.PrefixTree
	underAttack     access.UnderAttack
	rateLimiter     *ratelimit.Limiter
	ready           atomic.Bool
	via             string
	security        response.SecurityHeaders
	poolFactory     func([]wafcore.Origin, string) *proxy.OriginPool
	botManager      atomic.Pointer[bot.ChallengeManager]
	botVerified     bot.VerifiedBotChecker
	botIPTrust      bot.IPReputation
	botFPTrust      bot.FingerprintReputation
	botPhase        atomic.Pointer[bot.Phase]
	managedWAF      []waf.Rule
	poolMu          sync.Mutex
	pools           map[string]*proxy.OriginPool
	healthCtx       context.Context
	healthCancel    context.CancelFunc
}

type runtimeConfig struct {
	snapshot *wafcore.Snapshot
	router   *router.Router
	pipeline *pipeline.Pipeline
}

var fallbackRequestIDCounter atomic.Uint64

func New(s *wafcore.Snapshot, via string) *Edge {
	audit := pipeline.NewHistogram()
	prom := telemetry.NewPrometheusMetrics()
	healthCtx, healthCancel := context.WithCancel(context.Background())
	e := &Edge{via: via, metrics: composedMetrics{primary: prom, audit: audit}, promMetrics: prom, auditMetrics: audit, poolFactory: proxy.NewOriginPool, pools: map[string]*proxy.OriginPool{}, healthCtx: healthCtx, healthCancel: healthCancel}
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
func (e *Edge) SetReady(v bool) { e.ready.Store(v) }

// SelfTest exercises site selection and every in-process request phase using
// a synthetic benign request. Origin dialing remains covered by health checks.
func (e *Edge) SelfTest() error {
	state := e.runtime.Load()
	if state == nil || state.snapshot == nil || state.pipeline == nil || state.router == nil {
		return errors.New("edge has no compiled runtime snapshot")
	}
	for _, site := range state.snapshot.Sites {
		if site.Status != "active" {
			continue
		}
		for _, host := range site.Domains {
			if host == "" || strings.Contains(host, "*") {
				continue
			}
			r, err := http.NewRequest(http.MethodGet, "http://"+host+"/__waf/self-test", nil)
			if err != nil {
				continue
			}
			r.Host = host
			r.Header.Set("Accept", "text/html,application/xhtml+xml")
			r.Header.Set("Accept-Language", "en")
			r.Header.Set("User-Agent", "WAF-Edge-SelfTest/1")
			ctx := reqctx.New(r, state.snapshot, "edge-self-test", net.ParseIP("192.0.2.1"))
			resolved, status := state.router.Resolve(ctx)
			if status != 0 || resolved == nil {
				reqctx.Release(ctx)
				return fmt.Errorf("self-test site resolution failed: %s", host)
			}
			decision := state.pipeline.Run(ctx)
			reqctx.Release(ctx)
			if decision.Action != reqctx.ActionAllow && decision.Action != reqctx.ActionLogOnly {
				return fmt.Errorf("self-test request denied by %s/%s", decision.Phase, decision.RuleID)
			}
			return nil
		}
	}
	return errors.New("self-test requires an active site with a concrete domain")
}

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
	if e.logShipper != nil {
		e.logShipper.Close()
	}
	if e.auditMetrics != nil {
		e.auditMetrics.Close()
	}
}
func (e *Edge) Metrics() http.Handler                    { return e.promMetrics.Handler() }
func (e *Edge) SetLogShipper(shipper *telemetry.Shipper) { e.logShipper = shipper }
func (e *Edge) SetTelemetryIdentity(edgeID, region string) {
	e.telemetryEdgeID = edgeID
	e.telemetryRegion = region
}
func (e *Edge) RecordLogDropped(n uint64) { e.promMetrics.LogDropped(n) }
func (e *Edge) RecordCacheHit()           { e.promMetrics.CacheHit() }
func (e *Edge) RefreshMetrics(agentVersion uint64, agentAge time.Duration, hasAgent, snapshotStale bool, clientCertExpiry time.Time) {
	e.promMetrics.RefreshRuntime()
	state := e.runtime.Load()
	if hasAgent {
		e.promMetrics.SetSnapshot(agentVersion, agentAge.Seconds(), snapshotStale)
		e.promMetrics.SetClientCertificateExpiry(clientCertExpiry)
		return
	}
	if state != nil && state.snapshot != nil {
		age := time.Duration(0)
		if !state.snapshot.GeneratedAt.IsZero() {
			age = time.Since(state.snapshot.GeneratedAt)
			if age < 0 {
				age = 0
			}
		}
		e.promMetrics.SetSnapshot(state.snapshot.Version, age.Seconds(), false)
	}
}

type composedMetrics struct {
	primary *telemetry.PrometheusMetrics
	audit   *pipeline.Histogram
}

func (m composedMetrics) ObservePhase(name string, d time.Duration) {
	m.primary.ObservePhase(name, d)
	m.audit.ObservePhase(name, d)
}
func (m composedMetrics) Blocked(action string) { m.primary.Blocked(action); m.audit.Blocked(action) }
func (m composedMetrics) LogDropped(n uint64)   { m.primary.LogDropped(n); m.audit.LogDropped(n) }
func (m composedMetrics) EnqueueAudit(event pipeline.AuditEvent) bool {
	m.primary.AuditEvent(event.Kind)
	ok := m.audit.EnqueueAudit(event)
	if !ok {
		m.primary.AuditDropped(1)
	}
	return ok
}
func (e *Edge) Snapshot() *wafcore.Snapshot {
	state := e.runtime.Load()
	if state == nil {
		return nil
	}
	return state.snapshot
}
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
	started := time.Now()
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := otel.Tracer("waf/edge").Start(ctx, "edge.request", trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attribute.String("http.request.method", r.Method)))
	r = r.WithContext(ctx)
	tw := &trackingWriter{ResponseWriter: w}
	defer func() {
		status := tw.status
		if status == 0 {
			status = http.StatusOK
		}
		e.promMetrics.ObserveRequest(r.Method, status)
		span.SetAttributes(attribute.Int("http.response.status_code", status))
		if tw.originAttempted && status >= 500 {
			e.promMetrics.OriginError(status)
		}
		span.End()
	}()
	if r.URL.Path == "/healthz" {
		tw.WriteHeader(http.StatusOK)
		_, _ = tw.Write([]byte("ok\n"))
		return
	}
	if r.URL.Path == "/readyz" {
		if !e.ready.Load() {
			http.Error(tw, "not ready", http.StatusServiceUnavailable)
			return
		}
		tw.WriteHeader(http.StatusOK)
		_, _ = tw.Write([]byte("ready\n"))
		return
	}
	state := e.runtime.Load()
	if state == nil || state.snapshot == nil {
		http.Error(tw, "no snapshot", http.StatusServiceUnavailable)
		return
	}
	snap := state.snapshot
	id := requestID()
	clientIP := remoteIP(r.RemoteAddr)
	c := reqctx.New(r, snap, id, clientIP)
	defer reqctx.Release(c)
	defer e.recordRequest(c, tw, started)
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
		e.botManager.Load().ServeVerifyRequestID(tw, r, c.Site.ID, c.Site.Secrets.ChallengeHMACKeyID, c.ClientIP, c.Header("User-Agent"), c.RequestID)
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
		e.promMetrics.BlockedGroup(decision.Phase)
		if decision.Phase == "ratelimit" {
			e.promMetrics.RateLimited()
			log.Printf("giới hạn tốc độ request_id=%q rule_id=%q", c.RequestID, decision.RuleID)
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
				if bot.IsHTMLNavigation(c.Request) {
					bot.ChallengePageForRequest(tw, c.Request, c.BotChallengeToken)
				} else {
					writeAPIChallenge(tw, c.RequestID)
				}
			case decision.Phase == "bot":
				if bot.IsHTMLNavigation(c.Request) {
					response.Block(tw, c, http.StatusServiceUnavailable, "challenge unavailable")
				} else {
					writeAPIChallengeStatus(tw, http.StatusServiceUnavailable, "challenge_unavailable", c.RequestID)
				}
			default:
				if bot.IsHTMLNavigation(c.Request) {
					response.Challenge(tw, c)
				} else {
					writeAPIChallenge(tw, c.RequestID)
				}
			}
		} else {
			status := http.StatusForbidden
			code := "request_blocked"
			if decision.Action == reqctx.ActionRateLimited {
				status = http.StatusTooManyRequests
				code = "rate_limited"
			}
			if bot.IsHTMLNavigation(c.Request) {
				response.Block(tw, c, status, decision.Reason)
			} else {
				writeAPIChallengeStatus(tw, status, code, c.RequestID)
			}
		}
		return
	}
	e.proxySite(tw, c)
	if phase := e.botPhase.Load(); phase != nil && tw.status == http.StatusNotFound {
		phase.RecordResponse(c.Site.ID, c.ClientIP, c.Path, tw.status)
	}
}

func writeAPIChallenge(w http.ResponseWriter, requestID string) {
	writeAPIChallengeStatus(w, http.StatusForbidden, "challenge_required", requestID)
}

func writeAPIChallengeStatus(w http.ResponseWriter, status int, code, requestID string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-ID", requestID)
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q,"request_id":%q}`, code, requestID)
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
	log.Printf("edge panic request_id=%q: phục hồi sau panic: %q", c.RequestID, fmt.Sprint(recovered))
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
		if tracked, ok := w.(*trackingWriter); ok {
			tracked.originAttempted = true
		}
		response.Block(w, c, http.StatusBadGateway, err.Error())
		return
	}
	if tracked, ok := w.(*trackingWriter); ok {
		tracked.originAttempted = true
		upstreamStart := time.Now()
		defer func() { tracked.upstream = time.Since(upstreamStart) }()
	}
	pool.Serve(w, c)
}

func (e *Edge) recordRequest(c *reqctx.RequestCtx, tw *trackingWriter, started time.Time) {
	if c == nil || c.Site == nil || c.Request == nil {
		return
	}
	status := tw.status
	if status == 0 {
		status = http.StatusOK
	}
	decision := c.Decision()
	action := "allow"
	switch decision.Action {
	case reqctx.ActionBlock:
		action = "block"
	case reqctx.ActionChallenge:
		action = "challenge"
	case reqctx.ActionRateLimited:
		action = "rate_limited"
	case reqctx.ActionLogOnly:
		action = "log"
	}
	input := uint64(0)
	if c.Request.ContentLength > 0 {
		input = uint64(c.Request.ContentLength)
	}
	output := uint64(0)
	if tw.bytesWritten > 0 {
		output = uint64(tw.bytesWritten)
	}
	latency := time.Since(started)
	event := wafcore.LogEvent{SchemaVersion: wafcore.LogSchemaVersion, TS: started.UTC(), RequestID: c.RequestID, SiteID: c.Site.ID, TenantID: c.Site.TenantID, EdgeID: e.telemetryEdgeID, Region: e.telemetryRegion, ClientIP: clientIPString(c.ClientIP), Country: c.GeoCountry, ASN: c.GeoASN, JA3: c.JA3, Method: c.Method, Host: c.Host, Path: c.Path, Status: statusCode16(status), BytesIn: input, BytesOut: output, LatencyMS: durationMilliseconds(latency), UpstreamMS: durationMilliseconds(tw.upstream), Action: action, RuleID: decision.RuleID, WAFScore: score16(decision.Score), BotScore: score8(c.BotScore), CacheStatus: "", Tags: decision.Tags}
	for _, tag := range event.Tags {
		if tag == "cache_hit" {
			event.CacheStatus = "hit"
			e.promMetrics.CacheHit()
			break
		}
	}
	security := decision.Terminal() || decision.RuleID != "" || decision.Phase == "waf" || decision.Phase == "access" || decision.Phase == "ratelimit"
	if e.logShipper != nil {
		_ = e.logShipper.Record(event, security, c.Site.Plan)
	}
}
func clientIPString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
func durationMilliseconds(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	ms := uint64(d / time.Millisecond)
	if ms > uint64(1<<32-1) {
		ms = uint64(1<<32 - 1)
	}
	return uint32(ms)
}
func statusCode16(status int) uint16 {
	if status < 0 {
		return 0
	}
	if status > 65535 {
		return 65535
	}
	return uint16(status)
}
func score16(score int) uint16 {
	if score <= 0 {
		return 0
	}
	if score >= 65535 {
		return 65535
	}
	return uint16(score)
}
func score8(score int) uint8 {
	if score <= 0 {
		return 0
	}
	if score >= 255 {
		return 255
	}
	return uint8(score)
}

type trackingWriter struct {
	http.ResponseWriter
	wrote           bool
	status          int
	bytesWritten    int64
	upstream        time.Duration
	originAttempted bool
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
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}
func (w *trackingWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := io.Copy(w.ResponseWriter, r)
	w.bytesWritten += n
	return n, err
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
	if !w.wrote {
		w.status = http.StatusSwitchingProtocols
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
