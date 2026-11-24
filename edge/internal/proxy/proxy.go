package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

type OriginPool struct {
	origins            []wafcore.Origin
	healthy            []atomic.Bool
	next               atomic.Int64
	mu                 sync.Mutex
	failures           []int
	openUntil          []time.Time
	probing            []bool
	client             *http.Client
	timeout            time.Duration
	via                string
	resolve            func(context.Context, string) ([]net.IP, error)
	dialIP             func(context.Context, string, string) (net.Conn, error)
	clock              func() time.Time
	ResponseHeaderHook func(http.Header)
}

type retryTransport struct {
	base     http.RoundTripper
	attempts int
}

func (t retryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	max := 1
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && (r.Body == nil || r.Body == http.NoBody) && t.attempts > 1 {
		max = t.attempts
	}
	var last error
	for i := 0; i < max; i++ {
		resp, err := t.base.RoundTrip(r)
		if err == nil {
			return resp, nil
		}
		last = err
		if r.Context().Err() != nil || !isDialError(err) {
			return nil, err
		}
	}
	return nil, last
}
func isDialError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && (op.Op == "dial" || op.Op == "connect")
}

func NewOriginPool(origins []wafcore.Origin, via string) *OriginPool {
	p := &OriginPool{origins: append([]wafcore.Origin(nil), origins...), healthy: make([]atomic.Bool, len(origins)), failures: make([]int, len(origins)), openUntil: make([]time.Time, len(origins)), probing: make([]bool, len(origins)), timeout: 30 * time.Second, via: via, clock: time.Now}
	p.resolve = func(ctx context.Context, host string) ([]net.IP, error) {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		return ips, err
	}
	p.dialIP = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		return d.DialContext(ctx, network, address)
	}
	for i := range p.healthy {
		p.healthy[i].Store(true)
	}
	p.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: p.dial, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: p.timeout, IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 100, ForceAttemptHTTP2: true}, Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return p
}

func (p *OriginPool) ValidateOrigins() error {
	for i, origin := range p.origins {
		u, err := url.Parse(origin.URL)
		if err != nil || u.Hostname() == "" {
			return fmt.Errorf("origin[%d]: invalid URL", i)
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && blockedIP(ip) {
			return fmt.Errorf("origin[%d]: prohibited address %s", i, ip)
		}
		if net.ParseIP(u.Hostname()) == nil {
			ips, resolveErr := p.resolve(context.Background(), u.Hostname())
			if resolveErr != nil {
				return fmt.Errorf("origin[%d]: resolve host: %w", i, resolveErr)
			}
			if len(ips) == 0 {
				return fmt.Errorf("origin[%d]: hostname resolved to no addresses", i)
			}
			for _, ip := range ips {
				if blockedIP(ip) {
					return fmt.Errorf("origin[%d]: hostname resolves to prohibited address %s", i, ip)
				}
			}
		}
	}
	return nil
}
func (p *OriginPool) Transport() http.RoundTripper {
	base := p.client.Transport.(*http.Transport)
	return retryTransport{base: base, attempts: 2}
}
func (p *OriginPool) SetResolver(resolver func(context.Context, string) ([]net.IP, error)) {
	if resolver != nil {
		p.resolve = resolver
	}
}
func (p *OriginPool) SetDialer(dialer func(context.Context, string, string) (net.Conn, error)) {
	if dialer != nil {
		p.dialIP = dialer
	}
}
func (p *OriginPool) Select() (wafcore.Origin, int, error) {
	if len(p.origins) == 0 {
		return wafcore.Origin{}, -1, errors.New("no origins configured")
	}
	total := 0
	for _, o := range p.origins {
		if o.Weight > 0 {
			total += o.Weight
		}
	}
	if total == 0 {
		total = len(p.origins)
	}
	slot := (p.next.Add(1) - 1) % int64(total)
	if slot < 0 {
		slot += int64(total)
	}
	for i, o := range p.origins {
		weight := o.Weight
		if weight <= 0 && total == len(p.origins) {
			weight = 1
		}
		if weight <= 0 || !p.eligible(i) {
			continue
		}
		slot -= int64(weight)
		if slot < 0 {
			return o, i, nil
		}
	}
	for i, o := range p.origins {
		if p.eligible(i) {
			return o, i, nil
		}
	}
	return wafcore.Origin{}, -1, errors.New("no healthy origins")
}
func (p *OriginPool) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := p.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("origin host resolved to no addresses")
	}
	for _, ip := range ips {
		if blockedIP(ip) {
			return nil, fmt.Errorf("origin address %s is prohibited", ip)
		}
	}
	var last error
	for _, ip := range ips {
		conn, e := p.dialIP(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, last
}
func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
			return true
		}
	}
	return false
}
func (p *OriginPool) Serve(w http.ResponseWriter, c *reqctx.RequestCtx) {
	origin, index, err := p.Select()
	if err != nil {
		writeProxyError(w, c, http.StatusBadGateway, "no healthy origin")
		return
	}
	target, err := url.Parse(origin.URL)
	if err != nil {
		writeProxyError(w, c, http.StatusBadGateway, "invalid origin")
		return
	}
	if hasLoopVia(c.Request.Header.Values("Via"), p.via) {
		writeProxyError(w, c, http.StatusLoopDetected, "proxy loop detected")
		return
	}
	{
		proxy := &httputil.ReverseProxy{Transport: p.Transport(), FlushInterval: -1}
		proxy.Rewrite = func(pr *httputil.ProxyRequest) {
			r := pr.Out
			r.URL.Scheme = target.Scheme
			r.URL.Host = target.Host
			r.URL.Path = joinPath(target.Path, c.Request.URL.Path)
			r.URL.RawQuery = joinQuery(target.RawQuery, c.Request.URL.RawQuery)
			if origin.HostHeader != "" {
				r.Host = origin.HostHeader
			} else {
				r.Host = c.Request.Host
			}
			for name := range r.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") || strings.EqualFold(name, "X-Real-IP") || strings.EqualFold(name, "Forwarded") {
					r.Header.Del(name)
				}
			}
			clientIP := ""
			if c.ClientIP != nil {
				clientIP = c.ClientIP.String()
			}
			r.Header.Set("X-Forwarded-For", clientIP)
			proto := "http"
			if c.Request.TLS != nil {
				proto = "https"
			}
			r.Header.Set("X-Forwarded-Proto", proto)
			r.Header.Set("X-Forwarded-Host", c.Request.Host)
			r.Header.Set("X-Request-ID", safeRequestID(c.RequestID))
			r.Header.Del("Via")
			r.Header.Set("Via", "1.1 "+p.via)
			otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))
		}
		proxy.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, e error) {
			// safeRequestID accepts only the fixed-width hexadecimal IDs generated by edgecore.
			// The control-character test covers hostile IDs passed through direct internal callers.
			//nolint:gosec // validated hexadecimal correlation ID is quoted; no attacker text reaches this log field.
			log.Printf("origin request_id=%q transport_error=%T", safeRequestID(c.RequestID), e)
			p.recordFailure(index)
			status := http.StatusBadGateway
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				status = http.StatusGatewayTimeout
			}
			writeProxyError(rw, c, status, e.Error())
		}
		proxy.ModifyResponse = func(resp *http.Response) error {
			p.recordSuccess(index)
			if p.ResponseHeaderHook != nil {
				p.ResponseHeaderHook(resp.Header)
			}
			return nil
		}
		proxy.ServeHTTP(w, c.Request)
	}
}

func (p *OriginPool) ServeOrigin(w http.ResponseWriter, r *http.Request, origin wafcore.Origin, via, requestID, clientIP string) {
	ctx := reqctx.New(r, nil, requestID, net.ParseIP(clientIP))
	defer reqctx.Release(ctx)
	ctx.Site = &wafcore.Site{Origins: []wafcore.Origin{origin}}
	p.Serve(w, ctx)
	_ = via
}
func (p *OriginPool) recordFailure(i int) {
	if i < 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures[i]++
	if p.failures[i] >= 5 || p.probing[i] {
		p.openUntil[i] = p.clock().Add(30 * time.Second)
		p.probing[i] = false
	}
}
func (p *OriginPool) recordSuccess(i int) {
	if i < 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures[i] = 0
	p.openUntil[i] = time.Time{}
	p.probing[i] = false
}
func (p *OriginPool) HealthCheck(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i, o := range p.origins {
				u, err := url.Parse(o.URL)
				if err != nil {
					p.healthy[i].Store(false)
					continue
				}
				reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				req, _ := http.NewRequestWithContext(reqCtx, http.MethodHead, u.String(), nil)
				resp, e := p.client.Do(req)
				cancel()
				ok := e == nil
				if resp != nil {
					if closeErr := resp.Body.Close(); closeErr != nil {
						log.Printf("origin health check: lỗi đóng response body: %v", closeErr)
						ok = false
					}
				}
				p.healthy[i].Store(ok)
				if ok {
					p.recordSuccess(i)
				}
			}
		}
	}
}
func (p *OriginPool) eligible(i int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clock().Before(p.openUntil[i]) {
		return false
	}
	if !p.openUntil[i].IsZero() {
		if p.probing[i] {
			return false
		}
		p.probing[i] = true
	}
	return p.healthy[i].Load()
}

func (p *OriginPool) RecordFailure(i int) { p.recordFailure(i) }
func (p *OriginPool) RecordSuccess(i int) { p.recordSuccess(i) }
func (p *OriginPool) CircuitState(i int) (failures int, openUntil time.Time, halfOpen bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	failures = p.failures[i]
	openUntil = p.openUntil[i]
	halfOpen = !openUntil.IsZero() && !p.clock().Before(openUntil)
	return
}
func hasLoopVia(values []string, via string) bool {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if strings.Contains(strings.ToLower(part), strings.ToLower(via)) {
				return true
			}
		}
	}
	return false
}
func joinPath(a, b string) string {
	if a == "" {
		return b
	}
	return strings.TrimRight(a, "/") + "/" + strings.TrimLeft(b, "/")
}
func joinQuery(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "&" + b
}
func writeProxyError(w http.ResponseWriter, c *reqctx.RequestCtx, status int, reason string) {
	id := safeRequestID(c.RequestID)
	if id != "" {
		w.Header().Set("X-Request-ID", id)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "upstream error (%s)\n", strconv.Itoa(status))
}

func safeRequestID(value string) string {
	if len(value) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return value
}
