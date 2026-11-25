package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

func TestValidateOriginsBlocksLocalAddresses(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.1.2.3", "169.254.1.1", "169.254.169.254", "::1", "192.168.1.2"} {
		p := NewOriginPool([]wafcore.Origin{{URL: "http://" + net.JoinHostPort(host, "80"), Weight: 1}}, "edge")
		if err := p.ValidateOrigins(); err == nil {
			t.Errorf("accepted prohibited origin %s", host)
		}
	}
}
func TestDialRebindingBlocked(t *testing.T) {
	p := NewOriginPool(nil, "edge")
	p.resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("169.254.169.254")}, nil }
	if _, err := p.dial(context.Background(), "tcp", "origin.test:80"); err == nil {
		t.Fatal("dial accepted rebound metadata IP")
	}
}

func TestOriginTransportDoesNotUseEnvironmentProxy(t *testing.T) {
	p := NewOriginPool(nil, "edge")
	transport, ok := p.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type %T", p.client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("environment proxy could bypass netguard origin resolution")
	}
}
func TestValidateOriginsResolvesDNSAndRejectsPrivateTargets(t *testing.T) {
	p := NewOriginPool([]wafcore.Origin{{URL: "https://rebinding.test", Weight: 1}}, "edge")
	p.SetResolver(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.2")}, nil })
	if err := p.ValidateOrigins(); err == nil {
		t.Fatal("configuration accepted hostname resolving to private IP")
	}
}
func TestDialUsesResolvedIP(t *testing.T) {
	p := NewOriginPool(nil, "edge")
	var dialed atomic.Bool
	p.resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.4")}, nil }
	p.dialIP = func(_ context.Context, _, address string) (net.Conn, error) {
		dialed.Store(true)
		if !strings.HasPrefix(address, "203.0.113.4:") {
			t.Fatalf("dial address %s", address)
		}
		return nil, errors.New("expected test dial failure")
	}
	_, _ = p.dial(context.Background(), "tcp", "origin.test:80")
	if !dialed.Load() {
		t.Fatal("resolved address not dialed")
	}
}
func TestWeightedOriginSelection(t *testing.T) {
	p := NewOriginPool([]wafcore.Origin{{URL: "http://203.0.113.1", Weight: 3}, {URL: "http://203.0.113.2", Weight: 1}}, "edge")
	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		origin, _, err := p.Select()
		if err != nil {
			t.Fatal(err)
		}
		counts[origin.URL]++
	}
	if counts["http://203.0.113.1"] != 30 || counts["http://203.0.113.2"] != 10 {
		t.Fatalf("weighted selection counts: %#v", counts)
	}
}

func TestWeightedOriginSelectionCounterNearInt64Maximum(t *testing.T) {
	p := NewOriginPool([]wafcore.Origin{
		{URL: "http://203.0.113.1", Weight: 1},
		{URL: "http://203.0.113.2", Weight: 1},
	}, "edge")
	p.next.Store(int64(^uint64(0) >> 1))

	origin, _, err := p.Select()
	if err != nil {
		t.Fatal(err)
	}
	if origin.URL != "http://203.0.113.2" {
		t.Fatalf("selected origin %q, want second origin after int64 wraparound", origin.URL)
	}
}
func TestCircuitBreakerFiveFailuresAndHalfOpen(t *testing.T) {
	p := NewOriginPool([]wafcore.Origin{{URL: "http://203.0.113.1", Weight: 1}}, "edge")
	now := time.Now()
	p.clock = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		p.RecordFailure(0)
	}
	n, until, half := p.CircuitState(0)
	if n != 5 || until.Sub(now) != 30*time.Second || half {
		t.Fatalf("state failures=%d until=%v half=%v", n, until, half)
	}
	if _, _, err := p.Select(); err == nil {
		t.Fatal("open breaker selected origin")
	}
	now = now.Add(30 * time.Second)
	_, _, half = p.CircuitState(0)
	if !half {
		t.Fatal("breaker did not enter half-open")
	}
	if _, _, err := p.Select(); err != nil {
		t.Fatalf("half-open should allow a probe: %v", err)
	}
	if _, _, err := p.Select(); err == nil {
		t.Fatal("half-open allowed more than one concurrent probe")
	}
	p.RecordSuccess(0)
	n, until, _ = p.CircuitState(0)
	if n != 0 || !until.IsZero() {
		t.Fatalf("success did not reset breaker: %d %v", n, until)
	}
}
func TestRetryOnlyGETAndHEADDialFailures(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			rt := retryTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}
			}), attempts: 2}
			_, _ = rt.RoundTrip(httptest.NewRequest(method, "http://example.test", nil))
			want := int32(1)
			if method == http.MethodGet || method == http.MethodHead {
				want = 2
			}
			if calls.Load() != want {
				t.Fatalf("calls=%d want=%d", calls.Load(), want)
			}
		})
	}
}

func TestRetryTransportNeverRetriesAfterRequestBodyWasSent(t *testing.T) {
	var calls atomic.Int32
	rt := retryTransport{base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("read request body: %v", err)
		}
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("synthetic late dial failure")}
	}), attempts: 2}
	request := httptest.NewRequest(http.MethodGet, "http://example.test", strings.NewReader("body"))
	_, _ = rt.RoundTrip(request)
	if calls.Load() != 1 {
		t.Fatalf("calls=%d, want no retry after request body was sent", calls.Load())
	}
}

func TestRetryTransportRetriesGetAndHeadOnlyForDialErrors(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			rt := retryTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("response header failure")
			}), attempts: 2}
			_, _ = rt.RoundTrip(httptest.NewRequest(method, "http://example.test", nil))
			if calls.Load() != 1 {
				t.Fatalf("calls=%d; non-dial error must not retry", calls.Load())
			}
		})
	}
}

func TestProxyErrorsCarryRequestIDAndDoNotReflectTransportDetails(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{
		{name: "bad gateway", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused: secret")}, code: http.StatusBadGateway},
		{name: "gateway timeout", err: &net.OpError{Op: "dial", Net: "tcp", Err: timeoutTestError{}}, code: http.StatusGatewayTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://site.test/", nil)
			ctx := reqctx.New(request, nil, "0123456789abcdef0123456789abcdef", net.ParseIP("192.0.2.4"))
			ctx.Site = &wafcore.Site{Origins: []wafcore.Origin{{URL: "http://203.0.113.8:80", Weight: 1}}}
			pool := NewOriginPool(ctx.Site.Origins, "edge")
			pool.resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.8")}, nil }
			pool.dialIP = func(context.Context, string, string) (net.Conn, error) { return nil, tc.err }
			rr := httptest.NewRecorder()
			pool.Serve(rr, ctx)
			if rr.Code != tc.code || rr.Header().Get("X-Request-ID") != ctx.RequestID {
				t.Fatalf("status=%d request_id=%q, want %d and %q", rr.Code, rr.Header().Get("X-Request-ID"), tc.code, ctx.RequestID)
			}
			if strings.Contains(rr.Body.String(), "connection refused") || strings.Contains(rr.Body.String(), "secret") {
				t.Fatalf("transport detail leaked to response: %q", rr.Body.String())
			}
		})
	}
}

type timeoutTestError struct{}

func (timeoutTestError) Error() string   { return "dial timeout secret" }
func (timeoutTestError) Timeout() bool   { return true }
func (timeoutTestError) Temporary() bool { return true }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLoopbackProxyHTTP1HTTP2SSEAndWebSocket(t *testing.T) {
	for _, proto := range []string{"http1", "http2", "sse", "websocket"} {
		t.Run(proto, func(t *testing.T) {
			var originURL string
			var origin *httptest.Server
			switch proto {
			case "http2":
				origin = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, r.Proto) }))
				origin.EnableHTTP2 = true
				origin.StartTLS()
			case "websocket":
				origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Upgrade") != "websocket" {
						http.Error(w, "no upgrade", 400)
						return
					}
					h := w.(http.Hijacker)
					c, rw, _ := h.Hijack()
					defer func() {
						if err := c.Close(); err != nil {
							t.Errorf("close websocket origin connection: %v", err)
						}
					}()
					_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
					_ = rw.Flush()
					line, _ := rw.ReadString('\n')
					_, _ = rw.WriteString(line)
					_ = rw.Flush()
				}))
			default:
				origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if proto == "sse" {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = fmt.Fprint(w, "data: one\n\n")
						w.(http.Flusher).Flush()
						time.Sleep(50 * time.Millisecond)
						_, _ = fmt.Fprint(w, "data: two\n\n")
						return
					}
					_, _ = fmt.Fprint(w, r.Proto)
				}))
			}
			defer origin.Close()
			originURL = origin.URL
			p := NewOriginPool([]wafcore.Origin{{URL: originURL, Weight: 1}}, "edge-test")
			originHost, originPort, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(originURL, "http://"), "https://"))
			p.resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.4")}, nil }
			p.dialIP = func(ctx context.Context, network, address string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(address)
				d := net.Dialer{}
				if originHost != "" {
					port = originPort
				}
				return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			}
			if proto == "http2" {
				tr := p.client.Transport.(*http.Transport)
				tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if proto == "websocket" {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
			}
			if proto == "websocket" {
				proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ctx := reqctx.New(r, nil, "0123456789abcdef0123456789abcdef", net.ParseIP("192.0.2.9"))
					ctx.Site = &wafcore.Site{Origins: []wafcore.Origin{{URL: originURL, Weight: 1}}}
					defer reqctx.Release(ctx)
					p.Serve(w, ctx)
				}))
				defer proxyServer.Close()
				proxyURL := strings.TrimPrefix(proxyServer.URL, "http://")
				conn, err := net.Dial("tcp", proxyURL)
				if err != nil {
					t.Fatal(err)
				}
				closeOnCleanup(t, conn)
				_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: site.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				br := bufio.NewReader(conn)
				line, err := br.ReadString('\n')
				if err != nil || !strings.Contains(line, "101") {
					t.Fatalf("upgrade response %q err=%v", line, err)
				}
				for {
					line, err = br.ReadString('\n')
					if err != nil {
						t.Fatal(err)
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(conn, "hello\n")
				echo, err := br.ReadString('\n')
				if err != nil || echo != "hello\n" {
					t.Fatalf("echo=%q err=%v", echo, err)
				}
				return
			}
			rw := httptest.NewRecorder()
			c := reqctx.New(req, nil, "0123456789abcdef0123456789abcdef", net.ParseIP("192.0.2.9"))
			c.Site = &wafcore.Site{Origins: []wafcore.Origin{{URL: originURL, Weight: 1}}}
			p.Serve(rw, c)
			if proto == "sse" {
				if !strings.Contains(rw.Body.String(), "data: two") {
					t.Fatalf("SSE body %q", rw.Body.String())
				}
				return
			}
			if proto == "http2" && !strings.Contains(rw.Body.String(), "HTTP/2") {
				t.Fatalf("origin protocol %q", rw.Body.String())
			}
			if proto == "http1" && !strings.Contains(rw.Body.String(), "HTTP/1.1") {
				t.Fatalf("origin protocol %q", rw.Body.String())
			}
		})
	}
}

func TestLoopViaRejected(t *testing.T) {
	p := NewOriginPool([]wafcore.Origin{{URL: "http://203.0.113.9"}}, "edge-a")
	req := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	req.Header.Set("Via", "1.1 edge-a")
	c := reqctx.New(req, nil, "id", net.ParseIP("192.0.2.2"))
	c.Site = &wafcore.Site{Origins: []wafcore.Origin{{URL: "http://203.0.113.9"}}}
	rr := httptest.NewRecorder()
	p.Serve(rr, c)
	if rr.Code != http.StatusLoopDetected {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestProxyErrorDoesNotLogOrReflectUnsafeRequestID(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	ctx := reqctx.New(request, nil, "attacker-id\r\nX-Forged: yes", net.ParseIP("192.0.2.4"))
	ctx.Site = &wafcore.Site{Origins: []wafcore.Origin{{URL: "http://203.0.113.8:80", Weight: 1}}}
	pool := NewOriginPool(ctx.Site.Origins, "edge")
	pool.resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.8")}, nil }
	pool.dialIP = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	rr := httptest.NewRecorder()
	pool.Serve(rr, ctx)
	if strings.Contains(logs.String(), "attacker-id") || strings.Contains(logs.String(), "X-Forged") {
		t.Fatalf("unsafe request ID entered log: %q", logs.String())
	}
	if strings.Contains(rr.Body.String(), "attacker-id") || strings.Contains(rr.Body.String(), "X-Forged") || rr.Header().Get("X-Request-ID") != "" {
		t.Fatalf("unsafe request ID reflected: headers=%v body=%q", rr.Header(), rr.Body.String())
	}
	if !strings.Contains(logs.String(), `request_id=""`) {
		t.Fatalf("unsafe request ID was not replaced in quoted log field: %q", logs.String())
	}
	if rr.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing safe error response headers: %v", rr.Header())
	}
}

func TestLoopbackSSEFlushesBeforeOriginCompletes(t *testing.T) {
	first := make(chan struct{})
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		close(first)
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
	}))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	_ = host
	p := NewOriginPool([]wafcore.Origin{{URL: "http://203.0.113.80:80", Weight: 1}}, "edge-sse")
	p.SetResolver(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.80")}, nil })
	p.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := reqctx.New(r, nil, "0123456789abcdef0123456789abcdef", net.ParseIP("192.0.2.1"))
		defer reqctx.Release(ctx)
		ctx.Site = &wafcore.Site{Origins: []wafcore.Origin{{URL: "http://203.0.113.80:80", Weight: 1}}}
		p.Serve(w, ctx)
	}))
	defer srv.Close()
	defer close(release)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	closeOnCleanup(t, resp.Body)
	reader := bufio.NewReader(resp.Body)
	line := make(chan string, 1)
	errs := make(chan error, 1)
	go func() { s, e := reader.ReadString('\n'); line <- s; errs <- e }()
	select {
	case got := <-line:
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		if got != "data: first\n" {
			t.Fatalf("first event line %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SSE first event was buffered until origin completed")
	}
}

func TestLoopbackProxyRewritesForwardingHeaders(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "xff=%s|xreal=%s|proto=%s|host=%s|id=%s|via=%s|forwarded=%s|fwdcustom=%s|hop=%s|connection=%s|keepalive=%s|proxyauth=%s|te=%s|originhost=%s", r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Request-ID"), r.Header.Get("Via"), r.Header.Get("Forwarded"), r.Header.Get("X-Forwarded-Custom"), r.Header.Get("X-Hop-Secret"), r.Header.Get("Connection"), r.Header.Get("Keep-Alive"), r.Header.Get("Proxy-Authorization"), r.Header.Get("TE"), r.Host)
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	target := "http://203.0.113.88:80"
	p := NewOriginPool([]wafcore.Origin{{URL: target, Weight: 1, HostHeader: "origin-header.test"}}, "edge-node")
	p.SetResolver(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.88")}, nil })
	p.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := reqctx.New(r, nil, "0123456789abcdef0123456789abcdef", net.ParseIP("192.0.2.9"))
		defer reqctx.Release(c)
		c.Site = &wafcore.Site{Origins: []wafcore.Origin{{URL: target, Weight: 1}}}
		p.Serve(w, c)
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Host = "original.test"
	req.Header.Set("X-Forwarded-For", "203.0.113.200")
	req.Header.Set("X-Real-IP", "203.0.113.201")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Custom", "forged")
	req.Header.Set("Forwarded", "for=203.0.113.200;host=evil.example;proto=https")
	req.Header.Set("Via", "1.1 client-proxy")
	req.Header.Set("Connection", "X-Hop-Secret")
	req.Header.Set("X-Hop-Secret", "must-not-reach-origin")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Proxy-Authorization", "Basic client-secret")
	req.Header.Set("TE", "trailers")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	closeOnCleanup(t, resp.Body)
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"xff=192.0.2.9", "xreal=", "proto=http", "host=original.test", "id=0123456789abcdef0123456789abcdef", "via=1.1 edge-node", "forwarded=", "fwdcustom=", "hop=", "connection=", "keepalive=", "proxyauth=", "te=", "originhost=origin-header.test"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("forwarded response %q missing %q", body, want)
		}
	}
}

func closeOnCleanup(t *testing.T, closer interface{ Close() error }) {
	t.Helper()
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Errorf("close test connection: %v", err)
		}
	})
}
