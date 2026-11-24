package edgecore

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/access"
	"github.com/example/wafplatform/edge/internal/bot"
	"github.com/example/wafplatform/edge/internal/pipeline"
	"github.com/example/wafplatform/edge/internal/proxy"
	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/edge/internal/telemetry"
	"github.com/example/wafplatform/pkg/wafcore"
	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

type panicPhase struct{}

func (panicPhase) Name() string                              { return "panic-test" }
func (panicPhase) Handle(*reqctx.RequestCtx) reqctx.Decision { panic("phase boom") }

type challengePhase struct{}

func (challengePhase) Name() string { return "rules" }
func (challengePhase) Handle(*reqctx.RequestCtx) reqctx.Decision {
	return reqctx.Decision{Action: reqctx.ActionChallenge, Phase: "rules", RuleID: "api-challenge"}
}

type rateLimitedPhase struct{}

func (rateLimitedPhase) Name() string { return "ratelimit" }
func (rateLimitedPhase) Handle(*reqctx.RequestCtx) reqctx.Decision {
	return reqctx.Decision{Action: reqctx.ActionRateLimited, Phase: "ratelimit", RuleID: "api-limit", RetryAfter: time.Second}
}
func siteSnapshot(status, failMode, origin string, version uint64) *wafcore.Snapshot {
	return &wafcore.Snapshot{SchemaVersion: 1, Version: version, GeneratedAt: time.Now(), Global: wafcore.GlobalConfig{ManagedRuleset: "test"}, Sites: []wafcore.Site{{ID: "site", TenantID: "tenant", Status: status, Plan: "pro", Domains: []string{"site.test"}, Origins: []wafcore.Origin{{URL: origin, Weight: 1}}, FailMode: failMode}}}
}

func TestStartupSelfTestControlsReadiness(t *testing.T) {
	e := New(siteSnapshot("active", "closed", "http://203.0.113.77:80", 1), "edge-test")
	defer e.Close()
	e.SetReady(false)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://edge/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready before self-test status=%d", response.Code)
	}
	if err := e.SelfTest(); err != nil {
		t.Fatalf("pipeline self-test: %v", err)
	}
	e.SetReady(true)
	response = httptest.NewRecorder()
	e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://edge/readyz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("ready after self-test status=%d", response.Code)
	}
}

func TestBotChallengeVerifyEndpointRequiresEntitlementAndRejectsReplay(t *testing.T) {
	snap := siteSnapshot("active", "closed", "http://127.0.0.1:8080", 1)
	snap.Sites[0].Bot = wafcore.BotConfig{Mode: "challenge", Threshold: 30, ChallengeDifficulty: 8}
	snap.Sites[0].Entitlements.BotJSChallenge = true
	snap.Sites[0].Secrets.ChallengeHMACKeyID = "challenge-v1"
	e := New(snap, "edge-test")
	defer e.Close()
	key := []byte(strings.Repeat("k", 32))
	e.SetBotChallengeKeys(bot.StaticKeyRing{Active: "challenge-v1", Keys: map[string][]byte{"challenge-v1": key}})

	challengeReq := httptest.NewRequest(http.MethodGet, "http://site.test/private", nil)
	challengeReq.Host, challengeReq.RemoteAddr = "site.test", "198.51.100.6:12345"
	challengeReq.Header.Set("User-Agent", "curl/8.0")
	challengeReq.Header.Set("Accept", "text/html")
	challengeResp := httptest.NewRecorder()
	e.ServeHTTP(challengeResp, challengeReq)
	if challengeResp.Code != http.StatusForbidden || !strings.Contains(challengeResp.Body.String(), "/__waf/verify") {
		t.Fatalf("challenge response status=%d body=%q", challengeResp.Code, challengeResp.Body.String())
	}

	ticket, err := e.botManager.Load().IssueForKey("site", "challenge-v1", "curl/8.0", net.ParseIP("198.51.100.6"), 8, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	nonce := bot.FindNonce(ticket, 8)
	body := fmt.Sprintf(`{"token":%q,"nonce":%q}`, ticket, nonce)
	verify := httptest.NewRequest(http.MethodPost, "http://site.test/__waf/verify", strings.NewReader(body))
	verify.Host, verify.RemoteAddr = "site.test", "198.51.100.6:12345"
	verify.Header.Set("User-Agent", "curl/8.0")
	response := httptest.NewRecorder()
	e.ServeHTTP(response, verify)
	if response.Code != http.StatusNoContent || len(response.Result().Cookies()) != 1 || !response.Result().Cookies()[0].Secure {
		t.Fatalf("verification response=%d cookies=%v body=%q", response.Code, response.Result().Cookies(), response.Body.String())
	}
	replay := httptest.NewRecorder()
	replayedRequest := httptest.NewRequest(http.MethodPost, "http://site.test/__waf/verify", strings.NewReader(body))
	replayedRequest.Host, replayedRequest.RemoteAddr = "site.test", "198.51.100.6:12345"
	replayedRequest.Header.Set("User-Agent", "curl/8.0")
	e.ServeHTTP(replay, replayedRequest)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replayed proof status=%d want 403", replay.Code)
	}
	verifiedRequest := httptest.NewRequest(http.MethodGet, "http://site.test/private", nil)
	verifiedRequest.Host, verifiedRequest.RemoteAddr = "site.test", "198.51.100.6:12345"
	verifiedRequest.Header.Set("User-Agent", "curl/8.0")
	verifiedRequest.AddCookie(response.Result().Cookies()[0])
	verifiedResponse := httptest.NewRecorder()
	e.ServeHTTP(verifiedResponse, verifiedRequest)
	if verifiedResponse.Code == http.StatusForbidden && strings.Contains(verifiedResponse.Body.String(), "Checking your browser") {
		t.Fatal("valid verification cookie did not bypass challenge")
	}

	snap.Sites[0].Entitlements.BotJSChallenge = false
	if err := e.Apply(snap); err != nil {
		t.Fatal(err)
	}
	freeVerify := httptest.NewRecorder()
	freeRequest := httptest.NewRequest(http.MethodPost, "http://site.test/__waf/verify", strings.NewReader(body))
	freeRequest.Host, freeRequest.RemoteAddr = "site.test", "198.51.100.6:12345"
	e.ServeHTTP(freeVerify, freeRequest)
	if freeVerify.Code != http.StatusNotFound {
		t.Fatalf("unentitled verification status=%d want 404", freeVerify.Code)
	}
}

func TestBotChallengeUsesJSONForAPIClients(t *testing.T) {
	snap := siteSnapshot("active", "closed", "http://127.0.0.1:8080", 1)
	snap.Sites[0].Bot = wafcore.BotConfig{Mode: "challenge", Threshold: 1, ChallengeDifficulty: 8}
	snap.Sites[0].Entitlements.BotJSChallenge = true
	snap.Sites[0].Secrets.ChallengeHMACKeyID = "challenge-v1"
	e := New(snap, "edge-api-challenge")
	defer e.Close()
	e.SetBotChallengeKeys(bot.StaticKeyRing{Active: "challenge-v1", Keys: map[string][]byte{"challenge-v1": []byte(strings.Repeat("k", 32))}})
	for name, req := range map[string]*http.Request{
		"post-json": httptest.NewRequest(http.MethodPost, "http://site.test/api", strings.NewReader(`{"x":1}`)),
		"get-xhr": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "http://site.test/api", nil)
			r.Header.Set("Accept", "text/html")
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
			return r
		}(),
		"get-no-html": httptest.NewRequest(http.MethodGet, "http://site.test/api", nil),
	} {
		req.Host, req.RemoteAddr = "site.test", "198.51.100.6:12345"
		req.Header.Set("User-Agent", "curl/8.0")
		if name == "post-json" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
		}
		rr := httptest.NewRecorder()
		e.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden || rr.Header().Get("Content-Type") != "application/json; charset=utf-8" || rr.Header().Get("X-Request-ID") == "" || !strings.Contains(rr.Body.String(), `"error":"challenge_required"`) || strings.Contains(rr.Body.String(), "<html") {
			t.Errorf("%s challenge response status=%d headers=%v body=%q", name, rr.Code, rr.Header(), rr.Body.String())
		}
	}
}

func TestRuleChallengeUsesJSONForAPIClients(t *testing.T) {
	e := New(siteSnapshot("active", "closed", "http://127.0.0.1:8080", 1), "edge-rule-api-challenge")
	defer e.Close()
	e.SetPipeline(pipeline.New(e.metrics, challengePhase{}))
	r := httptest.NewRequest(http.MethodPost, "http://site.test/api", strings.NewReader(`{"x":1}`))
	r.Host, r.RemoteAddr = "site.test", "198.51.100.7:12345"
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, r)
	if rr.Code != http.StatusForbidden || rr.Header().Get("Content-Type") != "application/json; charset=utf-8" || rr.Header().Get("X-Request-ID") == "" || !strings.Contains(rr.Body.String(), `"error":"challenge_required"`) {
		t.Fatalf("API rule challenge status=%d headers=%v body=%q", rr.Code, rr.Header(), rr.Body.String())
	}
}

func TestAPIRateLimitIsMachineReadable(t *testing.T) {
	e := New(siteSnapshot("active", "closed", "http://127.0.0.1:8080", 1), "edge-api-rate-limit")
	defer e.Close()
	e.SetPipeline(pipeline.New(e.metrics, rateLimitedPhase{}))
	r := httptest.NewRequest(http.MethodPost, "http://site.test/api", strings.NewReader(`{"x":1}`))
	r.Host, r.RemoteAddr = "site.test", "198.51.100.9:12345"
	r.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, r)
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Content-Type") != "application/json; charset=utf-8" || rr.Header().Get("Retry-After") != "1" || !strings.Contains(rr.Body.String(), `"error":"rate_limited"`) || !strings.Contains(rr.Body.String(), `"request_id":"`+rr.Header().Get("X-Request-ID")+`"`) {
		t.Fatalf("API rate-limit response status=%d headers=%v body=%q", rr.Code, rr.Header(), rr.Body.String())
	}
}
func localOrigin(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	_ = host
	return srv, port
}
func installLocalPool(e *Edge, port string) {
	e.poolFactory = func(origins []wafcore.Origin, via string) *proxy.OriginPool {
		p := proxy.NewOriginPool(origins, via)
		p.SetResolver(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.77")}, nil })
		p.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		})
		return p
	}
}

func TestLoopbackPanicRespectsFailMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int
		body string
	}{{"open", 200, "origin ok"}, {"closed", 503, "internal edge error"}} {
		t.Run(tc.mode, func(t *testing.T) {
			origin, port := localOrigin(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "origin ok") })
			defer origin.Close()
			snap := siteSnapshot("active", tc.mode, "http://203.0.113.77:80", 1)
			e := New(snap, "edge-test")
			installLocalPool(e, port)
			e.SetPipeline(pipeline.New(e.metrics, panicPhase{}))
			r := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
			r.RemoteAddr = "192.0.2.9:1234"
			rr := httptest.NewRecorder()
			e.ServeHTTP(rr, r)
			if rr.Code != tc.want || !strings.Contains(rr.Body.String(), tc.body) {
				t.Fatalf("response=(%d,%q), want status %d containing %q", rr.Code, rr.Body.String(), tc.want, tc.body)
			}
		})
	}
}

func TestLoopbackReloadDoesNotInterruptInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	origin, port := localOrigin(t, func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = fmt.Fprint(w, "completed")
	})
	defer origin.Close()
	e := New(siteSnapshot("active", "closed", "http://203.0.113.77:80", 1), "edge-test")
	installLocalPool(e, port)
	srv := httptest.NewServer(e)
	defer srv.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	result := make(chan error, 1)
	go func() {
		defer wg.Done()
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			result <- err
			return
		}
		req.Host = "site.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			result <- err
			return
		}
		closeOnCleanup(t, resp.Body)
		buf := new(strings.Builder)
		_, err = io.Copy(buf, resp.Body)
		if err == nil && !strings.Contains(buf.String(), "completed") {
			err = fmt.Errorf("response body %q", buf.String())
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("origin request did not start")
	}
	if err := e.Apply(siteSnapshot("active", "closed", "http://203.0.113.77:80", 2)); err != nil {
		t.Fatal(err)
	}
	close(release)
	wg.Wait()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if e.runtime.Load().snapshot.Version != 2 {
		t.Fatal("new snapshot not applied")
	}
}

func TestLoopbackSampleSnapshotServesThroughFakeOrigin(t *testing.T) {
	data, err := os.ReadFile("../../../test/fixtures/snapshot.sample.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot wafcore.Snapshot
	if err = yaml.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	origin, port := localOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "origin=%s proto=%s", r.Host, r.Proto)
	})
	defer origin.Close()
	snapshot.Sites[0].Origins = []wafcore.Origin{{URL: "http://203.0.113.77:80", Weight: 1, HostHeader: "example.com", TLSVerify: true}}
	e := New(&snapshot, "edge-test")
	installLocalPool(e, port)
	srv := httptest.NewServer(e)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/sample", nil)
	req.Host = "www.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	closeOnCleanup(t, resp.Body)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "proto=HTTP/1.1") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestLoopbackInspectedChunkedBodyTrailerAndExpectContinueReachOrigin(t *testing.T) {
	origin, port := localOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "origin body read failed", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, "body=%s trailer=%s", body, r.Trailer.Get("X-Checksum"))
	})
	defer origin.Close()
	const target = "http://203.0.113.77:80"
	pool := proxy.NewOriginPool([]wafcore.Origin{{URL: target, Weight: 1}}, "edge-test")
	pool.SetResolver(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.77")}, nil })
	pool.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := reqctx.New(r, nil, "0123456789abcdef0123456789abcdef", net.ParseIP("192.0.2.8"))
		defer reqctx.Release(ctx)
		ctx.Site = &wafcore.Site{Origins: []wafcore.Origin{{URL: target, Weight: 1}}}
		_ = ctx.BodyText()
		pool.Serve(w, ctx)
	}))
	defer srv.Close()

	const body = "ordinary chunked data"
	request, err := http.NewRequest(http.MethodPost, srv.URL+"/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "site.test"
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.Trailer = http.Header{"X-Checksum": []string{"checksum-value"}}
	request.Header.Set("Expect", "100-continue")
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request with Expect: 100-continue failed: %v", err)
	}
	closeOnCleanup(t, resp.Body)
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(got) != "body="+body+" trailer=checksum-value" {
		t.Fatalf("status=%d origin response=%q", resp.StatusCode, got)
	}
}

func TestLoopbackBodyReadDeadlineSlowAndHungClients(t *testing.T) {
	for _, tc := range []struct {
		name string
		sent string
		wait time.Duration
	}{
		{name: "slow_body", sent: "x", wait: 250 * time.Millisecond},
		{name: "hung_body", sent: "", wait: 250 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := siteSnapshot("active", "closed", "http://127.0.0.1:8080", 1)
			snap.Sites[0].WAF = wafcore.WAFConfig{Mode: "block", Sensitivity: "high", BodyLimitKB: 8, BodyReadTimeoutMS: 80, BudgetMS: 2000}
			e := New(snap, "edge-test")
			defer e.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: e}
			go func() { _ = srv.Serve(listener) }()
			defer func() { _ = srv.Close() }()
			conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = fmt.Fprintf(conn, "POST /submit HTTP/1.1\r\nHost: site.test\r\nContent-Type: text/plain\r\nContent-Length: 32\r\nConnection: close\r\n\r\n%s", tc.sent)
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Fatalf("deadline failed to release body read (elapsed %s): %v", time.Since(started), err)
			}
			if !strings.Contains(line, "403") {
				t.Fatalf("fail-closed body read timeout status=%q", line)
			}
			if time.Since(started) > time.Second {
				t.Fatalf("listener held by body read for %s", time.Since(started))
			}
		})
	}
}

func TestLoopbackTruncatedBodyReleasesListener(t *testing.T) {
	snap := siteSnapshot("active", "closed", "http://127.0.0.1:8080", 1)
	snap.Sites[0].WAF = wafcore.WAFConfig{Mode: "block", Sensitivity: "high", BodyLimitKB: 8, BodyReadTimeoutMS: 500, BudgetMS: 2000}
	e := New(snap, "edge-test")
	defer e.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: e}
	go func() { _ = srv.Serve(listener) }()
	defer func() { _ = srv.Close() }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tcp := conn.(*net.TCPConn)
	defer func() { _ = tcp.Close() }()
	_ = tcp.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = fmt.Fprint(tcp, "POST /submit HTTP/1.1\r\nHost: site.test\r\nContent-Type: text/plain\r\nContent-Length: 32\r\nConnection: close\r\n\r\nabc")
	if err != nil {
		t.Fatal(err)
	}
	if err = tcp.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(tcp).ReadString('\n')
	if err != nil {
		t.Fatalf("truncated body did not release handler: %v", err)
	}
	if !strings.Contains(line, "403") {
		t.Fatalf("truncated body did not use paid fail-closed policy: %q", line)
	}
}

func TestHostAndSiteStatusResponses(t *testing.T) {
	snap := siteSnapshot("suspended", "closed", "http://203.0.113.1", 1)
	snap.Sites = append(snap.Sites, wafcore.Site{ID: "pending", TenantID: "t", Status: "pending", Plan: "p", Domains: []string{"pending.test"}, FailMode: "closed"})
	e := New(snap, "edge")
	for _, tc := range []struct {
		host string
		code int
	}{{"unknown.test", 421}, {"site.test", 402}, {"pending.test", 403}} {
		r := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/", nil)
		r.RemoteAddr = "192.0.2.1:10"
		rr := httptest.NewRecorder()
		e.ServeHTTP(rr, r)
		if rr.Code != tc.code {
			t.Errorf("host %s got %d want %d", tc.host, rr.Code, tc.code)
		}
	}
}

func TestCanonicalHTTPHostUsesRouterAndRejectsMalformedHosts(t *testing.T) {
	snapshot := siteSnapshot("active", "closed", "http://203.0.113.77:80", 1)
	snapshot.Sites[0].Domains = []string{"*.example.test"}
	e := New(snapshot, "edge")
	for _, tc := range []struct {
		host string
		want string
		ok   bool
	}{{"API.EXAMPLE.TEST.:80", "api.example.test", true}, {"evil.com", "", false}, {"api.example.test:bad", "", false}, {"api.example.test:80:evil", "", false}, {"user@api.example.test", "", false}, {"api.example.test/evil", "", false}} {
		got, ok := e.CanonicalHTTPHost(tc.host)
		if ok != tc.ok || got != tc.want {
			t.Errorf("CanonicalHTTPHost(%q)=(%q,%v) want (%q,%v)", tc.host, got, ok, tc.want, tc.ok)
		}
	}
}

func TestRequestIDIsAlwaysHex(t *testing.T) {
	id := requestID()
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 {
		t.Fatalf("request ID=%q err=%v decoded bytes=%d", id, err, len(decoded))
	}
}

func TestLoopbackEdgeGeneratesRequestIDAndIgnoresClientHeader(t *testing.T) {
	origin, port := localOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Request-ID", r.Header.Get("X-Request-ID"))
		_, _ = io.WriteString(w, "origin response")
	})
	defer origin.Close()
	e := New(siteSnapshot("active", "closed", "http://203.0.113.77:80", 1), "edge-test")
	installLocalPool(e, port)
	r := httptest.NewRequest(http.MethodGet, "http://site.test/path", nil)
	r.RemoteAddr = "192.0.2.9:1234"
	r.Header.Set("X-Request-ID", "client-id\r\nX-Injected: yes")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, r)
	got := rr.Header().Get("X-Origin-Request-ID")
	decoded, err := hex.DecodeString(got)
	if rr.Code != http.StatusOK || err != nil || len(decoded) != 16 || strings.Contains(rr.Body.String(), "client-id") {
		t.Fatalf("status=%d request id=%q body=%q", rr.Code, got, rr.Body.String())
	}
}

func TestLoopbackRateLimitReturns429RetryAfterAndRuleID(t *testing.T) {
	snapshot := siteSnapshot("active", "closed", "http://127.0.0.1:1", 1)
	snapshot.Sites[0].RateLimits = []wafcore.RateLimit{{
		ID: "rl_login", Match: "http.path == '/login' and http.method == 'POST'", Key: "site", Limit: 1, WindowS: 60, Action: "throttle",
	}}
	e := New(snapshot, "edge-test")
	srv := httptest.NewServer(e)
	defer srv.Close()

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/login", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "site.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		closeOnCleanup(t, resp.Body)
		if i == 0 && resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("initial request status=%d, want origin validation 502", resp.StatusCode)
		}
		if i == 1 {
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("limited request status=%d, want 429", resp.StatusCode)
			}
			if resp.Header.Get("Retry-After") != "60" {
				t.Fatalf("Retry-After=%q, want 60", resp.Header.Get("Retry-After"))
			}
		}
	}
}

func TestUntrustedForwardedForDoesNotOverrideRemoteAddress(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	r.RemoteAddr = "198.51.100.24:43122"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	got := remoteIP(r.RemoteAddr)
	if want := net.ParseIP("198.51.100.24"); !got.Equal(want) {
		t.Fatalf("client IP=%v, want remote address %v despite spoofed X-Forwarded-For", got, want)
	}
}

func TestUntrustedForwardingHeadersCannotBypassIPPolicies(t *testing.T) {
	t.Run("allow-list cannot override blocked peer", func(t *testing.T) {
		snapshot := siteSnapshot("active", "closed", "http://127.0.0.1:1", 1)
		snapshot.Sites[0].Access = wafcore.AccessConfig{AllowIPs: []string{"203.0.113.0/24"}, BlockIPs: []string{"198.51.100.0/24"}}
		e := New(snapshot, "edge-test")
		req := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
		req.RemoteAddr = "198.51.100.24:43122"
		req.Header.Set("X-Forwarded-For", "203.0.113.99, 192.0.2.99")
		req.Header.Set("Forwarded", "for=203.0.113.99")
		rr := httptest.NewRecorder()
		e.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("spoofed XFF bypassed peer block: status=%d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("geo policy uses peer address", func(t *testing.T) {
		snapshot := siteSnapshot("active", "closed", "http://127.0.0.1:1", 1)
		snapshot.Sites[0].Access.BlockCountries = []string{"US"}
		e := New(snapshot, "edge-test")
		e.SetGeoResolver(access.FakeGeoResolver{"198.51.100.24": {Country: "VN"}, "203.0.113.99": {Country: "US"}})
		req := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
		req.RemoteAddr = "198.51.100.24:43122"
		req.Header.Set("X-Forwarded-For", "203.0.113.99")
		rr := httptest.NewRecorder()
		e.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("geo policy did not use transport peer (expected allow-to-origin 502), status=%d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("rate limit key uses peer across changing XFF", func(t *testing.T) {
		snapshot := siteSnapshot("active", "closed", "http://127.0.0.1:1", 1)
		snapshot.Sites[0].RateLimits = []wafcore.RateLimit{{ID: "ip-limit", Match: "http.path starts_with '/'", Key: "ip", Limit: 1, WindowS: 60, Action: "throttle"}}
		e := New(snapshot, "edge-test")
		srv := httptest.NewServer(e)
		defer srv.Close()
		for i, spoof := range []string{"203.0.113.1", "203.0.113.2"} {
			req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "site.test"
			req.Header.Set("X-Forwarded-For", spoof)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			closeOnCleanup(t, resp.Body)
			if i == 0 && resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("first request status=%d, want origin attempt", resp.StatusCode)
			}
			if i == 1 && resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("changing spoofed XFF bypassed same-peer rate limit: status=%d", resp.StatusCode)
			}
		}
	})
}

type hijackWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}
func TestPanicAfterHeadersClosesConnectionAndCountsMetric(t *testing.T) {
	e := New(siteSnapshot("active", "closed", "http://203.0.113.1", 1), "edge")
	serverConn, clientConn := net.Pipe()
	closeOnCleanup(t, clientConn)
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	tw := &trackingWriter{ResponseWriter: &hijackWriter{ResponseRecorder: rec, conn: serverConn}, wrote: true}
	ctx := reqctx.New(httptest.NewRequest(http.MethodGet, "http://site.test/", nil), e.runtime.Load().snapshot, "request-1", nil)
	ctx.Site = &e.runtime.Load().snapshot.Sites[0]
	e.recoverPanic(tw, ctx, "boom")
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection was not closed after committed headers")
	}
	metrics := httptest.NewRecorder()
	e.Metrics().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "edge_blocked_total{group=\"panic\"} 1") {
		t.Fatalf("panic metric missing: %s", metrics.Body.String())
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

type edgeTelemetrySink struct{ batches chan []byte }

func (s *edgeTelemetrySink) Publish(_ context.Context, batch []byte) error {
	s.batches <- append([]byte(nil), batch...)
	return nil
}

func TestRequestTelemetryUsesWafcoreSchemaAndOmitsSecrets(t *testing.T) {
	sink := &edgeTelemetrySink{batches: make(chan []byte, 4)}
	shipper, err := telemetry.NewShipper(sink, telemetry.ShipperConfig{QueueSize: 4, BatchSize: 1, FlushInterval: time.Hour, PlanSampleRate: map[string]float64{"free": 0}, IPMaskV4Bits: 24, IPMaskV6Bits: 56})
	if err != nil {
		t.Fatal(err)
	}
	e := New(siteSnapshot("active", "closed", "http://203.0.113.1", 1), "edge")
	e.SetLogShipper(shipper)
	e.SetTelemetryIdentity("edge-a", "region-b")
	r := httptest.NewRequest(http.MethodPost, "http://site.test/login?password=query-secret", nil)
	r.Header.Set("Authorization", "Bearer header-secret")
	r.Header.Set("Cookie", "session=cookie-secret")
	c := reqctx.New(r, e.runtime.Load().snapshot, "request-id", net.ParseIP("203.0.113.19"))
	c.Site = &e.runtime.Load().snapshot.Sites[0]
	c.SetDecision(reqctx.Decision{Action: reqctx.ActionBlock, Phase: "waf", RuleID: "sqli", Score: 5, Tags: []string{"security"}})
	tw := &trackingWriter{ResponseWriter: httptest.NewRecorder()}
	tw.WriteHeader(http.StatusForbidden)
	_, _ = tw.Write([]byte("blocked"))
	e.recordRequest(c, tw, time.Now().Add(-time.Millisecond))
	reqctx.Release(c)
	shipper.Close()
	e.Close()
	compressed := <-sink.batches
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := decoder.DecodeAll(compressed, nil)
	decoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	var batch telemetry.CompressedBatch
	if err = json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("events=%d", len(batch.Events))
	}
	event := batch.Events[0]
	if err = event.Validate(); err != nil {
		t.Fatal(err)
	}
	if event.EdgeID != "edge-a" || event.Region != "region-b" || event.Action != "block" || event.RuleID != "sqli" || event.ClientIP != "203.0.113.0" || event.BytesOut != 7 {
		t.Fatalf("event=%+v", event)
	}
	encoded := string(raw)
	for _, secret := range []string{"header-secret", "cookie-secret", "query-secret"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("sensitive request data was logged: %s", secret)
		}
	}
}
