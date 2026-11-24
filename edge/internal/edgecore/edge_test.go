package edgecore

import (
	"bufio"
	"context"
	"encoding/hex"
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

	"github.com/example/wafplatform/edge/internal/bot"
	"github.com/example/wafplatform/edge/internal/pipeline"
	"github.com/example/wafplatform/edge/internal/proxy"
	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
	"gopkg.in/yaml.v3"
)

type panicPhase struct{}

func (panicPhase) Name() string                              { return "panic-test" }
func (panicPhase) Handle(*reqctx.RequestCtx) reqctx.Decision { panic("phase boom") }
func siteSnapshot(status, failMode, origin string, version uint64) *wafcore.Snapshot {
	return &wafcore.Snapshot{SchemaVersion: 1, Version: version, GeneratedAt: time.Now(), Global: wafcore.GlobalConfig{ManagedRuleset: "test"}, Sites: []wafcore.Site{{ID: "site", TenantID: "tenant", Status: status, Plan: "pro", Domains: []string{"site.test"}, Origins: []wafcore.Origin{{URL: origin, Weight: 1}}, FailMode: failMode}}}
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
	if !strings.Contains(metrics.Body.String(), "edge_blocked_total{action=\"panic\"} 1") {
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
