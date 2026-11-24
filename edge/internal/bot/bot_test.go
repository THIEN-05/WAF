package bot

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

func testManager() *ChallengeManager {
	return NewChallengeManager(StaticKeyRing{Active: "k2", Keys: map[string][]byte{"k1": []byte(strings.Repeat("a", 32)), "k2": []byte(strings.Repeat("b", 32))}})
}
func TestChallengeCookieBindingExpiryRotationAndReplay(t *testing.T) {
	m := testManager()
	now := time.Now()
	ip := net.ParseIP("198.51.100.8")
	ticket, err := m.Issue("site", "Mozilla/5.0", ip, 8, now)
	if err != nil {
		t.Fatal(err)
	}
	nonce := FindNonce(ticket, 8)
	cookie, err := m.Verify(ticket, nonce, "site", "Mozilla/5.0", ip, now)
	if err != nil {
		t.Fatal(err)
	}
	if !m.ValidCookie(cookie, "site", "Mozilla/5.0", ip, now.Add(time.Minute)) {
		t.Fatal("valid cookie rejected")
	}
	for name, args := range map[string]struct {
		site, ua string
		ip       net.IP
		at       time.Time
	}{"fake": {"site", "Mozilla/5.0", ip, now}, "wrong-site": {"else", "Mozilla/5.0", ip, now}, "wrong-UA": {"site", "other", ip, now}, "wrong-/24": {"site", "Mozilla/5.0", net.ParseIP("198.51.101.8"), now}, "expired": {"site", "Mozilla/5.0", ip, now.Add(31 * time.Minute)}} {
		value := cookie
		if name == "fake" {
			value += "x"
		}
		if m.ValidCookie(value, args.site, args.ua, args.ip, args.at) {
			t.Errorf("%s cookie accepted", name)
		}
	}
	if _, err = m.Verify(ticket, nonce, "site", "Mozilla/5.0", ip, now); err == nil {
		t.Fatal("challenge proof replay accepted")
	}
	bad, err := m.Issue("site", "Mozilla/5.0", ip, 8, now)
	if err != nil {
		t.Fatal(err)
	}
	badNonce := "bad-proof"
	for validPoW(bad, badNonce, 8) {
		badNonce += "x"
	}
	if _, err = m.Verify(bad, badNonce, "site", "Mozilla/5.0", ip, now); err == nil {
		t.Fatal("bad proof accepted")
	}
	// Cookies signed by a retained old key stay valid after active-key rotation.
	old := NewChallengeManager(StaticKeyRing{Active: "k1", Keys: map[string][]byte{"k1": []byte(strings.Repeat("a", 32))}})
	oldTicket, _ := old.Issue("site", "Mozilla/5.0", ip, 1, now)
	oldCookie, err := old.Verify(oldTicket, FindNonce(oldTicket, 1), "site", "Mozilla/5.0", ip, now)
	if err != nil {
		t.Fatal(err)
	}
	rotated := NewChallengeManager(StaticKeyRing{Active: "k2", Keys: map[string][]byte{"k1": []byte(strings.Repeat("a", 32)), "k2": []byte(strings.Repeat("b", 32))}})
	if !rotated.ValidCookie(oldCookie, "site", "Mozilla/5.0", ip, now) {
		t.Fatal("cookie signed by retained old key rejected")
	}
}
func TestChallengeVerifyHandlerRejectsBadProofAndSetsCookie(t *testing.T) {
	m := testManager()
	ip := net.ParseIP("192.0.2.3")
	ticket, _ := m.Issue("s", "ua", ip, 4, time.Now())
	badNonce := "bad"
	for validPoW(ticket, badNonce, 4) {
		badNonce += "x"
	}
	for _, nonce := range []string{badNonce, FindNonce(ticket, 4)} {
		body := `{"token":"` + ticket + `","nonce":"` + nonce + `"}`
		r := httptest.NewRequest(http.MethodPost, "/__waf/verify", strings.NewReader(body))
		r = r.WithContext(context.Background())
		r.RemoteAddr = "192.0.2.3:4"
		rr := httptest.NewRecorder()
		m.ServeVerify(rr, r, "s", ip, "ua")
		if nonce == badNonce && rr.Code != http.StatusForbidden {
			t.Fatalf("bad proof status %d", rr.Code)
		}
		if nonce != badNonce && (rr.Code != http.StatusNoContent || len(rr.Result().Cookies()) != 1) {
			t.Fatalf("valid proof response=%d cookies=%v", rr.Code, rr.Result().Cookies())
		}
		if nonce != badNonce {
			cookie := rr.Result().Cookies()[0]
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
				t.Fatalf("verification cookie attributes unsafe: %+v", cookie)
			}
			if rr.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("verification cache policy=%q", rr.Header().Get("Cache-Control"))
			}
		}
	}
}

func TestChallengeVerifyRateLimitMethodBodyAndRequestID(t *testing.T) {
	m := testManager()
	m.ConfigureVerifyLimits(1, time.Minute, 10, 32, 100*time.Millisecond)
	ip := net.ParseIP("192.0.2.80")
	for i, method := range []string{http.MethodGet, http.MethodPost, http.MethodPost} {
		body := strings.NewReader(strings.Repeat("x", 64))
		if i == 1 {
			body = strings.NewReader(`{"token":"` + strings.Repeat("x", 64) + `","nonce":"n"}`)
		}
		r := httptest.NewRequest(method, "/__waf/verify", body)
		w := httptest.NewRecorder()
		m.ServeVerifyRequestID(w, r, "site", "", ip, "ua", "request-123")
		want := http.StatusMethodNotAllowed
		if i == 1 {
			want = http.StatusBadRequest
		}
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want || w.Header().Get("Content-Type") != "application/json; charset=utf-8" || !strings.Contains(w.Body.String(), `"request_id":"request-123"`) {
			t.Fatalf("attempt %d got status=%d headers=%v body=%q want=%d", i, w.Code, w.Header(), w.Body.String(), want)
		}
	}
}

func TestLoopbackChallengeVerifyBodyReadDeadline(t *testing.T) {
	m := testManager()
	m.ConfigureVerifyLimits(10, time.Minute, 10, 8<<10, 100*time.Millisecond)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.ServeVerifyRequestID(w, r, "site", "", net.ParseIP("192.0.2.90"), "ua", "slow-verify")
	}))
	defer server.Close()
	reader, writer := io.Pipe()
	defer func() {
		if closeErr := writer.Close(); closeErr != nil && !errors.Is(closeErr, io.ErrClosedPipe) {
			t.Errorf("close slow verify writer: %v", closeErr)
		}
	}()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/__waf/verify", reader)
	if err != nil {
		t.Fatal(err)
	}
	req.TransferEncoding = []string{"chunked"}
	response := make(chan struct {
		res *http.Response
		err error
	}, 1)
	writerDone := make(chan struct{})
	go func() {
		res, err := http.DefaultClient.Do(req)
		response <- struct {
			res *http.Response
			err error
		}{res, err}
	}()
	go func() {
		defer close(writerDone)
		_, _ = io.WriteString(writer, `{"token":"`)
		time.Sleep(250 * time.Millisecond)
		_, _ = io.WriteString(writer, `slow","nonce":"x"}`)
		if closeErr := writer.Close(); closeErr != nil && !errors.Is(closeErr, io.ErrClosedPipe) {
			t.Errorf("close slow verify writer: %v", closeErr)
		}
	}()
	select {
	case result := <-response:
		if result.err != nil {
			t.Fatalf("request failed before timeout response: %v", result.err)
		}
		defer func() {
			if closeErr := result.res.Body.Close(); closeErr != nil {
				t.Errorf("close slow verify response: %v", closeErr)
			}
		}()
		body, _ := io.ReadAll(result.res.Body)
		if result.res.StatusCode != http.StatusRequestTimeout || !strings.Contains(string(body), `"error":"body_timeout"`) || !strings.Contains(string(body), `"request_id":"slow-verify"`) {
			t.Fatalf("slow verify response status=%d body=%q", result.res.StatusCode, body)
		}
	case <-time.After(time.Second):
		t.Fatal("challenge verification handler remained blocked on a slow body")
	}
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("slow body writer goroutine was not released")
	}
}
func TestChallengePageUsesScopedNonceCSP(t *testing.T) {
	m := testManager()
	ticket, err := m.Issue("site", "ua", net.ParseIP("192.0.2.1"), 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	ChallengePage(rr, ticket)
	body := rr.Body.String()
	policy := rr.Header().Get("Content-Security-Policy")
	if rr.Code != http.StatusForbidden || !strings.Contains(policy, "script-src 'nonce-") || !strings.Contains(body, "<script nonce=") || !strings.Contains(body, "/__waf/verify") {
		t.Fatalf("challenge response status=%d csp=%q body=%q", rr.Code, policy, body)
	}
}

func TestChallengeHTMLNavigationClassification(t *testing.T) {
	for name, req := range map[string]*http.Request{
		"get-navigation": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "text/html,application/xhtml+xml")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			return r
		}(),
		"head-navigation": func() *http.Request {
			r := httptest.NewRequest(http.MethodHead, "/", nil)
			r.Header.Set("Accept", "text/html")
			return r
		}(),
		"post-json": func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.Header.Set("Accept", "text/html")
			return r
		}(),
		"json": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "application/json")
			return r
		}(),
		"xhr": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "text/html")
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
			return r
		}(),
		"fetch": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", "text/html")
			r.Header.Set("Sec-Fetch-Mode", "cors")
			return r
		}(),
	} {
		want := name == "get-navigation" || name == "head-navigation"
		if got := IsHTMLNavigation(req); got != want {
			t.Errorf("%s classified as navigation=%t want=%t", name, got, want)
		}
	}
}

type fakeDNS struct {
	reverse                []string
	forward                []net.IPAddr
	reverseErr, forwardErr error
}

func (d fakeDNS) LookupAddr(context.Context, string) ([]string, error) {
	return d.reverse, d.reverseErr
}
func (d fakeDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return d.forward, d.forwardErr
}
func TestVerifiedBotRequiresForwardConfirmationAndCaches(t *testing.T) {
	ip := net.ParseIP("66.249.66.1")
	dns := fakeDNS{reverse: []string{"crawl-1.googlebot.com."}, forward: []net.IPAddr{{IP: ip}}}
	v := NewVerifiedResolver(dns, []string{"googlebot.com"}, nil, time.Minute)
	if v.IsVerified("Googlebot", ip) {
		t.Fatal("pending DNS lookup must not block or be treated as verified")
	}
	deadline := time.Now().Add(time.Second)
	for !v.IsVerified("Googlebot", ip) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !v.IsVerified("Googlebot", ip) {
		t.Fatal("forward-confirmed bot result was not cached")
	}
	for _, bad := range []*VerifiedResolver{NewVerifiedResolver(fakeDNS{reverse: []string{"evilgooglebot.com"}, forward: []net.IPAddr{{IP: ip}}}, []string{"googlebot.com"}, nil, time.Minute), NewVerifiedResolver(fakeDNS{reverse: []string{"crawl.googlebot.com"}, forward: []net.IPAddr{{IP: net.ParseIP("66.249.66.2")}}}, []string{"googlebot.com"}, nil, time.Minute)} {
		if bad.IsVerified("ua", ip) {
			t.Fatal("unverified PTR accepted")
		}
		deadline := time.Now().Add(time.Second)
		for bad.CacheSize() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if bad.IsVerified("ua", ip) {
			t.Fatal("PTR without matching forward address was trusted")
		}
	}
}

func TestVerifiedResolverNegativeResultIsCached(t *testing.T) {
	ip := net.ParseIP("203.0.113.41")
	v := NewVerifiedResolver(fakeDNS{reverse: []string{"spoof.googlebot.com.evil.test."}, forward: []net.IPAddr{{IP: ip}}}, []string{"googlebot.com"}, nil, time.Minute)
	if v.IsVerified("Googlebot", ip) {
		t.Fatal("unresolved IP unexpectedly trusted")
	}
	deadline := time.Now().Add(time.Second)
	for v.CacheSize() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	started, _ := v.LookupStats()
	for i := 0; i < 100; i++ {
		if v.IsVerified("Googlebot", ip) {
			t.Fatal("negative result became trusted")
		}
	}
	after, _ := v.LookupStats()
	if started != 1 || after != 1 {
		t.Fatalf("negative cache did not suppress duplicate DNS: before=%d after=%d", started, after)
	}
}

type gatedDNS struct {
	started chan struct{}
	gate    chan struct{}
	mu      sync.Mutex
	active  int
	max     int
	calls   int
}

func (d *gatedDNS) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	d.mu.Lock()
	d.active++
	d.calls++
	if d.active > d.max {
		d.max = d.active
	}
	d.mu.Unlock()
	select {
	case d.started <- struct{}{}:
	default:
	}
	select {
	case <-d.gate:
	case <-ctx.Done():
	}
	d.mu.Lock()
	d.active--
	d.mu.Unlock()
	return nil, context.DeadlineExceeded
}
func (*gatedDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, nil
}

func TestVerifiedResolverAsyncBoundedDeduplicatedAndNonblocking(t *testing.T) {
	dns := &gatedDNS{started: make(chan struct{}, 64), gate: make(chan struct{})}
	v := NewVerifiedResolverWithLimits(dns, []string{"googlebot.com"}, nil, time.Minute, 2*time.Second, 4, 30, 64)
	started := time.Now()
	for i := 1; i <= 10_000; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).To4()
		if v.IsVerified("Googlebot", ip) {
			t.Fatal("not-yet-resolved IP was treated as verified")
		}
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("request path waited on resolver: %s", elapsed)
	}
	startedCount, _ := v.LookupStats()
	if startedCount > 30 {
		t.Fatalf("lookup rate cap exceeded: started=%d", startedCount)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-dns.started:
		default:
			goto checked
		}
	}
checked:
	dns.mu.Lock()
	active, calls := dns.active, dns.calls
	dns.mu.Unlock()
	if active > 4 || calls > 30 {
		t.Fatalf("resolver worker/dedup bound failed active=%d calls=%d", active, calls)
	}
	close(dns.gate)

	dupDNS := &gatedDNS{started: make(chan struct{}, 64), gate: make(chan struct{})}
	dup := NewVerifiedResolverWithLimits(dupDNS, []string{"googlebot.com"}, nil, time.Minute, 2*time.Second, 2, 100, 64)
	keyIP := net.ParseIP("198.51.100.5")
	for i := 0; i < 100; i++ {
		dup.IsVerified("Googlebot", keyIP)
	}
	select {
	case <-dupDNS.started:
	case <-time.After(time.Second):
		t.Fatal("deduplicated DNS lookup did not start")
	}
	dupDNS.mu.Lock()
	dupCalls := dupDNS.calls
	dupDNS.mu.Unlock()
	if dupCalls != 1 {
		t.Fatalf("duplicate IP lookup was not coalesced: calls=%d", dupCalls)
	}
	close(dupDNS.gate)
}

func TestVerifiedResolverNegativeCacheAndCapacity(t *testing.T) {
	dns := fakeDNS{reverse: []string{"spoofed.example."}, forward: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}}
	v := NewVerifiedResolverWithLimits(dns, []string{"googlebot.com"}, nil, time.Minute, 100*time.Millisecond, 4, 100, 32)
	for i := 1; i <= 1_000_000; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).To4()
		v.IsVerified("Googlebot", ip)
	}
	deadline := time.Now().Add(time.Second)
	for v.PendingLookups() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := v.CacheSize(); got > 32 {
		t.Fatalf("negative cache grew beyond configured cap: %d", got)
	}
}

type verifiedAlways struct{}

func (verifiedAlways) IsVerified(string, net.IP) bool { return true }
func TestVerifiedBotBypassesChallengeAndFreeHasNoChallengeEntitlement(t *testing.T) {
	site := &wafcore.Site{ID: "site", Plan: "free", Bot: wafcore.BotConfig{Mode: "challenge", Threshold: 1}, Entitlements: wafcore.Entitlements{VerifiedBots: true}}
	snap := &wafcore.Snapshot{}
	r := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	r.Header.Set("User-Agent", "Googlebot")
	c := reqctx.New(r, snap, "id", net.ParseIP("203.0.113.4"))
	c.Site = site
	p := NewPhase(testManager(), verifiedAlways{})
	d := p.Handle(c)
	if d.Action != reqctx.ActionAllow || !c.BotVerified || !contains(c.Tags(), "verified_bot") {
		t.Fatalf("verified bot decision=%+v ctx=%+v", d, c)
	}
	reqctx.Release(c)
	site.Entitlements = wafcore.Entitlements{}
	r = httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	r.Header.Set("User-Agent", "curl/8.1")
	c = reqctx.New(r, snap, "id", net.ParseIP("203.0.113.4"))
	c.Site = site
	p = NewPhase(testManager(), nil)
	d = p.Handle(c)
	if d.Action == reqctx.ActionChallenge || c.BotChallengeToken != "" {
		t.Fatalf("Free plan got challenge: %+v", d)
	}
	reqctx.Release(c)
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

type fakeFingerprintReputation bool

func (f fakeFingerprintReputation) IsAutomation(string, string) bool { return bool(f) }

type fakeIPReputation int

func (f fakeIPReputation) Score(net.IP, uint32) int { return int(f) }
func TestBotScoreUsesHeaderFingerprintAndIPSignalsAndStaysBounded(t *testing.T) {
	site := &wafcore.Site{ID: "site", Bot: wafcore.BotConfig{Mode: "monitor", Threshold: 50}}
	r := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/123.0")
	c := reqctx.New(r, &wafcore.Snapshot{}, "id", net.ParseIP("203.0.113.10"))
	c.Site = site
	c.JA3 = "curl-like"
	p := NewPhase(nil, nil)
	p.Fingerprints = fakeFingerprintReputation(true)
	p.IPTrust = fakeIPReputation(55)
	d := p.Handle(c)
	if d.Action != reqctx.ActionAllow || c.BotScore != 94 {
		t.Fatalf("score=%d decision=%+v, want 94 (missing Accept 14 + JA mismatch 25 + reputation 55)", c.BotScore, d)
	}
	if c.BotScore < 0 || c.BotScore > 100 {
		t.Fatalf("score out of range %d", c.BotScore)
	}
	reqctx.Release(c)
	r = httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	c = reqctx.New(r, &wafcore.Snapshot{}, "id", net.ParseIP("203.0.113.10"))
	c.Site = site
	p = NewPhase(nil, nil)
	p.IPTrust = fakeIPReputation(100)
	p.Handle(c)
	if c.BotScore != 100 {
		t.Fatalf("score did not clamp to 100: %d", c.BotScore)
	}
	reqctx.Release(c)
}

func TestUnverifiedSearchBotUAAddsRiskInsteadOfTrust(t *testing.T) {
	site := &wafcore.Site{ID: "site", Bot: wafcore.BotConfig{Mode: "monitor"}, Entitlements: wafcore.Entitlements{VerifiedBots: true}}
	r := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	r.Header.Set("User-Agent", "Googlebot")
	c := reqctx.New(r, &wafcore.Snapshot{}, "id", net.ParseIP("203.0.113.15"))
	c.Site = site
	p := NewPhase(testManager(), nil)
	p.Handle(c)
	if c.BotVerified || c.BotScore < 20 {
		t.Fatalf("unverified Googlebot UA trusted: verified=%t score=%d", c.BotVerified, c.BotScore)
	}
	reqctx.Release(c)
}

func TestBehaviorStateMillionGeneratedKeysStaysBounded(t *testing.T) {
	p := NewPhase(nil, nil)
	p.maxKeys = 256
	site := &wafcore.Site{ID: "tenant-site", Bot: wafcore.BotConfig{Mode: "monitor"}}
	r := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	c := reqctx.New(r, nil, "request", net.ParseIP("10.0.0.0"))
	c.Site = site
	defer reqctx.Release(c)
	for i := 0; i < 1_000_000; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).To4()
		c.ClientIP = ip
		if d := p.Handle(c); d.Action != reqctx.ActionAllow {
			t.Fatalf("new key was rejected by bounded state policy at %d: %+v", i, d)
		}
	}
	if got := p.BehaviorKeyCount(); got > p.maxKeys {
		t.Fatalf("behavior table exceeded cap: got=%d cap=%d", got, p.maxKeys)
	}
	if got := p.BehaviorKeyCount(); got != p.maxKeys {
		t.Fatalf("expected the first %d keys to be retained, got %d", p.maxKeys, got)
	}
	c.ClientIP = net.ParseIP("203.0.113.250")
	c.Request.Header.Set("User-Agent", "curl/8.0")
	p.Handle(c)
	if c.BotScore < 24 || p.BehaviorKeyCount() > p.maxKeys {
		t.Fatalf("overflow key did not receive stateless UA scoring: score=%d keys=%d", c.BotScore, p.BehaviorKeyCount())
	}
}

func TestBehaviorStateExpiresAndReinitializes(t *testing.T) {
	p := NewPhase(nil, nil)
	now := time.Unix(1_000, 0)
	p.now = func() time.Time { return now }
	site := &wafcore.Site{ID: "site", Bot: wafcore.BotConfig{Mode: "monitor"}}
	ip := net.ParseIP("192.0.2.45")
	r := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	c := reqctx.New(r, nil, "id", ip)
	c.Site = site
	p.Handle(c)
	key := site.ID + "|" + ip.String()
	if p.shard(key).entries[key].count != 1 {
		t.Fatal("initial behavior state not recorded")
	}
	now = now.Add(behaviorTTL + time.Second)
	p.Handle(c)
	entry := p.shard(key).entries[key]
	if entry == nil || entry.count != 1 || p.BehaviorKeyCount() != 1 {
		t.Fatalf("expired behavior state was not cleaned/reinitialized: entry=%+v keys=%d", entry, p.BehaviorKeyCount())
	}
	reqctx.Release(c)
}
