package bot

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if _, err = m.Verify(bad, "wrong", "site", "Mozilla/5.0", ip, now); err == nil {
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
	if !v.IsVerified("Googlebot", ip) {
		t.Fatal("forward-confirmed bot rejected")
	}
	for _, bad := range []*VerifiedResolver{NewVerifiedResolver(fakeDNS{reverse: []string{"evilgooglebot.com"}, forward: []net.IPAddr{{IP: ip}}}, []string{"googlebot.com"}, nil, time.Minute), NewVerifiedResolver(fakeDNS{reverse: []string{"crawl.googlebot.com"}, forward: []net.IPAddr{{IP: net.ParseIP("66.249.66.2")}}}, []string{"googlebot.com"}, nil, time.Minute)} {
		if bad.IsVerified("ua", ip) {
			t.Fatal("unverified PTR accepted")
		}
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
