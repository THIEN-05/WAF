package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

func TestExactBeforeWildcardAndNormalize(t *testing.T) {
	s := &wafcore.Snapshot{Sites: []wafcore.Site{{ID: "wild", Status: "active", Domains: []string{"*.example.com"}}, {ID: "exact", Status: "active", Domains: []string{"api.example.com"}}}}
	r := New(s)
	if got := r.Route("API.EXAMPLE.COM.:443"); got == nil || got.ID != "exact" {
		t.Fatalf("exact route=%v", got)
	}
	if got := r.Route("www.example.com"); got == nil || got.ID != "wild" {
		t.Fatalf("wild route=%v", got)
	}
	if r.Route("example.com") != nil {
		t.Fatal("wildcard matched apex")
	}
}
func TestNormalizeHostPunycode(t *testing.T) {
	if got := NormalizeHost("BÜCHER.example."); got != "xn--bcher-kva.example" {
		t.Fatalf("NormalizeHost punycode=%q", got)
	}
}

func TestNormalizeHostRejectsMalformedAuthority(t *testing.T) {
	for _, raw := range []string{"known.test:bad", "known.test:", "known.test:65536", "known.test:80:evil", "2001:db8::1", "[not-ipv6]", "[2001:db8::1]:bad"} {
		if got := NormalizeHost(raw); got != "" {
			t.Errorf("NormalizeHost(%q)=%q, want empty", raw, got)
		}
	}
	for raw, want := range map[string]string{"KNOWN.TEST.:443": "known.test", "[2001:db8::1]": "2001:db8::1", "[2001:db8::1]:443": "2001:db8::1"} {
		if got := NormalizeHost(raw); got != want {
			t.Errorf("NormalizeHost(%q)=%q, want %q", raw, got, want)
		}
	}
}
func TestResolveSNIAndSiteStates(t *testing.T) {
	s := &wafcore.Snapshot{Sites: []wafcore.Site{{ID: "active", TenantID: "t", Status: "active", Plan: "pro", Domains: []string{"a.test"}, Entitlements: wafcore.Entitlements{MaxRules: 2}}, {ID: "suspended", TenantID: "t", Status: "suspended", Plan: "pro", Domains: []string{"b.test"}}, {ID: "pending", TenantID: "t", Status: "pending", Plan: "pro", Domains: []string{"c.test"}}}}
	r := New(s)
	req := httptest.NewRequest(http.MethodGet, "http://a.test", nil)
	c := reqctx.New(req, s, "id", nil)
	site, status := r.Resolve(c)
	if status != 0 || site.ID != "active" || c.Entitlements.MaxRules != 2 {
		t.Fatal("active resolution failed")
	}
	c.Host = "a.test"
	c.SNI = "other.test"
	if _, status = r.Resolve(c); status != http.StatusMisdirectedRequest {
		t.Fatalf("SNI mismatch status %d", status)
	}
	c.SNI = ""
	c.Host = "unknown.test"
	if _, status = r.Resolve(c); status != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host status %d", status)
	}
	c.Host = "b.test"
	if _, status = r.Resolve(c); status != http.StatusPaymentRequired {
		t.Fatalf("suspended status %d", status)
	}
	c.Host = "c.test"
	if _, status = r.Resolve(c); status != http.StatusForbidden {
		t.Fatalf("pending status %d", status)
	}
}
