package router

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	cases := map[string]string{
		"known.test:bad": "", ":": "", "host:": "", "host:80:80": "", "[::1": "", "[::1]:x": "",
		"user@host": "", "host/": "", "host?x": "", "host\x00.test": "", strings.Repeat("a", 254): "",
		strings.Repeat("a", 64) + ".test": "", "host..": "", "xn--.test": "", "xn--a.test": "",
		"host:0": "", "host:65536": "", "KNOWN.TEST.:443": "known.test", "host:65535": "host",
		"[2001:db8::1]": "[2001:db8::1]", "[2001:db8::1]:443": "[2001:db8::1]",
		"BÜCHER.example.": "xn--bcher-kva.example", "xn--bcher-kva.example": "xn--bcher-kva.example",
	}
	longDomain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63)
	cases[longDomain] = ""
	for raw, want := range cases {
		if got := NormalizeHost(raw); got != want {
			t.Errorf("NormalizeHost(%q)=%q, want %q", raw, got, want)
		}
	}
}

func FuzzNormalizeHost(f *testing.F) {
	for _, seed := range []string{
		"known.test", "known.test:bad", ":", "host:", "host:80:80", "[::1", "[::1]:x",
		"user@host", "host/", "host?x", "host\x00.test", strings.Repeat("a", 254),
		strings.Repeat("a", 64) + ".test", "host..", "xn--.test", "xn--a.test", "BÜCHER.example.",
		"host:0", "host:65535", "host:65536", "[2001:db8::1]:443",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := NormalizeHost(raw)
		if len(raw) > 4096 && got != "" {
			t.Fatalf("oversized authority normalized: input=%d output=%q", len(raw), got)
		}
		parsed, parseErr := url.Parse("//" + raw)
		if parseErr != nil && got != "" {
			t.Fatalf("net/url rejected authority but NormalizeHost accepted it: input=%q normalized=%q err=%v", raw, got, parseErr)
		}
		if parseErr == nil && got != "" && (parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "") {
			t.Fatalf("url.Parse sees userinfo/path/query/fragment but NormalizeHost accepted it: input=%q parsed=%+v normalized=%q", raw, parsed, got)
		}
		if strings.Count(raw, ":") == 1 && !strings.HasPrefix(raw, "[") {
			_, port, splitErr := net.SplitHostPort(raw)
			if splitErr == nil && !validHostPort(port) && got != "" {
				t.Fatalf("net.SplitHostPort found invalid port %q but NormalizeHost accepted %q as %q", port, raw, got)
			}
		}
		if got != "" {
			if len(got) > 253 {
				t.Fatalf("normalized DNS name exceeds 253 bytes: %d", len(got))
			}
			if again := NormalizeHost(got); again != got {
				t.Fatalf("normalization is not idempotent: %q -> %q", got, again)
			}
		}
	})
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
