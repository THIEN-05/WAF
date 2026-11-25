package site

import (
	"context"
	"crypto/sha256"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type fakeDNS struct {
	txt   []string
	cname string
	ips   []net.IP
}

func (f fakeDNS) LookupTXT(context.Context, string) ([]string, error)        { return f.txt, nil }
func (f fakeDNS) LookupCNAME(context.Context, string) (string, error)        { return f.cname, nil }
func (f fakeDNS) LookupIP(context.Context, string, string) ([]net.IP, error) { return f.ips, nil }

func TestVerifyDNSOwnership(t *testing.T) {
	hash := sha256.Sum256([]byte("token-123"))
	if err := VerifyDNSHash(context.Background(), fakeDNS{txt: []string{"wrong", "token-123"}}, "Example.test.", hash[:], "verify.example.net"); err != nil {
		t.Fatalf("TXT proof: %v", err)
	}
	if err := VerifyDNSHash(context.Background(), fakeDNS{cname: CNAMEProofTarget(hash[:], "verify.example.net")}, "example.test", hash[:], "verify.example.net"); err != nil {
		t.Fatalf("CNAME proof: %v", err)
	}
	if err := VerifyDNSHash(context.Background(), fakeDNS{}, "example.test", hash[:], "verify.example.net"); err == nil {
		t.Fatal("missing proof accepted")
	}
}

func TestVerifyDNSHash(t *testing.T) {
	proof := fakeDNS{txt: []string{"token-123"}}
	hash := sha256.Sum256([]byte("token-123"))
	if err := VerifyDNSHash(context.Background(), proof, "example.test", hash[:], ""); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOriginPolicy(t *testing.T) {
	resolver := fakeDNS{ips: []net.IP{net.ParseIP("8.8.8.8")}}
	if _, err := ValidateOrigin(context.Background(), "https://origin.example:8443/base", resolver); err != nil {
		t.Fatalf("valid origin: %v", err)
	}
	for _, raw := range []string{"ftp://origin.example", "http://user@origin.example", "http://origin.example:22"} {
		if _, err := ValidateOrigin(context.Background(), raw, resolver); err == nil {
			t.Errorf("accepted invalid origin %q", raw)
		}
	}
	if _, err := ValidateOrigin(context.Background(), "http://origin.example", fakeDNS{ips: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}}); err == nil {
		t.Fatal("accepted mixed public/private DNS answer")
	}
	if _, err := ValidateOrigin(context.Background(), "http://127.0.0.1", resolver); err == nil {
		t.Fatal("accepted literal loopback")
	}
	if _, err := ValidateOrigin(context.Background(), "http://[::1]", resolver); err == nil {
		t.Fatal("accepted IPv6 loopback literal")
	}
	if _, err := ValidateOrigin(context.Background(), "http://origin.example/path#fragment", resolver); err == nil {
		t.Fatal("accepted origin URL fragment")
	}
}

func TestOriginProbeGuardsSelfAndDoesNotFollowRedirects(t *testing.T) {
	public := net.ParseIP("203.0.113.14")
	resolver := fakeDNS{ips: []net.IP{public}}
	if err := ProbeOrigin(context.Background(), "https://origin.example", resolver, []net.IP{public}, time.Second); err == nil {
		t.Fatal("probe allowed an origin resolving to this service")
	}
	client := originProbeClient(&http.Transport{}, time.Second)
	redirect := &http.Request{URL: &url.URL{Scheme: "http", Host: "127.0.0.1"}}
	if err := client.CheckRedirect(redirect, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect decision=%v, want ErrUseLastResponse", err)
	}
}

func TestVerificationIntervalUsesAge(t *testing.T) {
	if got := VerificationInterval(23*time.Hour + 59*time.Minute); got != time.Minute {
		t.Fatalf("initial verification interval=%v", got)
	}
	if got := VerificationInterval(24 * time.Hour); got != 15*time.Minute {
		t.Fatalf("slow verification interval=%v", got)
	}
}
