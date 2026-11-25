package site

import (
	"context"
	"crypto/sha256"
	"net"
	"testing"
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
	if err := VerifyDNS(context.Background(), fakeDNS{txt: []string{"wrong", "token-123"}}, "Example.test.", "token-123"); err != nil {
		t.Fatalf("TXT proof: %v", err)
	}
	if err := VerifyDNS(context.Background(), fakeDNS{cname: "verify.token-123.waf.invalid."}, "example.test", "token-123"); err != nil {
		t.Fatalf("CNAME proof: %v", err)
	}
	if err := VerifyDNS(context.Background(), fakeDNS{}, "example.test", "token-123"); err == nil {
		t.Fatal("missing proof accepted")
	}
}

func TestVerifyDNSHash(t *testing.T) {
	proof := fakeDNS{txt: []string{"token-123"}}
	hash := sha256.Sum256([]byte("token-123"))
	if err := VerifyDNSHash(context.Background(), proof, "example.test", hash[:]); err != nil {
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
}
