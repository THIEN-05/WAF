package site

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/example/wafplatform/pkg/netguard"
)

type DNS interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupCNAME(context.Context, string) (string, error)
}

// VerifyDNS implements the ownership proof used by the background domain verifier.
func VerifyDNS(ctx context.Context, dns DNS, hostname, token string) error {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if hostname == "" || token == "" || dns == nil {
		return fmt.Errorf("hostname, token and DNS resolver are required")
	}
	values, err := dns.LookupTXT(ctx, "_waf-verify."+hostname)
	if err == nil {
		for _, value := range values {
			if strings.TrimSpace(value) == token {
				return nil
			}
		}
	}
	target, cnameErr := dns.LookupCNAME(ctx, hostname)
	if cnameErr == nil && strings.EqualFold(strings.TrimSuffix(target, "."), "verify."+token+".waf.invalid") {
		return nil
	}
	return fmt.Errorf("domain ownership record not found")
}

// VerifyDNSHash compares DNS proof values to the stored token digest so the raw token need not persist.
func VerifyDNSHash(ctx context.Context, dns DNS, hostname string, expected []byte) error {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	values, err := dns.LookupTXT(ctx, "_waf-verify."+hostname)
	if err == nil {
		for _, value := range values {
			digest := sha256.Sum256([]byte(strings.TrimSpace(value)))
			if len(expected) == len(digest) && subtle.ConstantTimeCompare(expected, digest[:]) == 1 {
				return nil
			}
		}
	}
	target, cnameErr := dns.LookupCNAME(ctx, hostname)
	const prefix, suffix = "verify.", ".waf.invalid"
	if cnameErr == nil && strings.HasPrefix(strings.ToLower(target), prefix) && strings.HasSuffix(strings.ToLower(target), suffix) {
		proof := strings.TrimSuffix(strings.TrimPrefix(target, prefix), suffix)
		digest := sha256.Sum256([]byte(proof))
		if len(expected) == len(digest) && subtle.ConstantTimeCompare(expected, digest[:]) == 1 {
			return nil
		}
	}
	return fmt.Errorf("domain ownership record not found")
}

// ValidateOrigin rejects unsupported schemes/ports and any DNS answer that is not public.
func ValidateOrigin(ctx context.Context, raw string, resolver netguard.Resolver) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, fmt.Errorf("invalid origin URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("origin scheme must be http or https")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || (n != 80 && n != 443 && n != 8080 && n != 8443) {
		return nil, fmt.Errorf("origin port is not allowed")
	}
	g := netguard.New(resolver, nil)
	if _, err := g.ResolvePublic(ctx, u.Hostname()); err != nil {
		return nil, err
	}
	return u, nil
}

type NetResolver struct{ Resolver *net.Resolver }

func (r NetResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupIP(ctx, network, host)
}
