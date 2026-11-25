package site

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/example/wafplatform/pkg/netguard"
)

type DNS interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupCNAME(context.Context, string) (string, error)
}

// VerifyDNSHash compares DNS proof values to the stored token digest so the raw token need not persist.
func VerifyDNSHash(ctx context.Context, dns DNS, hostname string, expected []byte, cnameZone string) error {
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
	zone := strings.Trim(strings.ToLower(strings.TrimSpace(cnameZone)), ".")
	if zone != "" {
		target, cnameErr := dns.LookupCNAME(ctx, hostname)
		want := "verify-" + hex.EncodeToString(expected) + "." + zone + "."
		if cnameErr == nil && strings.EqualFold(target, want) {
			return nil
		}
	}
	return fmt.Errorf("domain ownership record not found")
}

func CNAMEProofTarget(tokenHash []byte, zone string) string {
	return "verify-" + hex.EncodeToString(tokenHash) + "." + strings.Trim(strings.ToLower(zone), ".") + "."
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
	if u.Fragment != "" {
		return nil, fmt.Errorf("origin URL must not contain a fragment")
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

const maxOriginProbeBody = 64 << 10

// ProbeOrigin makes a bounded, non-redirecting connectivity probe. Network isolation
// itself must be enforced by the worker's deployment network policy.
func ProbeOrigin(ctx context.Context, raw string, resolver netguard.Resolver, selfIPs []net.IP, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	u, err := ValidateOrigin(ctx, raw, resolver)
	if err != nil {
		return err
	}
	g := netguard.New(resolver, nil)
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := func(dialCtx context.Context, network, address string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		ips, resolveErr := g.ResolvePublic(dialCtx, host)
		if resolveErr != nil {
			return nil, resolveErr
		}
		for _, ip := range ips {
			for _, self := range selfIPs {
				if ip.Equal(self) {
					return nil, fmt.Errorf("origin resolves to this service")
				}
			}
		}
		var last error
		for _, ip := range ips {
			conn, dialErr := g.Dial(dialCtx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			last = dialErr
		}
		return nil, last
	}
	transport := &http.Transport{Proxy: nil, DialContext: dial, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := originProbeClient(transport, timeout)
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("build origin probe")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("origin probe connection failed")
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOriginProbeBody+1))
	if err != nil {
		return fmt.Errorf("origin probe response read failed")
	}
	if len(body) > maxOriginProbeBody {
		return fmt.Errorf("origin probe response exceeded limit")
	}
	return nil
}

func originProbeClient(transport *http.Transport, timeout time.Duration) *http.Client {
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func VerificationInterval(age time.Duration) time.Duration {
	if age < 24*time.Hour {
		return time.Minute
	}
	return 15 * time.Minute
}

type NetResolver struct{ Resolver *net.Resolver }

func (r NetResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupIP(ctx, network, host)
}
