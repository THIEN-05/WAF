package netguard

import (
	"context"
	"net"
	"strings"
	"testing"
)

type resolverFunc func(context.Context, string, string) ([]net.IP, error)

func (f resolverFunc) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f(ctx, network, host)
}

func TestIsBlocked(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "168.63.129.16", "::1", "::ffff:127.0.0.1", "fd00::1", "fc00::1", "0.0.0.0"} {
		if !IsBlocked(net.ParseIP(value)) {
			t.Errorf("%s was allowed", value)
		}
	}
	if IsBlocked(net.ParseIP("8.8.8.8")) {
		t.Fatal("public address was blocked")
	}
}

func TestResolvePublicRejectsLegacyPrivateIPLiterals(t *testing.T) {
	lookups := 0
	g := New(resolverFunc(func(context.Context, string, string) ([]net.IP, error) {
		lookups++
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}), nil)
	for _, host := range []string{"2130706433", "0x7f000001", "017700000001", "0177.0.0.1", "0x7f.1"} {
		if _, err := g.ResolvePublic(context.Background(), host); err == nil {
			t.Errorf("accepted encoded loopback %q", host)
		}
	}
	if lookups != 0 {
		t.Fatalf("legacy IP literals reached DNS resolver %d times", lookups)
	}
}

func TestResolvePublicRejectsIPv6LiteralAndCGNAT(t *testing.T) {
	g := New(resolverFunc(func(context.Context, string, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }), nil)
	for _, host := range []string{"[::1]", "100.64.0.1", "[fd00::1]"} {
		if _, err := g.ResolvePublic(context.Background(), strings.Trim(host, "[]")); err == nil {
			t.Errorf("accepted unsafe literal %q", host)
		}
	}
}

func TestDialContextRejectsRebindingAtDialTime(t *testing.T) {
	lookups, dials := 0, 0
	g := New(resolverFunc(func(context.Context, string, string) ([]net.IP, error) {
		lookups++
		if lookups == 1 {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}), func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, nil
	})
	if _, err := g.ResolvePublic(context.Background(), "origin.example"); err != nil {
		t.Fatalf("initial public resolution: %v", err)
	}
	if _, err := g.DialContext(context.Background(), "tcp", "origin.example:443"); err == nil {
		t.Fatal("rebinding to metadata address was allowed")
	}
	if dials != 0 {
		t.Fatalf("unsafe address was dialed %d times", dials)
	}
}

func TestResolvePublicRejectsMixedAnswerSet(t *testing.T) {
	g := New(resolverFunc(func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.1")}, nil
	}), nil)
	if _, err := g.ResolvePublic(context.Background(), "origin.example"); err == nil {
		t.Fatal("mixed public/private answer set was allowed")
	}
}
