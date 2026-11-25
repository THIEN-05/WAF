// Package netguard provides DNS-rebinding-resistant outbound connections.
package netguard

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type DialFunc func(context.Context, string, string) (net.Conn, error)

type Guard struct {
	Resolver Resolver
	Dial     DialFunc
}

func New(resolver Resolver, dial DialFunc) Guard {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	return Guard{Resolver: resolver, Dial: dial}
}

// IsBlocked returns true for addresses that are not suitable public origins.
func IsBlocked(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// Shared address space and protocol assignments, including IPv4 metadata service ranges.
		for _, block := range []string{"100.64.0.0/10", "168.63.129.16/32", "192.0.0.0/24", "240.0.0.0/4"} {
			_, subnet, _ := net.ParseCIDR(block)
			if subnet.Contains(v4) {
				return true
			}
		}
	}
	if ip.To4() == nil {
		// IPv6 discard-only range is not globally routable.
		for _, block := range []string{"100::/64"} {
			_, subnet, _ := net.ParseCIDR(block)
			if subnet.Contains(ip) {
				return true
			}
		}
	}
	return !ip.IsGlobalUnicast()
}

// ResolvePublic resolves a host and rejects the whole answer set if any result is unsafe.
func (g Guard) ResolvePublic(ctx context.Context, host string) ([]net.IP, error) {
	if g.Resolver == nil {
		g = New(nil, g.Dial)
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if ip := net.ParseIP(host); ip != nil {
		if IsBlocked(ip) {
			return nil, fmt.Errorf("prohibited destination address %s", ip)
		}
		return []net.IP{ip}, nil
	}
	ips, err := g.Resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve destination: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("destination resolved to no addresses")
	}
	for _, ip := range ips {
		if IsBlocked(ip) {
			return nil, fmt.Errorf("destination resolves to prohibited address %s", ip)
		}
	}
	return ips, nil
}

// DialContext resolves again at connection time, validates every answer, then dials numeric IPs only.
func (g Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if g.Resolver == nil || g.Dial == nil {
		g = New(g.Resolver, g.Dial)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := g.ResolvePublic(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		conn, dialErr := g.Dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		last = dialErr
	}
	if last == nil {
		last = fmt.Errorf("destination has no dialable addresses")
	}
	return nil, last
}
