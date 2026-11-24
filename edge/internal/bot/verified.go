package bot

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type DNSResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type VerifiedResolver struct {
	DNS      DNSResolver
	Suffixes []string
	Prefixes []*net.IPNet
	TTL      time.Duration
	mu       sync.Mutex
	cache    map[string]cacheEntry
	now      func() time.Time
	max      int
}
type cacheEntry struct {
	ok      bool
	expires time.Time
}

func NewVerifiedResolver(dns DNSResolver, suffixes []string, prefixes []*net.IPNet, ttl time.Duration) *VerifiedResolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &VerifiedResolver{DNS: dns, Suffixes: append([]string(nil), suffixes...), Prefixes: append([]*net.IPNet(nil), prefixes...), TTL: ttl, cache: map[string]cacheEntry{}, now: time.Now, max: 10_000}
}
func (v *VerifiedResolver) IsVerified(_ string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	key := ip.String()
	now := v.now()
	v.mu.Lock()
	if ent, ok := v.cache[key]; ok && now.Before(ent.expires) {
		v.mu.Unlock()
		return ent.ok
	}
	v.mu.Unlock()
	valid := false
	for _, prefix := range v.Prefixes {
		if prefix != nil && prefix.Contains(ip) {
			valid = true
			break
		}
	}
	if !valid && v.DNS != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		names, err := v.DNS.LookupAddr(ctx, key)
		if err == nil {
			for _, name := range names {
				name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
				if !v.allowedSuffix(name) {
					continue
				}
				addresses, e := v.DNS.LookupIPAddr(ctx, name)
				if e != nil {
					continue
				}
				for _, address := range addresses {
					if address.IP.Equal(ip) {
						valid = true
						break
					}
				}
				if valid {
					break
				}
			}
		}
	}
	v.mu.Lock()
	if len(v.cache) >= v.max {
		for k, entry := range v.cache {
			if !now.Before(entry.expires) {
				delete(v.cache, k)
				break
			}
		}
		if len(v.cache) >= v.max {
			for k := range v.cache {
				delete(v.cache, k)
				break
			}
		}
	}
	v.cache[key] = cacheEntry{valid, now.Add(v.TTL)}
	v.mu.Unlock()
	return valid
}
func (v *VerifiedResolver) allowedSuffix(name string) bool {
	for _, suffix := range v.Suffixes {
		suffix = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(suffix, ".")), ".")
		if suffix != "" && (name == suffix || strings.HasSuffix(name, "."+suffix)) {
			return true
		}
	}
	return false
}
