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

// VerifiedResolver returns cached results synchronously and schedules misses
// on a bounded worker queue. A pending lookup always means “not verified yet”.
type VerifiedResolver struct {
	DNS      DNSResolver
	Suffixes []string
	Prefixes []*net.IPNet
	TTL      time.Duration // compatibility alias for positive and negative TTL

	Timeout               time.Duration
	PositiveTTL           time.Duration
	NegativeTTL           time.Duration
	MaxConcurrent         int
	MaxLookupsPerSecond   int
	CacheMax              int
	mu                    sync.Mutex
	cache                 map[string]cacheEntry
	pending               map[string]struct{}
	queue                 chan string
	now                   func() time.Time
	windowStart           time.Time
	windowLookups         int
	lookupStarted, cached uint64
}

type cacheEntry struct {
	ok      bool
	expires time.Time
}

func NewVerifiedResolver(dns DNSResolver, suffixes []string, prefixes []*net.IPNet, ttl time.Duration) *VerifiedResolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return NewVerifiedResolverWithLimits(dns, suffixes, prefixes, ttl, 300*time.Millisecond, 8, 100, 10_000)
}

func NewVerifiedResolverWithLimits(dns DNSResolver, suffixes []string, prefixes []*net.IPNet, ttl, timeout time.Duration, maxConcurrent, maxLookupsPerSecond, cacheMax int) *VerifiedResolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 8
	}
	if maxLookupsPerSecond <= 0 {
		maxLookupsPerSecond = 100
	}
	if cacheMax <= 0 {
		cacheMax = 10_000
	}
	v := &VerifiedResolver{
		DNS: dns, Suffixes: append([]string(nil), suffixes...), Prefixes: append([]*net.IPNet(nil), prefixes...), TTL: ttl,
		Timeout: timeout, PositiveTTL: ttl, NegativeTTL: ttl, MaxConcurrent: maxConcurrent,
		MaxLookupsPerSecond: maxLookupsPerSecond, CacheMax: cacheMax, cache: map[string]cacheEntry{}, pending: map[string]struct{}{}, now: time.Now,
	}
	v.queue = make(chan string, 128)
	for i := 0; i < v.MaxConcurrent; i++ {
		go v.worker()
	}
	return v
}

func (v *VerifiedResolver) IsVerified(_ string, ip net.IP) bool {
	if v == nil || ip == nil {
		return false
	}
	for _, prefix := range v.Prefixes {
		if prefix != nil && prefix.Contains(ip) {
			return true
		}
	}
	key := ip.String()
	now := v.now()
	v.mu.Lock()
	if ent, ok := v.cache[key]; ok {
		if now.Before(ent.expires) {
			v.cached++
			v.mu.Unlock()
			return ent.ok
		}
		delete(v.cache, key)
	}
	if _, ok := v.pending[key]; ok || v.DNS == nil || v.CacheMax <= 0 || v.MaxLookupsPerSecond <= 0 {
		v.mu.Unlock()
		return false
	}
	if len(v.cache)+len(v.pending) >= v.CacheMax {
		v.evictOneLocked(now)
	}
	if len(v.cache)+len(v.pending) >= v.CacheMax || !v.allowLookupLocked(now) {
		v.mu.Unlock()
		return false
	}
	v.pending[key] = struct{}{}
	select {
	case v.queue <- key:
		v.lookupStarted++
	default:
		delete(v.pending, key)
	}
	v.mu.Unlock()
	return false
}

func (v *VerifiedResolver) allowLookupLocked(now time.Time) bool {
	if v.windowStart.IsZero() || now.Sub(v.windowStart) >= time.Second || now.Before(v.windowStart) {
		v.windowStart, v.windowLookups = now, 0
	}
	if v.windowLookups >= v.MaxLookupsPerSecond {
		return false
	}
	v.windowLookups++
	return true
}

func (v *VerifiedResolver) worker() {
	for key := range v.queue {
		ctx, cancel := context.WithTimeout(context.Background(), v.Timeout)
		ok := v.lookup(ctx, key)
		cancel()
		v.mu.Lock()
		delete(v.pending, key)
		ttl := v.NegativeTTL
		if ok {
			ttl = v.PositiveTTL
		}
		if ttl <= 0 {
			ttl = v.TTL
		}
		now := v.now()
		if len(v.cache) < v.CacheMax || v.evictOneLocked(now) {
			v.cache[key] = cacheEntry{ok: ok, expires: now.Add(ttl)}
		}
		v.mu.Unlock()
	}
}

func (v *VerifiedResolver) lookup(ctx context.Context, key string) bool {
	if v.DNS == nil {
		return false
	}
	names, err := v.DNS.LookupAddr(ctx, key)
	if err != nil {
		return false
	}
	for _, name := range names {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if !v.allowedSuffix(name) {
			continue
		}
		addresses, err := v.DNS.LookupIPAddr(ctx, name)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if address.IP.Equal(net.ParseIP(key)) {
				return true
			}
		}
	}
	return false
}

func (v *VerifiedResolver) evictOneLocked(now time.Time) bool {
	var oldestKey string
	var oldest time.Time
	for key, ent := range v.cache {
		if !now.Before(ent.expires) {
			delete(v.cache, key)
			return true
		}
		if oldestKey == "" || ent.expires.Before(oldest) {
			oldestKey, oldest = key, ent.expires
		}
	}
	if oldestKey != "" {
		delete(v.cache, oldestKey)
		return true
	}
	return false
}

func (v *VerifiedResolver) CacheSize() int {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.cache)
}

func (v *VerifiedResolver) PendingLookups() int {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.pending)
}

func (v *VerifiedResolver) LookupStats() (started, cacheHits uint64) {
	if v == nil {
		return 0, 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lookupStarted, v.cached
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
