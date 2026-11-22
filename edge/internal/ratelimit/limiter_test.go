package ratelimit

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

func TestTokenBucketWithFakeClock(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := NewLimiter(Config{MaxKeys: 10, Shards: 2, TTL: time.Minute, Now: func() time.Time { return now }})
	for i := 0; i < 3; i++ {
		allowed, _, err := limiter.AllowToken("site", "key", 3, time.Second, 0)
		if err != nil || !allowed {
			t.Fatalf("initial request %d allowed=%v err=%v", i, allowed, err)
		}
	}
	if allowed, retry, err := limiter.AllowToken("site", "key", 3, time.Second, 0); err != nil || allowed || retry <= 0 {
		t.Fatalf("over-limit request allowed=%v retry=%s err=%v", allowed, retry, err)
	}
	now = now.Add(time.Second)
	if allowed, _, err := limiter.AllowToken("site", "key", 3, time.Second, 0); err != nil || !allowed {
		t.Fatalf("request after refill allowed=%v err=%v", allowed, err)
	}
}

func TestTokenBucketConcurrentGoroutines(t *testing.T) {
	limiter := NewLimiter(Config{MaxKeys: 100, Shards: 8})
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _, err := limiter.AllowToken("site", "shared", 25, time.Hour, 0)
			if err != nil {
				t.Errorf("allow token: %v", err)
				return
			}
			if ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 25 {
		t.Fatalf("allowed=%d, want exactly 25", got)
	}
}

func TestSlidingWindowCounter(t *testing.T) {
	now := time.Unix(0, 0)
	limiter := NewLimiter(Config{Now: func() time.Time { return now }})
	for i := 0; i < 3; i++ {
		if ok, _, err := limiter.AllowSliding("site", "path", 3, 10*time.Second, 0); err != nil || !ok {
			t.Fatalf("request %d allowed=%v err=%v", i, ok, err)
		}
	}
	if ok, _, err := limiter.AllowSliding("site", "path", 3, 10*time.Second, 0); err != nil || ok {
		t.Fatalf("over-limit request allowed=%v err=%v", ok, err)
	}
	now = now.Add(10 * time.Second)
	if ok, retry, err := limiter.AllowSliding("site", "path", 3, 10*time.Second, 0); err != nil || ok || retry <= 0 {
		t.Fatalf("previous window should still count: allowed=%v retry=%s err=%v", ok, retry, err)
	}
	now = now.Add(10 * time.Second)
	if ok, _, err := limiter.AllowSliding("site", "path", 3, 10*time.Second, 0); err != nil || !ok {
		t.Fatalf("expired previous window did not clear: allowed=%v err=%v", ok, err)
	}
}

func TestCounterKeyLimitAndTTLBatchCleanup(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := NewLimiter(Config{MaxKeys: 2, Shards: 1, TTL: time.Second, Now: func() time.Time { return now }})
	for _, key := range []string{"one", "two"} {
		if ok, _, err := limiter.AllowToken("site", key, 1, time.Minute, 0); err != nil || !ok {
			t.Fatalf("key %s allowed=%v err=%v", key, ok, err)
		}
	}
	if _, _, err := limiter.AllowToken("other", "three", 1, time.Minute, 0); err != ErrCounterCapacity {
		t.Fatalf("capacity error=%v, want %v", err, ErrCounterCapacity)
	}
	now = now.Add(2 * time.Second)
	if removed := limiter.Cleanup(); removed != 2 {
		t.Fatalf("cleanup removed %d entries, want 2", removed)
	}
	if ok, _, err := limiter.AllowToken("other", "three", 1, time.Minute, 0); err != nil || !ok {
		t.Fatalf("new key after cleanup allowed=%v err=%v", ok, err)
	}
}

func TestCounterKeyCapacitySurvivesOneMillionAttackerKeys(t *testing.T) {
	const capacity = 32
	limiter := NewLimiter(Config{MaxKeys: capacity, Shards: 8, TTL: time.Hour})
	for i := 0; i < 1_000_000; i++ {
		_, _, err := limiter.AllowToken("attacker-site", fmt.Sprintf("generated-%d", i), 1, time.Minute, 0)
		if i < capacity && err != nil {
			t.Fatalf("key %d rejected before capacity: %v", i, err)
		}
		if i >= capacity && err != ErrCounterCapacity {
			t.Fatalf("key %d error=%v, want capacity rejection", i, err)
		}
	}
	if limiter.keyCount != capacity {
		t.Fatalf("retained %d keys, want bounded capacity %d", limiter.keyCount, capacity)
	}
}

func TestTokenBucketRejectsOverflowAndClockRollback(t *testing.T) {
	if _, _, err := NewLimiter(Config{}).AllowToken("site", "overflow", ^uint64(0), time.Second, 0); err == nil {
		t.Fatal("overflowing token capacity was accepted")
	}
	now := time.Unix(100, 0)
	limiter := NewLimiter(Config{Now: func() time.Time { return now }})
	if allowed, _, err := limiter.AllowToken("site", "rollback", 1, time.Second, 0); err != nil || !allowed {
		t.Fatalf("initial request allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := limiter.AllowToken("site", "rollback", 1, time.Second, 0); err != nil || allowed {
		t.Fatalf("second request allowed=%v err=%v, want exhausted bucket", allowed, err)
	}
	now = now.Add(-time.Hour)
	if allowed, _, err := limiter.AllowToken("site", "rollback", 1, time.Second, 0); err != nil || allowed {
		t.Fatalf("clock rollback refilled bucket: allowed=%v err=%v", allowed, err)
	}
	now = time.Unix(101, 0)
	if allowed, _, err := limiter.AllowToken("site", "rollback", 1, time.Second, 0); err != nil || !allowed {
		t.Fatalf("bucket did not refill after a full forward window: allowed=%v err=%v", allowed, err)
	}
}

type failingRedis struct {
	calls atomic.Int64
}

func (f *failingRedis) IncrWindows(context.Context, []RedisIncrement) ([]uint64, error) {
	f.calls.Add(1)
	return nil, fmt.Errorf("Redis unavailable")
}

func TestRedisFailureFallsBackToLocalLimiter(t *testing.T) {
	backend := &failingRedis{}
	syncer := NewAsyncRedisSync(backend, RedisSyncConfig{FlushEvery: time.Millisecond, BatchSize: 1})
	limiter := NewLimiter(Config{})
	limiter.SetRedisSync(syncer)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := syncer.Close(ctx); err != nil {
			t.Errorf("close Redis syncer: %v", err)
		}
	})
	allowed, _, err := limiter.AllowToken("site", "ip:192.0.2.1", 1, time.Minute, 0)
	if err != nil || !allowed {
		t.Fatalf("first local request allowed=%v err=%v", allowed, err)
	}
	deadline := time.Now().Add(time.Second)
	for syncer.Healthy() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !syncer.Degraded() || syncer.FailedBatches() == 0 {
		t.Fatal("Redis failure was not observed")
	}
	allowed, retry, err := limiter.AllowToken("site", "ip:192.0.2.1", 1, time.Minute, 0)
	if err != nil || allowed || retry <= 0 {
		t.Fatalf("local limiter did not enforce after Redis failure: allowed=%v retry=%s err=%v", allowed, retry, err)
	}
}

func TestRateLimitPhaseReturnsRuleAndKeyVariants(t *testing.T) {
	limits := []wafcore.RateLimit{
		{ID: "rl-header", Match: "http.path == '/login'", Key: "header:X-User", Limit: 1, WindowS: 60, Action: "throttle", Algorithm: "token_bucket"},
	}
	limiter := NewLimiter(Config{})
	phase := NewPhase(limiter, nil)
	site := wafcore.Site{ID: "site", Plan: "pro", RateLimits: limits, Entitlements: wafcore.Entitlements{MaxCounterKeys: 10}}
	makeCtx := func(headerValue string) *reqctx.RequestCtx {
		r := httptest.NewRequest("POST", "http://site.test/login", nil)
		r.Header.Set("X-User", headerValue)
		ctx := reqctx.New(r, &wafcore.Snapshot{Version: 1}, "request", net.ParseIP("192.0.2.10"))
		ctx.Site = &site
		return ctx
	}
	if d := phase.Handle(makeCtx("alice")); d.Action != reqctx.ActionAllow {
		t.Fatalf("first header key decision=%+v", d)
	}
	decision := phase.Handle(makeCtx("alice"))
	if decision.Action != reqctx.ActionRateLimited || decision.RuleID != "rl-header" || decision.Phase != "ratelimit" || decision.RetryAfter <= 0 {
		t.Fatalf("rate limit decision=%+v", decision)
	}
	if d := phase.Handle(makeCtx("bob")); d.Action != reqctx.ActionAllow {
		t.Fatalf("distinct header key shared counter: %+v", d)
	}
}

func TestAllRateLimitKeyTypesAndBanSeconds(t *testing.T) {
	request := httptest.NewRequest("POST", "http://site.test/path", nil)
	request.Header.Set("X-Client", "value")
	request.AddCookie(&http.Cookie{Name: "session", Value: "cookie-value"})
	ctx := reqctx.New(request, &wafcore.Snapshot{Version: 3}, "request", net.ParseIP("192.0.2.5"))
	ctx.Site = &wafcore.Site{ID: "site"}
	ctx.JA3 = "ja3-hash"
	keys := []string{"ip", "ip+path", "header:X-Client", "cookie:session", "ja3", "site"}
	seen := map[string]bool{}
	for _, kind := range keys {
		key, err := counterKey(kind, ctx)
		if err != nil {
			t.Fatalf("counter key %q: %v", kind, err)
		}
		if seen[key] {
			t.Fatalf("counter key %q collided", kind)
		}
		seen[key] = true
	}

	bans := &recordingBan{}
	phase := NewPhase(NewLimiter(Config{}), bans)
	site := wafcore.Site{ID: "site", Plan: "pro", RateLimits: []wafcore.RateLimit{{
		ID: "rl-ban", Match: "http.path == '/path'", Key: "ip", Limit: 1, WindowS: 30, Action: "block", BanS: 600,
	}}}
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "http://site.test/path", nil)
		requestCtx := reqctx.New(r, &wafcore.Snapshot{Version: 1}, "request", net.ParseIP("192.0.2.8"))
		requestCtx.Site = &site
		decision := phase.Handle(requestCtx)
		if i == 1 && (decision.Action != reqctx.ActionRateLimited || decision.RuleID != "rl-ban") {
			t.Fatalf("limited decision=%+v", decision)
		}
	}
	if bans.ttl != 600*time.Second {
		t.Fatalf("ban TTL=%s, want 10m", bans.ttl)
	}
}

func TestAsyncRedisSyncUsesLuaBatchAndRecovers(t *testing.T) {
	backend := &recordingRedis{}
	syncer := NewAsyncRedisSync(backend, RedisSyncConfig{FlushEvery: time.Millisecond, BatchSize: 2})
	syncer.Queue(RedisIncrement{Key: "k1", TTL: time.Minute, Limit: 1})
	syncer.Queue(RedisIncrement{Key: "k2", TTL: time.Minute, Limit: 1})
	deadline := time.Now().Add(time.Second)
	for backend.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if backend.calls.Load() != 1 || syncer.Degraded() {
		t.Fatalf("batch calls=%d degraded=%v", backend.calls.Load(), syncer.Degraded())
	}
	if exceeded, _ := syncer.RemoteExceeded("k2", 1, time.Now()); !exceeded {
		t.Fatal("asynchronously synchronized Redis count did not enforce remote threshold")
	}
	if !strings.Contains(IncrWindowsLua, "redis.call('INCR'") || !strings.Contains(IncrWindowsLua, "redis.call('PEXPIRE'") {
		t.Fatal("Redis Lua script does not use INCR and PEXPIRE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := syncer.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRedisClientBackendHonorsContextTimeout(t *testing.T) {
	backend, err := NewRedisClientBackend("redis://127.0.0.1:6379/0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	if !backend.client.Options().ContextTimeoutEnabled {
		t.Fatal("Redis backend must apply AsyncRedisSync context deadlines to socket operations")
	}
}

func BenchmarkRateLimitAllow(b *testing.B) {
	limiter := NewLimiter(Config{MaxKeys: 1, Shards: 1})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := limiter.AllowToken("bench-site", "fixed-client", 1_000_000, time.Hour, 0); err != nil {
			b.Fatal(err)
		}
	}
}

type recordingRedis struct{ calls atomic.Int64 }

func (r *recordingRedis) IncrWindows(_ context.Context, batch []RedisIncrement) ([]uint64, error) {
	if len(batch) != 2 {
		return nil, fmt.Errorf("got batch of %d increments", len(batch))
	}
	r.calls.Add(1)
	return []uint64{1, 2}, nil
}

type recordingBan struct{ ttl time.Duration }

func (b *recordingBan) Ban(_ net.IP, ttl time.Duration) error {
	b.ttl = ttl
	return nil
}
