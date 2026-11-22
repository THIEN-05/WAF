//go:build integration

package ratelimit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func integrationRedisAddr() string {
	if addr := strings.TrimSpace(os.Getenv("REDIS_ADDR")); addr != "" {
		return addr
	}
	return "localhost:6379"
}

func redisIntegrationURL(addr string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	return "redis://" + addr + "/0"
}

func openIntegrationRedis(t *testing.T) (*RedisClientBackend, *redis.Client) {
	t.Helper()
	url := redisIntegrationURL(integrationRedisAddr())
	backend, err := NewRedisClientBackend(url)
	if err != nil {
		t.Fatalf("parse REDIS_ADDR: %v", err)
	}
	options, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse REDIS_ADDR for verification: %v", err)
	}
	admin := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := admin.Ping(ctx).Err(); err != nil {
		_ = backend.Close()
		_ = admin.Close()
		t.Fatalf("required Redis is unavailable at %s: %v", integrationRedisAddr(), err)
	}
	t.Cleanup(func() { _ = backend.Close(); _ = admin.Close() })
	return backend, admin
}

func TestIntegrationRedisLuaIncrPexpireConcurrent(t *testing.T) {
	backend, admin := openIntegrationRedis(t)
	key := fmt.Sprintf("waf:test:lua:%d", time.Now().UnixNano())
	const goroutines = 64
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	counts := make(chan uint64, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			values, err := backend.IncrWindows(context.Background(), []RedisIncrement{{Key: key, TTL: 30 * time.Second, Limit: goroutines}})
			if err != nil {
				errs <- err
				return
			}
			counts <- values[0]
		}()
	}
	wg.Wait()
	close(errs)
	close(counts)
	for err := range errs {
		t.Errorf("Redis Lua increment: %v", err)
	}
	seen := make(map[uint64]bool, goroutines)
	for count := range counts {
		if count == 0 || count > goroutines || seen[count] {
			t.Errorf("non-atomic/duplicate Redis result %d", count)
		}
		seen[count] = true
	}
	if len(seen) != goroutines {
		t.Fatalf("got %d unique Lua counts, want %d", len(seen), goroutines)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pttl := admin.PTTL(ctx, key).Val()
	if pttl <= 0 || pttl > 30*time.Second {
		t.Fatalf("PEXPIRE TTL=%s, want (0, 30s]", pttl)
	}
	_ = admin.Del(ctx, key).Err()
}

func TestIntegrationRedisOutageFallsBackAndRecovers(t *testing.T) {
	backend, admin := openIntegrationRedis(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// CLIENT PAUSE WRITE makes counter writes unavailable for this short test window.
	if err := admin.Do(ctx, "CLIENT", "PAUSE", 1800, "WRITE").Err(); err != nil {
		t.Fatalf("pause Redis writes for outage test: %v", err)
	}
	syncer := NewAsyncRedisSync(backend, RedisSyncConfig{QueueSize: 32, BatchSize: 1, FlushEvery: 5 * time.Millisecond, Timeout: 150 * time.Millisecond})
	limiter := NewLimiter(Config{MaxKeys: 8})
	limiter.SetRedisSync(syncer)
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
		defer closeCancel()
		if err := syncer.Close(closeCtx); err != nil {
			t.Errorf("close Redis syncer: %v", err)
		}
	})

	key := fmt.Sprintf("waf:test:outage:%d", time.Now().UnixNano())
	syncer.Queue(RedisIncrement{Key: key, TTL: time.Minute, Limit: 1})
	deadline := time.Now().Add(time.Second)
	for !syncer.Degraded() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !syncer.Degraded() || syncer.FailedBatches() == 0 {
		t.Fatal("Redis outage was not observed by the syncer")
	}
	if allowed, _, err := limiter.AllowToken("site", "local-fallback", 1, time.Minute, 0); err != nil || !allowed {
		t.Fatalf("local limiter did not allow first request during outage: allowed=%v err=%v", allowed, err)
	}
	if allowed, retry, err := limiter.AllowToken("site", "local-fallback", 1, time.Minute, 0); err != nil || allowed || retry <= 0 {
		t.Fatalf("local limiter failed closed during outage: allowed=%v retry=%s err=%v", allowed, retry, err)
	}

	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		syncer.Queue(RedisIncrement{Key: key, TTL: time.Minute, Limit: 1})
		if syncer.Healthy() && syncer.FailedBatches() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Redis syncer did not recover after the pause ended")
}
