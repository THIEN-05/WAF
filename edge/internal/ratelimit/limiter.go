package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"
)

const microTokens int64 = 1_000_000

var ErrCounterCapacity = errors.New("rate limit counter capacity reached")

type Config struct {
	MaxKeys int
	Shards  int
	TTL     time.Duration
	Now     func() time.Time
}

type Limiter struct {
	shards     []counterShard
	maxKeys    int
	ttl        time.Duration
	now        func() time.Time
	countMu    sync.Mutex
	keyCount   int
	siteCounts map[string]int
	operations atomic.Uint64
	cleanupAt  atomic.Uint64
	redis      atomic.Pointer[AsyncRedisSync]
}

type counterShard struct {
	mu      sync.Mutex
	entries map[string]*counterEntry
}

type counterEntry struct {
	siteID  string
	expires time.Time
	token   atomic.Pointer[tokenState]
	mu      sync.Mutex
	sliding slidingState
}

type tokenState struct {
	tokens uint64
	lastNS int64
}

type slidingState struct {
	window      int64
	prev        uint64
	cur         uint64
	initialized bool
}

func NewLimiter(cfg Config) *Limiter {
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 100_000
	}
	if cfg.Shards <= 0 {
		cfg.Shards = 32
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 2 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	l := &Limiter{shards: make([]counterShard, cfg.Shards), maxKeys: cfg.MaxKeys, ttl: cfg.TTL, now: cfg.Now, siteCounts: map[string]int{}}
	for i := range l.shards {
		l.shards[i].entries = map[string]*counterEntry{}
	}
	return l
}

func (l *Limiter) SetRedisSync(syncer *AsyncRedisSync) { l.redis.Store(syncer) }

func (l *Limiter) AllowToken(siteID, key string, limit uint64, window time.Duration, siteMaxKeys int) (bool, time.Duration, error) {
	if err := validatePolicy(limit, window); err != nil {
		return false, 0, err
	}
	capacity, err := toMicroTokens(limit)
	if err != nil {
		return false, 0, err
	}
	now := l.now()
	entry, err := l.get(siteID, key, siteMaxKeys, now)
	if err != nil {
		return false, window, err
	}
	redisKey := l.redisKey(siteID, key, window, now)
	if redis := l.redis.Load(); redis != nil {
		if exceeded, retry := redis.RemoteExceeded(redisKey, limit, now); exceeded {
			redis.Queue(RedisIncrement{Key: redisKey, TTL: window, Limit: limit})
			l.maybeCleanup()
			return false, retry, nil
		}
	}
	allowed, retry := consumeToken(entry, now.UnixNano(), capacity, window)
	l.queueRedis(redisKey, limit, window)
	l.maybeCleanup()
	return allowed, retry, nil
}

func consumeToken(entry *counterEntry, nowNS int64, capacity uint64, window time.Duration) (bool, time.Duration) {
	windowNS := int64(window)
	if capacity == 0 || windowNS <= 0 {
		return false, 0
	}
	for {
		old := entry.token.Load()
		if old == nil {
			old = &tokenState{tokens: capacity, lastNS: nowNS}
			if !entry.token.CompareAndSwap(nil, old) {
				continue
			}
		}
		tokens := old.tokens
		lastNS := old.lastNS
		if nowNS > lastNS {
			elapsed := nowNS - lastNS
			if elapsed < 0 || elapsed >= windowNS {
				tokens = capacity
				lastNS = nowNS
			} else {
				hi, lo := bits.Mul64(uint64(elapsed), capacity)
				refill, _ := bits.Div64(hi, lo, uint64(windowNS))
				if refill > 0 {
					tokens = addRefill(tokens, refill, capacity)
					lastNS = nowNS // sub-micro-token remainder is intentionally discarded.
				}
			}
		}
		if tokens < uint64(microTokens) {
			next := &tokenState{tokens: tokens, lastNS: lastNS}
			if entry.token.CompareAndSwap(old, next) {
				return false, tokenRetryAfter(capacity-tokens, capacity, windowNS)
			}
			continue
		}
		next := &tokenState{tokens: tokens - uint64(microTokens), lastNS: lastNS}
		if entry.token.CompareAndSwap(old, next) {
			return true, 0
		}
	}
}

func addRefill(tokens, refill, capacity uint64) uint64 {
	if tokens >= capacity {
		return capacity
	}
	if refill >= capacity-tokens {
		return capacity
	}
	return tokens + refill
}

func tokenRetryAfter(missing, capacity uint64, windowNS int64) time.Duration {
	if windowNS <= 0 || capacity == 0 {
		return 0
	}
	window := uint64(windowNS)
	hi, lo := bits.Mul64(missing, window)
	ns, remainder := bits.Div64(hi, lo, capacity)
	if remainder != 0 {
		ns++
	}
	if ns == 0 {
		ns = 1
	}
	if ns > window {
		ns = window
	}
	if ns > math.MaxInt64 {
		ns = math.MaxInt64
	}
	return time.Duration(ns)
}

func (l *Limiter) AllowSliding(siteID, key string, limit uint64, window time.Duration, siteMaxKeys int) (bool, time.Duration, error) {
	if err := validatePolicy(limit, window); err != nil {
		return false, 0, err
	}
	now := l.now()
	entry, err := l.get(siteID, key, siteMaxKeys, now)
	if err != nil {
		return false, window, err
	}
	redisKey := l.redisKey(siteID, key, window, now)
	if redis := l.redis.Load(); redis != nil {
		if exceeded, retry := redis.RemoteExceeded(redisKey, limit, now); exceeded {
			redis.Queue(RedisIncrement{Key: redisKey, TTL: window, Limit: limit})
			l.maybeCleanup()
			return false, retry, nil
		}
	}
	windowNS := int64(window)
	nowNS := now.UnixNano()
	windowIndex := nowNS / windowNS
	startNS := windowIndex * windowNS
	entry.mu.Lock()
	if !entry.sliding.initialized {
		entry.sliding.window = windowIndex
		entry.sliding.initialized = true
	} else if windowIndex != entry.sliding.window {
		if windowIndex == entry.sliding.window+1 {
			entry.sliding.prev = entry.sliding.cur
		} else {
			entry.sliding.prev = 0
		}
		entry.sliding.cur = 0
		entry.sliding.window = windowIndex
	}
	elapsed := nowNS - startNS
	previousWeight := 1 - float64(elapsed)/float64(windowNS)
	used := float64(entry.sliding.prev)*previousWeight + float64(entry.sliding.cur)
	if used+1 > float64(limit) {
		entry.mu.Unlock()
		l.queueRedis(redisKey, limit, window)
		l.maybeCleanup()
		return false, time.Duration(windowNS - elapsed), nil
	}
	entry.sliding.cur++
	entry.mu.Unlock()
	l.queueRedis(redisKey, limit, window)
	l.maybeCleanup()
	return true, 0, nil
}

func validatePolicy(limit uint64, window time.Duration) error {
	if limit == 0 || window <= 0 {
		return fmt.Errorf("rate limit and positive window are required")
	}
	if _, err := toMicroTokens(limit); err != nil {
		return err
	}
	return nil
}

func toMicroTokens(limit uint64) (uint64, error) {
	if limit > uint64(math.MaxInt64/microTokens) {
		return 0, fmt.Errorf("rate limit exceeds micro-token capacity")
	}
	return limit * uint64(microTokens), nil
}

func (l *Limiter) get(siteID, key string, siteMaxKeys int, now time.Time) (*counterEntry, error) {
	hash := sha256.Sum256([]byte(siteID + "\x00" + key))
	keyHash := hex.EncodeToString(hash[:])
	shard := &l.shards[int(hash[0])%len(l.shards)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if entry, ok := shard.entries[keyHash]; ok {
		if entry.expires.After(now) {
			entry.expires = now.Add(l.ttl)
			return entry, nil
		}
		delete(shard.entries, keyHash)
		l.releaseKey(entry.siteID)
	}
	if err := l.reserveKey(siteID, siteMaxKeys); err != nil {
		return nil, err
	}
	entry := &counterEntry{siteID: siteID, expires: now.Add(l.ttl)}
	shard.entries[keyHash] = entry
	return entry, nil
}

func (l *Limiter) reserveKey(siteID string, siteMaxKeys int) error {
	l.countMu.Lock()
	defer l.countMu.Unlock()
	if l.keyCount >= l.maxKeys || (siteMaxKeys > 0 && l.siteCounts[siteID] >= siteMaxKeys) {
		return ErrCounterCapacity
	}
	l.keyCount++
	l.siteCounts[siteID]++
	return nil
}

func (l *Limiter) releaseKey(siteID string) {
	l.countMu.Lock()
	defer l.countMu.Unlock()
	l.keyCount--
	l.siteCounts[siteID]--
	if l.siteCounts[siteID] == 0 {
		delete(l.siteCounts, siteID)
	}
}

func (l *Limiter) Cleanup() int {
	now := l.now()
	removed := 0
	for i := range l.shards {
		shard := &l.shards[i]
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if !entry.expires.After(now) {
				delete(shard.entries, key)
				l.releaseKey(entry.siteID)
				removed++
			}
		}
		shard.mu.Unlock()
	}
	return removed
}

func (l *Limiter) maybeCleanup() {
	if l.operations.Add(1)%256 == 0 {
		if len(l.shards) == 0 {
			return
		}
		start := l.cleanupAt.Add(4) % uint64(len(l.shards))
		for i := uint64(0); i < 4; i++ {
			l.cleanupShard((start+i)%uint64(len(l.shards)), 64)
		}
	}
}

func (l *Limiter) cleanupShard(index uint64, scanLimit int) int {
	shard := &l.shards[index]
	now := l.now()
	shard.mu.Lock()
	defer shard.mu.Unlock()
	removed, scanned := 0, 0
	for key, entry := range shard.entries {
		scanned++
		if !entry.expires.After(now) {
			delete(shard.entries, key)
			l.releaseKey(entry.siteID)
			removed++
		}
		if scanned >= scanLimit {
			break
		}
	}
	return removed
}

func (l *Limiter) redisKey(siteID, key string, window time.Duration, now time.Time) string {
	hash := sha256.Sum256([]byte(siteID + "\x00" + key))
	windowNumber := now.UnixNano() / int64(window)
	return fmt.Sprintf("waf:rl:%x:%d", hash, windowNumber)
}

func (l *Limiter) queueRedis(redisKey string, limit uint64, window time.Duration) {
	redis := l.redis.Load()
	if redis == nil {
		return
	}
	redis.Queue(RedisIncrement{Key: redisKey, TTL: window, Limit: limit})
}
