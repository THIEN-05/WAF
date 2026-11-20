package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const IncrWindowsLua = `local values = {}
for i, key in ipairs(KEYS) do
  local current = redis.call('INCR', key)
  if current == 1 then redis.call('PEXPIRE', key, ARGV[i]) end
  values[i] = current
end
return values`

type RedisIncrement struct {
	Key   string
	TTL   time.Duration
	Limit uint64
}

type RedisBackend interface {
	IncrWindows(context.Context, []RedisIncrement) ([]uint64, error)
}

type RedisClientBackend struct {
	client *redis.Client
}

func NewRedisClientBackend(rawURL string) (*RedisClientBackend, error) {
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse Redis URL: %w", err)
	}
	return &RedisClientBackend{client: redis.NewClient(options)}, nil
}

func (b *RedisClientBackend) IncrWindows(ctx context.Context, increments []RedisIncrement) ([]uint64, error) {
	if len(increments) == 0 {
		return nil, nil
	}
	keys := make([]string, len(increments))
	args := make([]any, len(increments))
	for i, increment := range increments {
		if increment.Key == "" || increment.TTL <= 0 {
			return nil, fmt.Errorf("redis counter key and positive TTL are required")
		}
		keys[i] = increment.Key
		args[i] = increment.TTL.Milliseconds()
	}
	result, err := b.client.Eval(ctx, IncrWindowsLua, keys, args...).Result()
	if err != nil {
		return nil, err
	}
	values, ok := result.([]any)
	if !ok || len(values) != len(increments) {
		return nil, fmt.Errorf("unexpected Redis Lua result %T", result)
	}
	counts := make([]uint64, len(values))
	for i, value := range values {
		switch count := value.(type) {
		case int64:
			if count < 0 {
				return nil, fmt.Errorf("redis returned negative counter")
			}
			counts[i] = uint64(count)
		case string:
			parsed, parseErr := strconv.ParseUint(count, 10, 64)
			if parseErr != nil {
				return nil, fmt.Errorf("parse Redis counter: %w", parseErr)
			}
			counts[i] = parsed
		default:
			return nil, fmt.Errorf("unexpected Redis counter value %T", value)
		}
	}
	return counts, nil
}

func (b *RedisClientBackend) Close() error {
	if b == nil || b.client == nil {
		return nil
	}
	return b.client.Close()
}

type RedisSyncConfig struct {
	QueueSize     int
	BatchSize     int
	MaxRemoteKeys int
	FlushEvery    time.Duration
	Timeout       time.Duration
}

type AsyncRedisSync struct {
	backend  RedisBackend
	queue    chan RedisIncrement
	cfg      RedisSyncConfig
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	healthy  atomic.Bool
	failed   atomic.Uint64
	dropped  atomic.Uint64
	remoteMu sync.Mutex
	remote   map[string]remoteCounter
}

type remoteCounter struct {
	count   uint64
	expires time.Time
}

func NewAsyncRedisSync(backend RedisBackend, cfg RedisSyncConfig) *AsyncRedisSync {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 128
	}
	if cfg.MaxRemoteKeys <= 0 {
		cfg.MaxRemoteKeys = 100_000
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 25 * time.Millisecond
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	syncer := &AsyncRedisSync{backend: backend, queue: make(chan RedisIncrement, cfg.QueueSize), cfg: cfg, ctx: ctx, cancel: cancel, done: make(chan struct{}), remote: map[string]remoteCounter{}}
	syncer.healthy.Store(true)
	go syncer.run()
	return syncer
}

func (s *AsyncRedisSync) Queue(increment RedisIncrement) {
	if s == nil || s.backend == nil {
		return
	}
	select {
	case s.queue <- increment:
	default:
		s.dropped.Add(1)
	}
}

func (s *AsyncRedisSync) Healthy() bool { return s != nil && s.healthy.Load() }
func (s *AsyncRedisSync) FailedBatches() uint64 {
	if s == nil {
		return 0
	}
	return s.failed.Load()
}
func (s *AsyncRedisSync) DroppedIncrements() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

func (s *AsyncRedisSync) RemoteExceeded(key string, limit uint64, now time.Time) (bool, time.Duration) {
	if s == nil || !s.Healthy() {
		return false, 0
	}
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	entry, ok := s.remote[key]
	if !ok {
		return false, 0
	}
	if !entry.expires.After(now) {
		delete(s.remote, key)
		return false, 0
	}
	if entry.count < limit {
		return false, 0
	}
	return true, entry.expires.Sub(now)
}

func (s *AsyncRedisSync) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.cancel()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *AsyncRedisSync) run() {
	defer close(s.done)
	ticker := time.NewTicker(s.cfg.FlushEvery)
	defer ticker.Stop()
	batch := make([]RedisIncrement, 0, s.cfg.BatchSize)
	for {
		select {
		case increment := <-s.queue:
			batch = append(batch, increment)
			if len(batch) >= s.cfg.BatchSize {
				s.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				s.flush(batch)
				batch = batch[:0]
			}
		case <-s.ctx.Done():
			for {
				select {
				case increment := <-s.queue:
					batch = append(batch, increment)
					if len(batch) >= s.cfg.BatchSize {
						s.flush(batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						s.flush(batch)
					}
					return
				}
			}
		}
	}
}

func (s *AsyncRedisSync) flush(batch []RedisIncrement) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
	values, err := s.backend.IncrWindows(ctx, batch)
	cancel()
	if err != nil || len(values) != len(batch) {
		s.healthy.Store(false)
		s.failed.Add(1)
		return // local limiting remains authoritative while Redis is unavailable.
	}
	now := time.Now()
	s.remoteMu.Lock()
	for i, increment := range batch {
		entry, exists := s.remote[increment.Key]
		if !exists && len(s.remote) >= s.cfg.MaxRemoteKeys {
			for key, old := range s.remote {
				if !old.expires.After(now) {
					delete(s.remote, key)
				}
				if len(s.remote) < s.cfg.MaxRemoteKeys {
					break
				}
			}
			if len(s.remote) >= s.cfg.MaxRemoteKeys {
				continue
			}
		}
		if !exists || !entry.expires.After(now) {
			entry.expires = now.Add(increment.TTL)
		}
		entry.count = values[i]
		s.remote[increment.Key] = entry
	}
	s.remoteMu.Unlock()
	s.healthy.Store(true)
}
