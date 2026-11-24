package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
	"github.com/klauspost/compress/zstd"
	"github.com/nats-io/nats.go"
)

type CompressedBatch struct {
	SchemaVersion int                   `json:"schema_version"`
	CreatedAt     time.Time             `json:"created_at"`
	Events        []wafcore.LogEvent    `json:"events,omitempty"`
	SiteStats     []wafcore.SiteStats1m `json:"site_stats_1m,omitempty"`
}

type BatchSink interface {
	Publish(context.Context, []byte) error
}

type ShipperConfig struct {
	QueueSize      int
	BatchSize      int
	MaxBatchBytes  int
	FlushInterval  time.Duration
	StatsLimit     int
	IPMaskV4Bits   int
	IPMaskV6Bits   int
	PlanSampleRate map[string]float64
	Now            func() time.Time
	OnDropped      func(uint64)
}

type queuedRecord struct {
	event      *wafcore.LogEvent
	stats      *wafcore.SiteStats1m
	statsDelta *wafcore.LogEvent
}
type statsKey struct{ tenant, site string }
type Shipper struct {
	cfg       ShipperConfig
	sink      BatchSink
	queue     chan queuedRecord
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	queueMu   sync.RWMutex
	closed    bool
	mu        sync.Mutex
	stats     map[statsKey]wafcore.SiteStats1m
	encoder   *zstd.Encoder
	dropped   atomic.Uint64
}

func NewShipper(sink BatchSink, cfg ShipperConfig) (*Shipper, error) {
	if sink == nil {
		return nil, errors.New("telemetry batch sink is required")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.BatchSize <= 0 || cfg.BatchSize > 1000 {
		cfg.BatchSize = 1000
	}
	if cfg.MaxBatchBytes <= 0 {
		cfg.MaxBatchBytes = 512 << 10
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	if cfg.StatsLimit <= 0 {
		cfg.StatsLimit = 100_000
	}
	if cfg.IPMaskV4Bits < 0 || cfg.IPMaskV4Bits > 32 || cfg.IPMaskV6Bits < 0 || cfg.IPMaskV6Bits > 128 {
		return nil, errors.New("invalid client IP mask prefix")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PlanSampleRate == nil {
		cfg.PlanSampleRate = map[string]float64{"free": .01, "pro": .1, "business": .5, "enterprise": 1}
	}
	for plan, rate := range cfg.PlanSampleRate {
		if strings.TrimSpace(plan) == "" || rate < 0 || rate > 1 {
			return nil, fmt.Errorf("invalid sample rate for plan %q", plan)
		}
	}
	rateCopy := make(map[string]float64, len(cfg.PlanSampleRate))
	for plan, rate := range cfg.PlanSampleRate {
		rateCopy[strings.ToLower(plan)] = rate
	}
	cfg.PlanSampleRate = rateCopy
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	s := &Shipper{cfg: cfg, sink: sink, queue: make(chan queuedRecord, cfg.QueueSize), stop: make(chan struct{}), done: make(chan struct{}), stats: make(map[statsKey]wafcore.SiteStats1m), encoder: enc}
	go s.run()
	return s, nil
}

// Record aggregates every request into site_stats_1m and samples only normal
// request events. Security events always enter the queue regardless of plan.
func (s *Shipper) Record(event wafcore.LogEvent, security bool, plan string) bool {
	if s == nil {
		return false
	}
	if event.TS.IsZero() {
		event.TS = s.cfg.Now().UTC()
	}
	if err := event.Validate(); err != nil {
		return false
	}
	event.Host = boundedField(event.Host, 253)
	event.Path = boundedField(event.Path, 2048)
	event.Method = boundedField(event.Method, 32)
	event.JA3 = boundedField(event.JA3, 64)
	event.RuleID = boundedField(event.RuleID, 256)
	event.Country = boundedField(event.Country, 8)
	event.Region = boundedField(event.Region, 64)
	event.EdgeID = boundedField(event.EdgeID, 128)
	if len(event.Tags) > 32 {
		event.Tags = event.Tags[:32]
	}
	event.ClientIP = MaskClientIP(event.ClientIP, s.cfg.IPMaskV4Bits, s.cfg.IPMaskV6Bits)
	for i := range event.Tags {
		event.Tags[i] = boundedTag(event.Tags[i])
	}
	item := queuedRecord{statsDelta: &event}
	if security || s.sample(event.RequestID, plan) {
		item.event = &event
	}
	return s.enqueue(item)
}

func (s *Shipper) sample(requestID, plan string) bool {
	rate, ok := s.cfg.PlanSampleRate[strings.ToLower(plan)]
	if !ok {
		rate = s.cfg.PlanSampleRate["free"]
	}
	if rate <= 0 {
		return false
	}
	if rate >= 1 {
		return true
	}
	h := sha256.Sum256([]byte(requestID))
	return float64(binary.BigEndian.Uint64(h[:8]))/float64(^uint64(0)) < rate
}

func (s *Shipper) aggregate(event wafcore.LogEvent) *wafcore.SiteStats1m {
	key := statsKey{tenant: event.TenantID, site: event.SiteID}
	minute := event.TS.UTC().Truncate(time.Minute)
	s.mu.Lock()
	stats, ok := s.stats[key]
	var old *wafcore.SiteStats1m
	if ok && !stats.Minute.Equal(minute) {
		done := stats
		old = &done
		ok = false
	}
	if !ok {
		if len(s.stats) >= s.cfg.StatsLimit {
			s.mu.Unlock()
			s.drop(1)
			return old
		}
		stats = wafcore.SiteStats1m{Minute: minute, TenantID: event.TenantID, SiteID: event.SiteID}
	}
	stats.Requests++
	if event.Status >= 500 {
		stats.Status5xx++
	}
	if event.BytesOut > 0 {
		stats.BytesOut += event.BytesOut
	}
	switch event.Action {
	case "block":
		stats.Blocked++
	case "challenge":
		stats.Challenged++
	case "rate_limited":
		stats.RateLimited++
	}
	if event.CacheStatus == "hit" {
		stats.CacheHits++
	}
	s.stats[key] = stats
	s.mu.Unlock()
	return old
}

func (s *Shipper) enqueue(item queuedRecord) bool {
	if !s.queueMu.TryRLock() {
		s.drop(1)
		return false
	}
	defer s.queueMu.RUnlock()
	if s.closed {
		s.drop(1)
		return false
	}
	select {
	case s.queue <- item:
		return true
	default:
		s.drop(1)
		return false
	}
}
func (s *Shipper) drop(n uint64) {
	s.dropped.Add(n)
	if s.cfg.OnDropped != nil {
		s.cfg.OnDropped(n)
	}
}
func (s *Shipper) Dropped() uint64 { return s.dropped.Load() }

// FlushStats is exposed for deterministic tests and for clean shutdown.
func (s *Shipper) FlushStats() {
	s.flushStats(false)
}
func (s *Shipper) flushStats(all bool) {
	for _, stats := range s.takeStats(all) {
		copy := stats
		_ = s.enqueue(queuedRecord{stats: &copy})
	}
}
func (s *Shipper) takeStats(all bool) []wafcore.SiteStats1m {
	nowMinute := s.cfg.Now().UTC().Truncate(time.Minute)
	s.mu.Lock()
	var flush []wafcore.SiteStats1m
	for key, stats := range s.stats {
		if all || stats.Minute.Before(nowMinute) {
			flush = append(flush, stats)
			delete(s.stats, key)
		}
	}
	s.mu.Unlock()
	return flush
}

func (s *Shipper) run() {
	defer close(s.done)
	ticker := time.NewTicker(s.cfg.FlushInterval)
	statsTicker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	defer statsTicker.Stop()
	batch := CompressedBatch{SchemaVersion: wafcore.LogSchemaVersion, Events: make([]wafcore.LogEvent, 0, s.cfg.BatchSize), SiteStats: make([]wafcore.SiteStats1m, 0, s.cfg.BatchSize)}
	batchBytes := 0
	flush := func() {
		if len(batch.Events)+len(batch.SiteStats) == 0 {
			return
		}
		batch.CreatedAt = s.cfg.Now().UTC()
		var err error
		for _, event := range batch.Events {
			if err = event.Validate(); err != nil {
				break
			}
		}
		if err == nil {
			for _, stats := range batch.SiteStats {
				if err = stats.Validate(); err != nil {
					break
				}
			}
		}
		var raw []byte
		if err == nil {
			raw, err = json.Marshal(batch)
		}
		if err == nil {
			compressed := s.encoder.EncodeAll(raw, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = s.sink.Publish(ctx, compressed)
			cancel()
		}
		if err != nil {
			s.drop(uint64(len(batch.Events) + len(batch.SiteStats)))
		}
		batch = CompressedBatch{SchemaVersion: wafcore.LogSchemaVersion, Events: make([]wafcore.LogEvent, 0, s.cfg.BatchSize), SiteStats: make([]wafcore.SiteStats1m, 0, s.cfg.BatchSize)}
		batchBytes = 0
	}
	appendStat := func(stats wafcore.SiteStats1m) {
		encoded, _ := json.Marshal(stats)
		sizeBytes := len(encoded)
		if len(batch.Events)+len(batch.SiteStats) > 0 && batchBytes+sizeBytes > s.cfg.MaxBatchBytes {
			flush()
		}
		batch.SiteStats = append(batch.SiteStats, stats)
		batchBytes += sizeBytes
		if len(batch.Events)+len(batch.SiteStats) >= s.cfg.BatchSize {
			flush()
		}
	}
	appendEvent := func(event wafcore.LogEvent) {
		encoded, _ := json.Marshal(event)
		sizeBytes := len(encoded)
		if len(batch.Events)+len(batch.SiteStats) > 0 && batchBytes+sizeBytes > s.cfg.MaxBatchBytes {
			flush()
		}
		batch.Events = append(batch.Events, event)
		batchBytes += sizeBytes
		if len(batch.Events)+len(batch.SiteStats) >= s.cfg.BatchSize {
			flush()
		}
	}
	appendItem := func(item queuedRecord) {
		if item.statsDelta != nil {
			if completed := s.aggregate(*item.statsDelta); completed != nil {
				appendStat(*completed)
			}
		}
		if item.stats != nil {
			appendStat(*item.stats)
		}
		if item.event != nil {
			appendEvent(*item.event)
		}
	}
	for {
		select {
		case item := <-s.queue:
			appendItem(item)
		case <-ticker.C:
			s.FlushStats()
			flush()
		case <-statsTicker.C:
			s.FlushStats()
		case <-s.stop:
			for {
				select {
				case item := <-s.queue:
					appendItem(item)
				default:
					for _, stats := range s.takeStats(true) {
						appendStat(stats)
					}
					flush()
					return
				}
			}
		}
	}
}
func (s *Shipper) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.queueMu.Lock()
		s.closed = true
		close(s.stop)
		s.queueMu.Unlock()
		<-s.done
		_ = s.encoder.Close()
	})
}

func MaskClientIP(raw string, v4Bits, v6Bits int) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		if v4Bits < 0 || v4Bits > 32 {
			v4Bits = 24
		}
		mask := net.CIDRMask(v4Bits, 32)
		return net.IP(v4.Mask(mask)).String()
	}
	if v6Bits < 0 || v6Bits > 128 {
		v6Bits = 56
	}
	return net.IP(ip.Mask(net.CIDRMask(v6Bits, 128))).String()
}
func boundedTag(tag string) string {
	if len(tag) > 96 {
		return tag[:96]
	}
	return tag
}
func boundedField(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}

// NATSBatchSink reconnects lazily on later worker publishes. A failed publish
// affects only the worker; request goroutines enqueue into a bounded channel.
type NATSBatchSink struct {
	URL, Subject string
	mu           sync.Mutex
	conn         *nats.Conn
	closed       bool
}

func NewNATSBatchSink(url, subject string) (*NATSBatchSink, error) {
	if strings.TrimSpace(url) == "" {
		return nil, errors.New("NATS URL is required")
	}
	if strings.TrimSpace(subject) == "" {
		subject = "edge.logs.v1"
	}
	return &NATSBatchSink{URL: url, Subject: subject}, nil
}
func (n *NATSBatchSink) Publish(ctx context.Context, payload []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return errors.New("NATS sink closed")
	}
	if n.conn == nil || n.conn.IsClosed() {
		conn, err := nats.Connect(n.URL, nats.Timeout(700*time.Millisecond), nats.MaxReconnects(-1), nats.ReconnectWait(250*time.Millisecond), nats.DisconnectErrHandler(func(_ *nats.Conn, err error) { _ = err }))
		if err != nil {
			return err
		}
		n.conn = conn
	}
	if err := n.conn.Publish(n.Subject, payload); err != nil {
		return err
	}
	timeout := 700 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	return n.conn.FlushTimeout(timeout)
}
func (n *NATSBatchSink) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = true
	if n.conn != nil {
		n.conn.Close()
		n.conn = nil
	}
}

// HTTPBatchSink is an alternative ingest path with a bounded request timeout.
type HTTPBatchSink struct {
	URL    string
	Client *http.Client
}

func (h HTTPBatchSink) Publish(ctx context.Context, payload []byte) error {
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/vnd.waf.logbatch+zstd")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ingest returned HTTP %d", resp.StatusCode)
	}
	return nil
}
