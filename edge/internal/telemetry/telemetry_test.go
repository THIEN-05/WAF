package telemetry

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/pipeline"
	"github.com/example/wafplatform/pkg/wafcore"
	"github.com/klauspost/compress/zstd"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func TestPrometheusMetricsHaveBoundedLabelsAndRequiredSignals(t *testing.T) {
	m := NewPrometheusMetrics()
	m.ObservePhase("waf", time.Millisecond)
	m.ObservePhase("attacker-controlled-phase", time.Second)
	m.BlockedGroup("waf")
	m.RateLimited()
	m.LogDropped(3)
	m.CacheHit()
	m.OriginError(502)
	m.ObserveRequest("GET", 200)
	m.ObserveRequest("x-unique-method", 500)
	m.SetSnapshot(91, 12.5, true)
	m.SetClientCertificateExpiry(time.Unix(1_800_000_000, 0))
	m.RefreshRuntime()
	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	for _, want := range []string{"edge_phase_duration_seconds_bucket{phase=\"waf\"", "edge_phase_duration_seconds_bucket{phase=\"other\"", "edge_blocked_total{group=\"waf\"} 1", "edge_rate_limited_total 1", "edge_log_dropped_total 3", "edge_cache_hits_total 1", "edge_origin_errors_total{status_class=\"5xx\"} 1", "edge_snapshot_version 91", "edge_snapshot_age_seconds 12.5", "edge_snapshot_stale 1", "edge_mtls_certificate_expiry_timestamp_seconds ", "edge_goroutines ", "edge_memory_bytes ", "edge_requests_total{method=\"OTHER\",status_class=\"5xx\"} 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("metric exposition missing %q", want)
		}
	}
	if strings.Contains(body, "site_id") || strings.Contains(body, "x-unique-method") {
		t.Fatal("unbounded/site label leaked into global metrics")
	}
}

type testBatchSink struct {
	batches chan []byte
	block   chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (s *testBatchSink) Publish(_ context.Context, b []byte) error {
	if s.entered != nil {
		s.once.Do(func() { close(s.entered) })
	}
	if s.block != nil {
		<-s.block
	}
	s.batches <- append([]byte(nil), b...)
	return nil
}

func validLogEvent(id string, at time.Time) wafcore.LogEvent {
	return wafcore.LogEvent{SchemaVersion: wafcore.LogSchemaVersion, TS: at, RequestID: id, SiteID: "site-a", TenantID: "tenant-a", ClientIP: "203.0.113.19", Method: "POST", Host: "example.test", Path: "/submit", Status: 403, BytesIn: 12, BytesOut: 23, Action: "block", RuleID: "waf-sqli", Tags: []string{"security"}}
}

func TestShipperBatchesZstdSchemaAndMasksIP(t *testing.T) {
	sink := &testBatchSink{batches: make(chan []byte, 2)}
	shipper, err := NewShipper(sink, ShipperConfig{QueueSize: 8, BatchSize: 10, FlushInterval: 20 * time.Millisecond, IPMaskV4Bits: 24, IPMaskV6Bits: 56})
	if err != nil {
		t.Fatal(err)
	}
	minute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if !shipper.Record(validLogEvent("req-1", minute), true, "free") {
		t.Fatal("security event was not queued")
	}
	select {
	case compressed := <-sink.batches:
		decoder, err := zstd.NewReader(nil)
		if err != nil {
			t.Fatal(err)
		}
		defer decoder.Close()
		raw, err := decoder.DecodeAll(compressed, nil)
		if err != nil {
			t.Fatal(err)
		}
		var batch CompressedBatch
		if err = json.Unmarshal(raw, &batch); err != nil {
			t.Fatal(err)
		}
		if batch.SchemaVersion != wafcore.LogSchemaVersion || len(batch.Events) != 1 || batch.Events[0].RequestID != "req-1" || batch.Events[0].ClientIP != "203.0.113.0" {
			t.Fatalf("decoded batch=%+v", batch)
		}
		if err := batch.Events[0].Validate(); err != nil {
			t.Fatalf("wafcore event schema invalid: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("batch did not flush")
	}
	shipper.FlushStats()
	shipper.Close()
	select {
	case compressed := <-sink.batches:
		statsBatch := decodeUnitBatch(t, compressed)
		if len(statsBatch.SiteStats) != 1 || statsBatch.SiteStats[0].Requests != 1 || statsBatch.SiteStats[0].Blocked != 1 {
			t.Fatalf("minute stats=%+v", statsBatch.SiteStats)
		}
		if err := statsBatch.SiteStats[0].Validate(); err != nil {
			t.Fatalf("site_stats_1m schema invalid: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("minute stats were not flushed")
	}
}

func decodeUnitBatch(t *testing.T, compressed []byte) CompressedBatch {
	t.Helper()
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	raw, err := decoder.DecodeAll(compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	var batch CompressedBatch
	if err = json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestShipperSecurityEventsBypassSamplingAndNormalSamplingUsesPlan(t *testing.T) {
	sink := &testBatchSink{batches: make(chan []byte, 4)}
	shipper, err := NewShipper(sink, ShipperConfig{QueueSize: 8, BatchSize: 1, FlushInterval: time.Hour, PlanSampleRate: map[string]float64{"free": 0}})
	if err != nil {
		t.Fatal(err)
	}
	defer shipper.Close()
	if shipper.Record(validLogEvent("security", time.Now()), true, "free") == false {
		t.Fatal("security event was sampled out")
	}
	if !shipper.Record(validLogEvent("normal", time.Now()), false, "free") {
		t.Fatal("normal event should aggregate even when sampled out")
	}
	select {
	case compressed := <-sink.batches:
		decoder, _ := zstd.NewReader(nil)
		raw, err := decoder.DecodeAll(compressed, nil)
		decoder.Close()
		if err != nil {
			t.Fatal(err)
		}
		var b CompressedBatch
		if err = json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		if len(b.Events) != 1 || b.Events[0].RequestID != "security" {
			t.Fatalf("sampled batch=%+v", b)
		}
	case <-time.After(time.Second):
		t.Fatal("security event was not flushed")
	}
}

func TestShipperQueueFullDropsWithoutBlocking(t *testing.T) {
	sink := &testBatchSink{batches: make(chan []byte, 4), block: make(chan struct{}), entered: make(chan struct{})}
	var dropped uint64
	shipper, err := NewShipper(sink, ShipperConfig{QueueSize: 1, BatchSize: 1, FlushInterval: time.Hour, OnDropped: func(n uint64) { dropped += n }})
	if err != nil {
		t.Fatal(err)
	}
	if !shipper.Record(validLogEvent("one", time.Now()), true, "pro") {
		t.Fatal("first event enqueue failed")
	}
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if !shipper.Record(validLogEvent("two", time.Now()), true, "pro") {
		t.Fatal("second event should occupy bounded queue")
	}
	start := time.Now()
	if shipper.Record(validLogEvent("three", time.Now()), true, "pro") {
		t.Fatal("full queue accepted another record")
	}
	if time.Since(start) > 20*time.Millisecond {
		t.Fatal("request-side enqueue blocked")
	}
	if shipper.Dropped() != 1 || dropped != 1 {
		t.Fatalf("drop counters shipper=%d callback=%d", shipper.Dropped(), dropped)
	}
	close(sink.block)
	shipper.Close()
}

func TestMaskClientIPAndSensitiveFieldsAreNotPartOfSchema(t *testing.T) {
	if got := MaskClientIP("2001:db8:abcd:1234::1", 56, 56); got != "2001:db8:abcd:1200::" {
		t.Fatalf("IPv6 masked=%q", got)
	}
	e := validLogEvent("req", time.Now())
	raw, _ := json.Marshal(e)
	for _, secret := range []string{"authorization", "cookie", "body"} {
		if strings.Contains(strings.ToLower(string(raw)), secret+"\"") {
			t.Fatalf("schema unexpectedly contains sensitive field %q", secret)
		}
	}
}

func TestTraceSamplerKeepsConfiguredOnePerThousandRatio(t *testing.T) {
	sampler := trace.TraceIDRatioBased(TraceSamplingRatio)
	low := oteltrace.TraceID{}
	high := oteltrace.TraceID{}
	for i := range high {
		high[i] = 0xff
	}
	for _, tc := range []struct {
		name string
		id   oteltrace.TraceID
		want trace.SamplingDecision
	}{{"lowest trace id", low, trace.RecordAndSample}, {"highest trace id", high, trace.Drop}} {
		got := sampler.ShouldSample(trace.SamplingParameters{TraceID: tc.id}).Decision
		if got != tc.want {
			t.Errorf("trace id %s decision=%v want=%v", tc.name, got, tc.want)
		}
	}
}

var _ pipeline.Metrics = (*PrometheusMetrics)(nil)
