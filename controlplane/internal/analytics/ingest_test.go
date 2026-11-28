package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
	"github.com/klauspost/compress/zstd"
)

type resolverStub struct {
	identity SiteIdentity
	err      error
	got      []string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (r *resolverStub) ResolveSite(_ context.Context, site string) (SiteIdentity, error) {
	r.got = append(r.got, site)
	return r.identity, r.err
}

func encodeBatch(t *testing.T, batch CompressedBatch) []byte {
	t.Helper()
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded := encoder.EncodeAll(raw, nil)
	if err = encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestProcessorUsesCanonicalTenantAndPlanRetention(t *testing.T) {
	siteID := "01900000-0000-7000-8000-000000000001"
	resolver := &resolverStub{identity: SiteIdentity{TenantID: "canonical-tenant", RetentionDay: 7}}
	event := wafcore.LogEvent{SchemaVersion: wafcore.LogSchemaVersion, TS: time.Now().UTC(), RequestID: "request-1", SiteID: siteID, TenantID: "attacker-tenant"}
	stats := wafcore.SiteStats1m{Minute: time.Now().UTC().Truncate(time.Minute), SiteID: siteID, TenantID: "attacker-tenant", Requests: 4}
	got, err := (Processor{Resolver: resolver}).DecodeAndAuthorize(context.Background(), encodeBatch(t, CompressedBatch{SchemaVersion: BatchSchemaVersion, Events: []wafcore.LogEvent{event}, SiteStats: []wafcore.SiteStats1m{stats}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 1 || got.Events[0].Event.TenantID != "canonical-tenant" || got.Events[0].RetentionDays != 7 {
		t.Fatalf("event identity/retention: %+v", got.Events)
	}
	if len(got.Stats) != 1 || got.Stats[0].TenantID != "canonical-tenant" {
		t.Fatalf("stats identity: %+v", got.Stats)
	}
	if len(resolver.got) != 2 || resolver.got[0] != siteID || resolver.got[1] != siteID {
		t.Fatalf("site resolver calls=%v", resolver.got)
	}
}

func TestProcessorDropsDuplicateRequestIDsWithinBatch(t *testing.T) {
	event := wafcore.LogEvent{SchemaVersion: wafcore.LogSchemaVersion, TS: time.Now().UTC(), RequestID: "duplicate", SiteID: "site", TenantID: "edge-tenant"}
	got, err := (Processor{Resolver: &resolverStub{identity: SiteIdentity{TenantID: "tenant", RetentionDay: 1}}}).DecodeAndAuthorize(context.Background(), encodeBatch(t, CompressedBatch{SchemaVersion: BatchSchemaVersion, Events: []wafcore.LogEvent{event, event}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 1 {
		t.Fatalf("duplicate request IDs inserted %d rows", len(got.Events))
	}
}

func TestProcessorRejectsInvalidSchemaAndUnknownSite(t *testing.T) {
	event := wafcore.LogEvent{SchemaVersion: wafcore.LogSchemaVersion, TS: time.Now(), RequestID: "r", SiteID: "site", TenantID: "untrusted"}
	if _, err := (Processor{Resolver: &resolverStub{identity: SiteIdentity{TenantID: "t", RetentionDay: 1}}}).DecodeAndAuthorize(context.Background(), encodeBatch(t, CompressedBatch{SchemaVersion: 99, Events: []wafcore.LogEvent{event}})); err == nil {
		t.Fatal("unsupported batch schema accepted")
	}
	resolver := &resolverStub{err: errors.New("unknown ingest site")}
	if _, err := (Processor{Resolver: resolver}).DecodeAndAuthorize(context.Background(), encodeBatch(t, CompressedBatch{SchemaVersion: BatchSchemaVersion, Events: []wafcore.LogEvent{event}})); err == nil {
		t.Fatal("event for unknown site accepted")
	}
}

func TestClickHouseWriterUsesExactInsertTablesAndRows(t *testing.T) {
	calls := 0
	stamp := time.Date(2026, time.November, 28, 12, 47, 17, 123000000, time.FixedZone("test", 7*60*60))
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.Query().Get("database") != "waf" {
			t.Errorf("request=%s %s", r.Method, r.URL)
		}
		query := r.URL.Query().Get("query")
		body, _ := io.ReadAll(r.Body)
		if calls == 1 && query != "INSERT INTO security_events FORMAT JSONEachRow" {
			t.Errorf("event query=%q", query)
		}
		if calls == 1 && !bytes.Contains(body, []byte(`"retention_days":7`)) {
			t.Errorf("event retention missing: %s", body)
		}
		if calls == 1 && !bytes.Contains(body, []byte(`"ts":"2026-11-28 05:47:17.123"`)) {
			t.Errorf("event timestamp is not ClickHouse DateTime64 JSONEachRow format: %s", body)
		}
		if calls == 2 && query != "INSERT INTO site_stats_1m FORMAT JSONEachRow" {
			t.Errorf("stats query=%q", query)
		}
		if calls == 2 && !bytes.Contains(body, []byte(`"minute":"2026-11-28 05:47:00"`)) {
			t.Errorf("stats timestamp is not ClickHouse DateTime JSONEachRow format: %s", body)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: r}, nil
	})}
	w := ClickHouseHTTP{Endpoint: "http://clickhouse.invalid:8123", Database: "waf", Client: client}
	rows := Rows{Events: []EventRow{{Event: wafcore.LogEvent{TS: stamp, TenantID: "00000000-0000-7000-8000-000000000001", SiteID: "00000000-0000-7000-8000-000000000002", ClientIP: "192.0.2.1"}, RetentionDays: 7}}, Stats: []wafcore.SiteStats1m{{Minute: stamp.Truncate(time.Minute), TenantID: "00000000-0000-7000-8000-000000000001", SiteID: "00000000-0000-7000-8000-000000000002"}}}
	if err := w.Write(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("ClickHouse insert calls=%d, want 2", calls)
	}
}

func TestClickHouseWriterReturnsFailedInsertForDeadLetter(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("insert failed")), Header: make(http.Header), Request: r}, nil
	})}
	if err := (ClickHouseHTTP{Endpoint: "http://clickhouse.invalid:8123", Client: client}).Write(context.Background(), Rows{Stats: []wafcore.SiteStats1m{{Minute: time.Now().Truncate(time.Minute)}}}); err == nil {
		t.Fatal("failed ClickHouse insert reported success")
	}
}

func TestAnalyticsQueriesAlwaysScopeByTenantAndSite(t *testing.T) {
	for _, kind := range []string{"overview", "timeseries", "top"} {
		query, err := analyticsSQL(kind, 50)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(query, "tenant_id={tenant_id:UUID}") || !strings.Contains(query, "site_id={site_id:UUID}") {
			t.Errorf("%s query lacks tenant/site predicates: %s", kind, query)
		}
	}
}

type writerStub struct {
	rows chan Rows
	err  error
}

func (w *writerStub) Write(_ context.Context, rows Rows) error {
	if w.rows != nil {
		w.rows <- rows
	}
	return w.err
}

type deadLetterStub struct{ records chan []byte }

func (d *deadLetterStub) Put(_ context.Context, payload []byte, _ error) error {
	d.records <- append([]byte(nil), payload...)
	return nil
}

func TestBatcherFlushesAndDeadLettersFailedClickHouseBatch(t *testing.T) {
	resolver := &resolverStub{identity: SiteIdentity{TenantID: "canonical", RetentionDay: 7}}
	writer := &writerStub{rows: make(chan Rows, 1), err: errors.New("clickhouse unavailable")}
	dead := &deadLetterStub{records: make(chan []byte, 1)}
	batcher := &Batcher{Processor: Processor{Resolver: resolver}, Writer: writer, DeadLetters: dead, QueueSize: 2, MaxRows: 1, FlushInterval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done, err := batcher.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	event := wafcore.LogEvent{SchemaVersion: wafcore.LogSchemaVersion, TS: time.Now(), RequestID: "r", SiteID: "site", TenantID: "untrusted"}
	if err = batcher.Enqueue(encodeBatch(t, CompressedBatch{SchemaVersion: BatchSchemaVersion, Events: []wafcore.LogEvent{event}})); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-dead.records:
		if !bytes.Contains(payload, []byte("canonical")) {
			t.Fatalf("dead letter lost authorized row: %s", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("failed batch was not dead-lettered")
	}
	if len((<-writer.rows).Events) != 1 {
		t.Fatal("batch writer did not receive event row")
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
