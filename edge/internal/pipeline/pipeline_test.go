package pipeline

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
)

type testPhase struct {
	name     string
	decision reqctx.Decision
}

func (p testPhase) Name() string                              { return p.name }
func (p testPhase) Handle(*reqctx.RequestCtx) reqctx.Decision { return p.decision }
func TestStopsOnTerminalAndObservesEachPhase(t *testing.T) {
	metrics := NewHistogram()
	p := New(metrics, testPhase{"access", reqctx.Decision{Action: reqctx.ActionBlock, RuleID: "r1", Phase: "access", Reason: "blocked"}}, testPhase{"waf", reqctx.Decision{Action: reqctx.ActionAllow}})
	ctx := reqctx.New(httptest.NewRequest("GET", "http://x/", nil), nil, "id", nil)
	got := p.Run(ctx)
	if !got.Terminal() || got.RuleID != "r1" {
		t.Fatalf("decision %+v", got)
	}
	metrics.ObservePhase("access", time.Millisecond)
	metrics.Blocked("block")
	metrics.LogDropped(2)
	rr := httptest.NewRecorder()
	metrics.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{"edge_phase_duration_seconds_bucket", "edge_blocked_total{action=\"block\"} 1", "edge_log_dropped_total 2"} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestSkipPhaseAndAccumulatedDecision(t *testing.T) {
	ctx := reqctx.New(httptest.NewRequest("GET", "http://x/", nil), nil, "id", nil)
	first := testPhase{"rules", reqctx.Decision{Action: reqctx.ActionAllow, Score: 2, Tags: []string{"custom"}}}
	second := testPhase{"waf", reqctx.Decision{Action: reqctx.ActionBlock, RuleID: "managed", Score: 5, Tags: []string{"waf"}}}
	p := New(nil, first, second)
	ctx.SkipPhase("waf")
	got := p.Run(ctx)
	if got.Action != reqctx.ActionAllow || got.Score != 2 || len(got.Tags) != 1 || got.Tags[0] != "custom" {
		t.Fatalf("skipped phase decision=%+v", got)
	}
}

func TestWAFEventsAreAuditedAsynchronously(t *testing.T) {
	metrics := NewHistogram()
	defer metrics.Close()
	p := New(metrics,
		testPhase{"waf", reqctx.Decision{Action: reqctx.ActionAllow, RuleID: "waf_budget", Tags: []string{AuditWAFBudgetExceeded, AuditWAFBodyTruncated, AuditWAFBodyReadTimeout}}},
	)
	ctx := reqctx.New(httptest.NewRequest("POST", "http://x/", strings.NewReader("body")), nil, "audit", nil)
	_ = p.Run(ctx)
	reqctx.Release(ctx)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		counts := metrics.AuditCounts()
		if counts[AuditWAFBudgetExceeded] == 1 && counts[AuditWAFBodyTruncated] == 1 && counts[AuditWAFBodyReadTimeout] == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("async audit events were not recorded: %v", metrics.AuditCounts())
}

type blockedAuditWriter struct {
	started chan struct{}
	release chan struct{}
}

func (w blockedAuditWriter) WriteAudit(AuditEvent) {
	select {
	case w.started <- struct{}{}:
	default:
	}
	<-w.release
}

func TestAsyncAuditDropsWhenQueueFullWithoutBlockingEmitter(t *testing.T) {
	writer := blockedAuditWriter{started: make(chan struct{}, 1), release: make(chan struct{})}
	sink := NewAsyncAuditSink(writer, 1)
	if !sink.Emit(AuditEvent{Kind: "first"}) {
		t.Fatal("first audit event dropped")
	}
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("audit worker did not start")
	}
	if !sink.Emit(AuditEvent{Kind: "queued"}) {
		t.Fatal("second event should fit bounded queue")
	}
	started := time.Now()
	if sink.Emit(AuditEvent{Kind: "overflow"}) {
		t.Fatal("full queue accepted overflow event")
	}
	if time.Since(started) > 20*time.Millisecond {
		t.Fatal("audit enqueue blocked request path")
	}
	if got := sink.Dropped(); got != 1 {
		t.Fatalf("dropped=%d want=1", got)
	}
	close(writer.release)
	sink.Close()
}
