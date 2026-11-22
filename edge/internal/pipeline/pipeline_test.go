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
