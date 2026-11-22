package rules

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

func rulesSnapshot(rules ...wafcore.Rule) *wafcore.Snapshot {
	return &wafcore.Snapshot{Version: 1, Sites: []wafcore.Site{{ID: "s", Rules: rules}}}
}

func ruleContext() *reqctx.RequestCtx {
	c := reqctx.New(httptest.NewRequest("GET", "http://edge.test/admin", nil), nil, "id", nil)
	c.Site = &wafcore.Site{ID: "s"}
	return c
}

func TestRulesPriorityExpiryTagSkipAndLogMode(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expired := now
	p, err := NewPhase(rulesSnapshot(
		wafcore.Rule{ID: "expired", Priority: 0, Expression: "true == true", Action: "block", ExpiresAt: &expired},
		wafcore.Rule{ID: "log", Priority: 1, Expression: "true == true", Action: "block", Mode: "log"},
		wafcore.Rule{ID: "tag", Priority: 2, Expression: "true == true", Action: "tag", Tag: "known"},
		wafcore.Rule{ID: "skip", Priority: 3, Expression: "true == true", Action: "skip", Phase: "waf"},
	), nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx := ruleContext()
	got := p.Handle(ctx)
	if got.Action != reqctx.ActionAllow || !ctx.PhaseSkipped("waf") {
		t.Fatalf("decision=%+v", got)
	}
	if len(ctx.Tags()) != 1 || ctx.Tags()[0] != "known" {
		t.Fatalf("tags=%v", ctx.Tags())
	}
}

func TestRulesRateLimitActionUsesNamedPolicy(t *testing.T) {
	limiter := &testRateLimit{decision: reqctx.Decision{Action: reqctx.ActionRateLimited, RuleID: "policy", Reason: "exceeded"}}
	p, err := NewPhase(rulesSnapshot(wafcore.Rule{ID: "custom-limit", Expression: "true == true", Action: "rate_limit", Policy: "login"}), limiter, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Handle(ruleContext())
	if limiter.policy != "login" || got.Action != reqctx.ActionRateLimited || got.RuleID != "custom-limit" || got.Phase != "rules" {
		t.Fatalf("policy=%q decision=%+v", limiter.policy, got)
	}
}

type testRateLimit struct {
	policy   string
	decision reqctx.Decision
}

func (t *testRateLimit) HandlePolicy(_ *reqctx.RequestCtx, policy string) reqctx.Decision {
	t.policy = policy
	return t.decision
}

func TestRulesSortPriorityAndBodyLazy(t *testing.T) {
	p, err := NewPhase(rulesSnapshot(
		wafcore.Rule{ID: "later", Priority: 20, Expression: "true == true", Action: "block"},
		wafcore.Rule{ID: "earlier", Priority: 1, Expression: "http.path == '/admin'", Action: "challenge"},
	), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := ruleContext()
	got := p.Handle(ctx)
	if got.Action != reqctx.ActionChallenge || got.RuleID != "earlier" {
		t.Fatalf("priority decision=%+v", got)
	}
	bodyRule, err := NewPhase(rulesSnapshot(wafcore.Rule{ID: "body", Expression: "http.body contains 'x'", Action: "block"}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx = reqctx.New(httptest.NewRequest("GET", "http://edge.test/admin", nil), nil, "id", nil)
	ctx.Site = &wafcore.Site{ID: "s"}
	ctx.SkipPhase("rules")
	_ = bodyRule.Handle(ctx)
	if ctx.BodyLoaded() {
		t.Fatal("skipped rules phase must not read body")
	}
}

func TestBodyRuleReadsOnceAndReplaysOriginBody(t *testing.T) {
	request := httptest.NewRequest("POST", "http://edge.test/submit", strings.NewReader("secret-value"))
	p, err := NewPhase(rulesSnapshot(wafcore.Rule{ID: "body", Expression: "http.body contains 'secret'", Action: "log"}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := reqctx.New(request, nil, "id", nil)
	ctx.Site = &wafcore.Site{ID: "s"}
	got := p.Handle(ctx)
	if got.Action != reqctx.ActionLogOnly || !ctx.BodyLoaded() {
		t.Fatalf("decision=%+v loaded=%v", got, ctx.BodyLoaded())
	}
	if ctx.BodyText() != "secret-value" {
		t.Fatalf("cached body mismatch")
	}
	replayed, err := io.ReadAll(request.Body)
	if err != nil || string(replayed) != "secret-value" {
		t.Fatalf("replayed=%q err=%v", replayed, err)
	}
}

func BenchmarkRules(b *testing.B) {
	rules := make([]wafcore.Rule, 128)
	for i := range rules {
		rules[i] = wafcore.Rule{ID: "r", Priority: i, Expression: "http.path starts_with '/admin'", Action: "log"}
	}
	p, err := NewPhase(rulesSnapshot(rules...), nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	ctx := ruleContext()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Handle(ctx)
	}
	b.ReportMetric(float64(b.N*len(rules))/b.Elapsed().Seconds(), "rules/s")
}
