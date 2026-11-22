package waf

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

func TestNormalizeTable(t *testing.T) {
	tests := []struct {
		name string
		in   string
		path bool
		want string
		flag func(Normalized) bool
	}{
		{"url decode repeatedly", "%252f%252e%252e%252f", false, "/../", func(n Normalized) bool { return n.DoubleEncoded }},
		{"html entity", "&lt;SCRIPT&gt;", false, "<script>", nil},
		{"nul", "a\x00b", false, "ab", func(n Normalized) bool { return n.HadNUL }},
		{"path clean", "/a/../B//c", true, "/b/c", nil},
		{"lowercase", "HeLLo", false, "hello", nil},
		{"fold whitespace", " a\t  b\n", false, "a b", nil},
		{"sql comments", "UNION/* hidden */SELECT", false, "union select", nil},
		{"traversal", "%252e%252e%252fetc", true, "../etc", func(n Normalized) bool { return n.Traversal && n.DoubleEncoded }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Normalize(tt.in, tt.path)
			if got.Value != tt.want {
				t.Fatalf("Value=%q want %q (decoded=%q)", got.Value, tt.want, got.Decoded)
			}
			if tt.flag != nil && !tt.flag(got) {
				t.Fatalf("flags not set: %+v", got)
			}
		})
	}
}

func TestLoadEmbeddedSampleRulesAndRejectInvalidRegex(t *testing.T) {
	rules, err := LoadYAML(strings.NewReader("- id: bad\n  phase: request\n  targets: [path]\n  pattern: '(a)\\1'\n  severity: error\n  paranoia: 1\n"), 256)
	if err == nil || rules != nil {
		t.Fatalf("invalid RE2 accepted: %v", err)
	}
}

func TestWAFMonitorExclusionAndBodyReplay(t *testing.T) {
	rules := []Rule{{ID: "body-xss", Phase: "request", Targets: []string{"body"}, Pattern: `<script`, Severity: "error", Paranoia: 1, Tags: []string{"xss"}}}
	phase, err := NewPhase(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "http://edge.test/submit", strings.NewReader("payload=<script>alert(1)</script>"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := reqctx.New(request, nil, "id", nil)
	ctx.Site = &wafcore.Site{ID: "site", FailMode: "open", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "high"}}
	decision := phase.Handle(ctx)
	if decision.Action != reqctx.ActionLogOnly || decision.Score != 4 {
		t.Fatalf("decision: %+v", decision)
	}
	if len(decision.Tags) != 1 || decision.Tags[0] != "xss" {
		t.Fatalf("tags: %v", decision.Tags)
	}
	if !ctx.BodyLoaded() {
		t.Fatal("body target did not load body")
	}
	if again := ctx.BodyText(); again != "payload=<script>alert(1)</script>" {
		t.Fatalf("body cache changed: %q", again)
	}
	got, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload=<script>alert(1)</script>" {
		t.Fatalf("origin body=%q", got)
	}
}

func TestWAFLazyBodyExclusionBudgetAndThreshold(t *testing.T) {
	rules := []Rule{{ID: "body", Phase: "request", Targets: []string{"body"}, Pattern: `evil`, Severity: "critical", Paranoia: 1}}
	phase, _ := NewPhase(rules, nil)
	request := httptest.NewRequest("POST", "http://edge.test/submit", strings.NewReader("evil"))
	request.Header.Set("Content-Type", "text/plain")
	ctx := reqctx.New(request, nil, "id", nil)
	ctx.Site = &wafcore.Site{ID: "s", FailMode: "open", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Exclusions: []wafcore.WAFExclusion{{RuleID: "body", Path: "/submit", Param: ""}}}}
	got := phase.Handle(ctx)
	if got.Action != reqctx.ActionAllow || ctx.BodyLoaded() {
		t.Fatalf("excluded body should be lazy; decision=%+v loaded=%v", got, ctx.BodyLoaded())
	}
	ctx.Site.WAF.Exclusions = nil
	got = phase.Handle(ctx)
	if got.Action != reqctx.ActionBlock || got.Score != 5 {
		t.Fatalf("high sensitivity threshold: %+v", got)
	}

	clock := time.Now()
	budgetPhase, _ := NewPhase(nil, func() time.Time { clock = clock.Add(3 * time.Millisecond); return clock })
	ctx2 := reqctx.New(httptest.NewRequest("GET", "http://edge.test/", nil), nil, "id", nil)
	ctx2.Site = &wafcore.Site{FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "block"}}
	got = budgetPhase.Handle(ctx2)
	if got.Action != reqctx.ActionBlock || got.RuleID != "waf_budget" {
		t.Fatalf("budget failure: %+v", got)
	}
}

func BenchmarkWAF(b *testing.B) {
	rules, err := LoadYAML(strings.NewReader("- id: sqli\n  phase: request\n  targets: [args]\n  pattern: 'union\\s+select'\n  severity: critical\n  paranoia: 1\n  prefilter: [union, select]\n"), 256)
	if err != nil {
		b.Fatal(err)
	}
	phase, err := NewPhase(rules, nil)
	if err != nil {
		b.Fatal(err)
	}
	ctx := reqctx.New(httptest.NewRequest("GET", "http://edge.test/?q=plain+text", nil), nil, "id", nil)
	ctx.Site = &wafcore.Site{ID: "s", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "medium"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := httptest.NewRequest("GET", "http://edge.test/?q=plain+text", nil)
		ctx := reqctx.New(request, nil, "id", nil)
		ctx.Site = &wafcore.Site{ID: "s", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "medium"}}
		_ = phase.Handle(ctx)
		reqctx.Release(ctx)
	}
}
