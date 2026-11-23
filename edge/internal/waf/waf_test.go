package waf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	duplicate := strings.NewReader(`- id: same
  phase: request
  targets: [path]
  pattern: 'first'
  severity: error
  paranoia: 1
  tags: [owasp-a01]
- id: same
  phase: request
  targets: [path]
  pattern: 'second'
  severity: error
  paranoia: 1
  tags: [owasp-a01]
`)
	if _, err := LoadYAML(duplicate, 256); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("duplicate rule ID accepted: %v", err)
	}
	oversized := strings.NewReader(fmt.Sprintf("- id: long\n  phase: request\n  targets: [path]\n  pattern: '%s'\n  severity: error\n  paranoia: 1\n  tags: [owasp-a01]\n", strings.Repeat("a", 257)))
	if _, err := LoadYAML(oversized, 256); err == nil || !strings.Contains(err.Error(), "outside limit") {
		t.Fatalf("oversized RE2 accepted: %v", err)
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

type corpusSample struct {
	group, target, value string
}

func TestManagedCorpusTPRFPR(t *testing.T) {
	rules := loadManagedRules(t)
	phase, err := NewPhase(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	attacks := readCorpus(t, "attacks.tsv")
	clean := readCorpus(t, "clean.tsv")
	attackCounts := make(map[string]int)
	for _, sample := range attacks {
		attackCounts[sample.group]++
	}
	for group, count := range attackCounts {
		if count < 20 || count > 30 {
			t.Fatalf("attack group %s has %d samples; want 20..30", group, count)
		}
	}
	baselineBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "corpus", "waf", "tpr-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var baseline map[string]float64
	if err := json.Unmarshal(baselineBytes, &baseline); err != nil {
		t.Fatal(err)
	}
	fprMax := corpusThreshold(t, "WAF_FPR_MAX", 0)
	tprMin := corpusThreshold(t, "WAF_TPR_MIN", 0)
	t.Log("metric\tgroup\tparanoia\tdetected/total\trate\tbaseline\tthreshold")
	for paranoia := 1; paranoia <= 4; paranoia++ {
		attackHits := make(map[string]int)
		attackTotal := make(map[string]int)
		for _, sample := range attacks {
			attackTotal[sample.group]++
			if hasCorpusTag(phase, sample, paranoia, sample.group) {
				attackHits[sample.group]++
			}
		}
		groups := make([]string, 0, len(attackTotal))
		for group := range attackTotal {
			groups = append(groups, group)
		}
		sort.Strings(groups)
		for _, group := range groups {
			rate := float64(attackHits[group]) / float64(attackTotal[group])
			key := fmt.Sprintf("%s/%d", group, paranoia)
			minimum, ok := baseline[key]
			if !ok {
				t.Fatalf("missing recorded TPR baseline %s", key)
			}
			t.Logf("TPR\t%s\t%d\t%d/%d\t%.3f\t%.3f\t%.3f", group, paranoia, attackHits[group], attackTotal[group], rate, minimum, tprMin)
			if rate+1e-12 < minimum || rate+1e-12 < tprMin {
				t.Errorf("TPR %s paranoia %d = %.3f, below baseline %.3f or minimum %.3f", group, paranoia, rate, minimum, tprMin)
			}
		}

		cleanHits := make(map[string]int)
		cleanTotal := make(map[string]int)
		for _, sample := range clean {
			cleanTotal[sample.group]++
			if anyCorpusTag(phase, sample, paranoia) {
				cleanHits[sample.group]++
			}
		}
		cleanGroups := make([]string, 0, len(cleanTotal))
		for group := range cleanTotal {
			cleanGroups = append(cleanGroups, group)
		}
		sort.Strings(cleanGroups)
		for _, group := range cleanGroups {
			rate := float64(cleanHits[group]) / float64(cleanTotal[group])
			t.Logf("FPR\t%s\t%d\t%d/%d\t%.3f\t-\t%.3f", group, paranoia, cleanHits[group], cleanTotal[group], rate, fprMax)
			if paranoia == 1 && rate > fprMax+1e-12 {
				t.Errorf("FPR %s paranoia 1 = %.3f, exceeds configured maximum %.3f", group, rate, fprMax)
			}
		}
	}
}

func loadManagedRules(t testing.TB) []Rule {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "rulesets", "managed.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := LoadYAML(strings.NewReader(string(data)), 256)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func readCorpus(t *testing.T, name string) []corpusSample {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "..", "test", "corpus", "waf", name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close corpus %s: %v", name, err)
		}
	}()
	var samples []corpusSample
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("%s malformed corpus line %q", name, line)
		}
		samples = append(samples, corpusSample{group: parts[0], target: parts[1], value: parts[2]})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return samples
}

func corpusThreshold(t *testing.T, name string, fallback float64) float64 {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value < 0 || value > 1 {
		t.Fatalf("%s must be a decimal fraction in [0,1], got %q", name, raw)
	}
	return value
}

func hasCorpusTag(phase *Phase, sample corpusSample, paranoia int, expected string) bool {
	for _, tag := range corpusDecision(phase, sample, paranoia).Tags {
		if tag == expected {
			return true
		}
	}
	return false
}

func anyCorpusTag(phase *Phase, sample corpusSample, paranoia int) bool {
	return len(corpusDecision(phase, sample, paranoia).Tags) > 0
}

func corpusDecision(phase *Phase, sample corpusSample, paranoia int) reqctx.Decision {
	var request *http.Request
	switch sample.target {
	case "args":
		request = httptest.NewRequest(http.MethodGet, "http://edge.test/?q="+url.QueryEscape(sample.value), nil)
	case "path":
		request = httptest.NewRequest(http.MethodGet, (&url.URL{Scheme: "http", Host: "edge.test", Path: sample.value}).String(), nil)
	case "body":
		request = httptest.NewRequest(http.MethodPost, "http://edge.test/submit", strings.NewReader(sample.value))
		if strings.HasPrefix(strings.TrimSpace(sample.value), "{") {
			request.Header.Set("Content-Type", "application/json")
		} else {
			request.Header.Set("Content-Type", "text/plain")
		}
	case "ua", "header":
		request = httptest.NewRequest(http.MethodGet, "http://edge.test/", nil)
		request.Header.Set("User-Agent", sample.value)
	case "protocol":
		request = httptest.NewRequest(http.MethodGet, "http://edge.test/", nil)
		switch {
		case strings.HasPrefix(sample.value, "missing_host"):
			request.Host = ""
		case strings.HasPrefix(sample.value, "unusual_method="):
			request.Method = strings.TrimPrefix(sample.value, "unusual_method=")
		case strings.HasPrefix(sample.value, "content_length_transfer_encoding"):
			request.Header.Set("Content-Length", "1")
			request.TransferEncoding = []string{"chunked"}
		case strings.HasPrefix(sample.value, "duplicate_content_length"):
			request.Header.Add("Content-Length", "1")
			request.Header.Add("Content-Length", "2")
		default:
			panic("unrecognized protocol corpus case: " + sample.value)
		}
	default:
		panic("unrecognized corpus target: " + sample.target)
	}
	ctx := reqctx.New(request, nil, "corpus", nil)
	// Corpus scoring isolates rule coverage; budget behavior has its own test and
	// the 2 ms production budget is measured separately by the managed benchmarks.
	ctx.Site = &wafcore.Site{ID: "corpus", FailMode: "open", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: paranoia, BudgetMS: 2000}}
	decision := phase.Handle(ctx)
	reqctx.Release(ctx)
	return decision
}

func TestManagedRuleEvasionsAndProtocolFraming(t *testing.T) {
	rules := loadManagedRules(t)
	var err error
	phase, err := NewPhase(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, group, target, value string
	}{
		{"double encoded traversal", "traversal", "args", "%252e%252e%252fetc%252fpasswd"},
		{"mixed case XSS", "xss", "args", "<ScRiPt>alert(1)</sCrIpT>"},
		{"interspersed SQL comments", "sqli", "args", "1/**/UNION/**/SELECT/**/1"},
		{"unusual SQL whitespace", "sqli", "args", "UNION\tALL\n SELECT"},
		{"embedded NUL", "sqli", "args", "1\x00 UNION SELECT 1"},
		{"Unicode adjacent to XSS", "xss", "args", "İstanbul 文本 <script>alert(1)</script>"},
		{"CL plus TE smuggling", "protocol", "protocol", "content_length_transfer_encoding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !hasCorpusTag(phase, corpusSample{group: tc.group, target: tc.target, value: tc.value}, 1, tc.group) {
				t.Fatalf("managed rules did not detect %q", tc.value)
			}
		})
	}
}

func BenchmarkWAFManagedClean(b *testing.B) {
	rules := loadManagedRules(b)
	fixedNow := time.Time{}
	probePhase, err := NewPhase(rules, func() time.Time { return fixedNow })
	if err != nil {
		b.Fatal(err)
	}
	probe := reqctx.New(httptest.NewRequest(http.MethodGet, "http://shop.example/search?q=select+union+drop+in+the+dictionary", nil), nil, "bench", nil)
	probe.Site = &wafcore.Site{ID: "bench", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "medium", Paranoia: 1, BudgetMS: 2}}
	if decision := probePhase.Handle(probe); decision.Action != reqctx.ActionAllow {
		b.Fatalf("clean benchmark request was not allowed: %+v", decision)
	}
	reqctx.Release(probe)
	phase, err := NewPhase(rules, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := httptest.NewRequest(http.MethodGet, "http://shop.example/search?q=select+union+drop+in+the+dictionary", nil)
		ctx := reqctx.New(request, nil, "bench", nil)
		ctx.Site = &wafcore.Site{ID: "bench", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "medium", Paranoia: 1, BudgetMS: 2}}
		_ = phase.Handle(ctx)
		reqctx.Release(ctx)
	}
}

func BenchmarkWAFManagedEarlyExit(b *testing.B) {
	rules := loadManagedRules(b)
	fixedNow := time.Time{}
	probePhase, err := NewPhase(rules, func() time.Time { return fixedNow })
	if err != nil {
		b.Fatal(err)
	}
	probe := reqctx.New(httptest.NewRequest(http.MethodGet, "http://shop.example/search?q=UNION+SELECT+secret", nil), nil, "bench", nil)
	probe.Site = &wafcore.Site{ID: "bench", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 1, BudgetMS: 2}}
	if decision := probePhase.Handle(probe); decision.Action != reqctx.ActionBlock {
		b.Fatalf("early exit benchmark request did not block: %+v", decision)
	}
	reqctx.Release(probe)
	phase, err := NewPhase(rules, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := httptest.NewRequest(http.MethodGet, "http://shop.example/search?q=UNION+SELECT+secret", nil)
		ctx := reqctx.New(request, nil, "bench", nil)
		ctx.Site = &wafcore.Site{ID: "bench", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 1, BudgetMS: 2}}
		_ = phase.Handle(ctx)
		reqctx.Release(ctx)
	}
}
