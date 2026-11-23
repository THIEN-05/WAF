package waf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
	attacks := readCorpus(t, "heldout", "attacks.tsv")
	clean := readCorpus(t, "heldout", "clean.tsv")
	attackCounts := make(map[string]int)
	for _, sample := range attacks {
		attackCounts[sample.group]++
	}
	for group, count := range attackCounts {
		if count < 40 {
			t.Fatalf("attack group %s has %d samples; want at least 40", group, count)
		}
	}
	baselineBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "corpus", "waf", "heldout", "tpr-baseline.json"))
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
			decision := corpusDecision(phase, sample, paranoia)
			if len(decision.Tags) > 0 {
				cleanHits[sample.group]++
				t.Logf("FALSE POSITIVE\t%s\t%d\t%s\t%s\t%v", sample.group, paranoia, sample.target, sample.value, decision.Tags)
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
			if rate > fprMax+1e-12 {
				t.Errorf("FPR %s paranoia %d = %.3f, exceeds configured maximum %.3f", group, paranoia, rate, fprMax)
			}
		}
	}
	if len(clean) < 300 {
		t.Fatalf("clean corpus has %d samples; want at least 300", len(clean))
	}
}

func TestDevCorpusTPR(t *testing.T) {
	rules := loadManagedRules(t)
	phase, err := NewPhase(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	attacks := readCorpus(t, "dev", "attacks.tsv")
	baselineBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "corpus", "waf", "dev", "tpr-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	var baseline map[string]float64
	if err := json.Unmarshal(baselineBytes, &baseline); err != nil {
		t.Fatal(err)
	}
	t.Log("DEV metric\tgroup\tparanoia\tdetected/total\trate\tbaseline")
	for paranoia := 1; paranoia <= 4; paranoia++ {
		hits, totals := map[string]int{}, map[string]int{}
		for _, sample := range attacks {
			totals[sample.group]++
			if hasCorpusTag(phase, sample, paranoia, sample.group) {
				hits[sample.group]++
			}
		}
		groups := make([]string, 0, len(totals))
		for group := range totals {
			groups = append(groups, group)
		}
		sort.Strings(groups)
		for _, group := range groups {
			rate := float64(hits[group]) / float64(totals[group])
			minimum, ok := baseline[fmt.Sprintf("%s/%d", group, paranoia)]
			if !ok {
				t.Errorf("missing dev baseline for %s/%d", group, paranoia)
			}
			t.Logf("DEV TPR\t%s\t%d\t%d/%d\t%.3f\t%.3f", group, paranoia, hits[group], totals[group], rate, minimum)
			if rate+1e-12 < minimum {
				t.Errorf("dev TPR %s paranoia %d = %.3f below baseline %.3f", group, paranoia, rate, minimum)
			}
		}
	}
}

func TestAttackMutations(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	attacks := readCorpus(t, "dev", "attacks.tsv")
	var total, caught int
	var misses []string
	for _, sample := range attacks {
		if sample.group != "sqli" && sample.group != "xss" && sample.group != "rce" && sample.group != "ssrf" {
			continue
		}
		encoded := strings.ReplaceAll(url.QueryEscape(sample.value), "+", "%20")
		doubleEncoded := strings.ReplaceAll(url.QueryEscape(encoded), "+", "%20")
		mutations := []string{encoded, doubleEncoded}
		switch sample.group {
		case "sqli":
			mutations = append(mutations, strings.ToUpper(sample.value), "雪"+sample.value)
			if strings.Contains(sample.value, " ") {
				mutations = append(mutations, strings.ReplaceAll(sample.value, " ", "/**/"), strings.ReplaceAll(sample.value, " ", "\t"))
			}
			if strings.Contains(sample.value, "=") {
				mutations = append(mutations, strings.ReplaceAll(sample.value, "=", " LIKE "))
			}
		case "xss":
			variant := strings.NewReplacer("<script", "<ScRiPt", "</script", "</ScRiPt", "onerror", "OnErRoR", "onload", "OnLoAd", "onfocus", "OnFoCuS", "onbegin", "OnBeGiN", "ontoggle", "OnToGgLe").Replace(sample.value)
			mutations = append(mutations, variant, strings.ReplaceAll(sample.value, " ", "\t"))
		case "rce":
			mutations = append(mutations, "雪"+sample.value, strings.ReplaceAll(sample.value, " ", "\t"))
		case "ssrf":
			mutations = append(mutations, strings.ToUpper(sample.value), "雪"+sample.value)
		}
		for _, mutation := range mutations {
			total++
			candidate := corpusSample{group: sample.group, target: "rawargs", value: mutation}
			if hasCorpusTag(phase, candidate, 1, sample.group) {
				caught++
			} else {
				misses = append(misses, sample.group+"\t"+mutation)
			}
		}
	}
	rate := float64(caught) / float64(total)
	t.Logf("MUTATION caught=%d/%d rate=%.3f", caught, total, rate)
	for _, miss := range misses {
		t.Logf("MUTATION MISS\t%s", miss)
	}
}

func TestNewManagedRulesPositiveNegative(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ id, group, target, positive, negative string }{
		{"waf-sqli-heldout-001", "sqli", "args", "name=' OR 9=9", "name=order status for report"},
		{"waf-xss-heldout-001", "xss", "args", "<svg><animate onbegin=alert(1)>", "SVG animation event documentation"},
		{"waf-rce-heldout-001", "rce", "args", "cmd=%0a/usr/bin/id", "python code prints hello"},
		{"waf-ssrf-heldout-001", "ssrf", "args", "url=http://[::1]:8080/admin", "url=http://203.0.113.10/public"},
		{"waf-sensitive-files-heldout-001", "sensitive", "path", "/actuator/env", "/.well-known/security.txt"},
		{"waf-scanner-ua-heldout-001", "scanner", "ua", "Mozilla/5.0 WPScan/3.8", "Mozilla/5.0 Chrome/130"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			positive := corpusDecision(phase, corpusSample{group: tc.group, target: tc.target, value: tc.positive}, 1)
			if !containsString(positive.Tags, tc.group) {
				t.Fatalf("positive sample missed: %+v", positive)
			}
			negative := corpusDecision(phase, corpusSample{group: tc.group, target: tc.target, value: tc.negative}, 1)
			if containsString(negative.Tags, tc.group) {
				t.Fatalf("negative sample matched: %+v", negative)
			}
		})
	}
}

func TestWorstCaseShapesTakeConfiguredFailMode(t *testing.T) {
	rules := loadManagedRules(t)
	for _, shape := range []string{"200_params", "repeated_aho", "deep_json", "multipart_many_parts"} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(shape+"_"+mode, func(t *testing.T) {
				clock := time.Time{}
				phase, err := NewPhase(rules, func() time.Time { clock = clock.Add(time.Millisecond); return clock })
				if err != nil {
					t.Fatal(err)
				}
				var request *http.Request
				switch shape {
				case "200_params":
					var q strings.Builder
					for i := 0; i < 200; i++ {
						if i > 0 {
							q.WriteByte('&')
						}
						fmt.Fprintf(&q, "p%d=select+union+membership+plain", i)
					}
					request = httptest.NewRequest(http.MethodGet, "http://edge.test/?"+q.String(), nil)
				case "repeated_aho":
					request = httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(strings.Repeat("select union membership script alert ", 220)))
					request.Header.Set("Content-Type", "text/plain")
				case "deep_json":
					request = httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader("{"+strings.Repeat(`"a":[{`, 1200)+`"x":"ok"`+strings.Repeat("}]", 1200)+"}"))
					request.Header.Set("Content-Type", "application/json")
				case "multipart_many_parts":
					var b strings.Builder
					for i := 0; i < 120; i++ {
						fmt.Fprintf(&b, "--b\r\nContent-Disposition: form-data; name=\"p%d\"\r\n\r\nplain\r\n", i)
					}
					b.WriteString("--b--\r\n")
					request = httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(b.String()))
					request.Header.Set("Content-Type", "multipart/form-data; boundary=b")
				}
				ctx := reqctx.New(request, nil, "budget", nil)
				ctx.Entitlements.MaxBodyBytes = 64 * 1024
				ctx.Site = &wafcore.Site{ID: "s", FailMode: mode, WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 4, BodyLimitKB: 64, BudgetMS: 2}}
				decision := phase.Handle(ctx)
				want := reqctx.ActionAllow
				if mode == "closed" {
					want = reqctx.ActionBlock
				}
				if decision.RuleID != "waf_budget" || decision.Action != want || !containsString(decision.Tags, "waf.budget_exceeded") {
					t.Fatalf("shape=%s mode=%s decision=%+v", shape, mode, decision)
				}
				reqctx.Release(ctx)
			})
		}
	}
}

type delayedBody struct {
	data    []byte
	delayed bool
}

func (r *delayedBody) Read(p []byte) (int, error) {
	if !r.delayed {
		r.delayed = true
		time.Sleep(3 * time.Millisecond)
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
func (r *delayedBody) Close() error { return nil }

func TestWorstCaseBodyLimitsAndBudgetFailMode(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kb := range []int{8, 64, 256} {
		for _, failMode := range []string{"open", "closed"} {
			t.Run(fmt.Sprintf("body_%dKB_fail_%s", kb, failMode), func(t *testing.T) {
				body := &delayedBody{data: []byte(strings.Repeat("a", kb*1024))}
				r := httptest.NewRequest(http.MethodPost, "http://edge.test/submit", nil)
				r.Body = body
				r.Header.Set("Content-Type", "text/plain")
				ctx := reqctx.New(r, nil, "worst-case", nil)
				ctx.Entitlements.MaxBodyBytes = kb * 1024
				ctx.Site = &wafcore.Site{ID: "s", FailMode: failMode, WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 1, BodyLimitKB: kb, BudgetMS: 2}}
				started := time.Now()
				decision := phase.Handle(ctx)
				elapsed := time.Since(started)
				if !ctx.BodyLoaded() || elapsed < 2*time.Millisecond {
					t.Fatalf("body was not read within enforced budget path: loaded=%v elapsed=%s", ctx.BodyLoaded(), elapsed)
				}
				if got := len(ctx.BodyText()); got != kb*1024 || ctx.BodyTruncated() {
					t.Fatalf("body boundary: got %d bytes truncated=%v, want exact %d-byte body", got, ctx.BodyTruncated(), kb*1024)
				}
				want := reqctx.ActionAllow
				if failMode == "closed" {
					want = reqctx.ActionBlock
				}
				if decision.Action != want || decision.RuleID != "waf_budget" {
					t.Fatalf("budget decision=%+v want action=%v", decision, want)
				}
				if !strings.Contains(decision.Reason, "budget exceeded") {
					t.Fatalf("budget reason missing: %+v", decision)
				}
				if !containsString(decision.Tags, "waf.budget_exceeded") {
					t.Fatalf("budget tag missing: %+v", decision)
				}
				reqctx.Release(ctx)
			})
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestWAFRequestContextsDoNotAccumulate(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	run := func(n int) {
		for i := 0; i < n; i++ {
			r := httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(strings.Repeat("plain", 1024)))
			r.Header.Set("Content-Type", "text/plain")
			c := reqctx.New(r, nil, "leak", nil)
			c.Site = &wafcore.Site{ID: "s", WAF: wafcore.WAFConfig{Mode: "monitor", BodyLimitKB: 8, BudgetMS: 2000}}
			_ = phase.Handle(c)
			reqctx.Release(c)
		}
	}
	run(100)
	runtime.GC()
	var before, runtimeAfter runtime.MemStats
	runtime.ReadMemStats(&before)
	run(3000)
	runtime.GC()
	runtime.ReadMemStats(&runtimeAfter)
	if runtimeAfter.HeapAlloc > before.HeapAlloc+4*1024*1024 {
		t.Fatalf("heap grew beyond bounded request working set: before=%d after=%d", before.HeapAlloc, runtimeAfter.HeapAlloc)
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

func readCorpus(t *testing.T, set, name string) []corpusSample {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "..", "test", "corpus", "waf", set, name))
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
		value := strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\t`, "\t").Replace(parts[2])
		samples = append(samples, corpusSample{group: parts[0], target: parts[1], value: value})
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

func corpusDecision(phase *Phase, sample corpusSample, paranoia int) reqctx.Decision {
	var request *http.Request
	var body io.Reader
	switch sample.target {
	case "args":
		request = httptest.NewRequest(http.MethodGet, "http://edge.test/?q="+url.QueryEscape(sample.value), nil)
	case "rawargs":
		request = httptest.NewRequest(http.MethodGet, "http://edge.test/", nil)
		request.URL.RawQuery = "q=" + strings.NewReplacer(" ", "%20", "#", "%23", ";", "%3B", "&", "%26").Replace(sample.value)
	case "path":
		pathValue, query, _ := strings.Cut(sample.value, "?")
		u := (&url.URL{Scheme: "http", Host: "edge.test", Path: pathValue, RawQuery: query}).String()
		request = httptest.NewRequest(http.MethodGet, u, nil)
	case "body", "json", "xml", "multipart", "form":
		contentType := "text/plain"
		switch sample.target {
		case "json":
			contentType = "application/json"
			encoded, _ := json.Marshal(map[string]string{"input": sample.value})
			body = bytes.NewReader(encoded)
		case "xml":
			contentType = "application/xml"
			body = strings.NewReader("<root><input>" + sample.value + "</input></root>")
		case "form":
			contentType = "application/x-www-form-urlencoded"
			body = strings.NewReader("input=" + url.QueryEscape(sample.value))
		case "multipart":
			var data bytes.Buffer
			writer := multipart.NewWriter(&data)
			_ = writer.WriteField("input", sample.value)
			_ = writer.Close()
			contentType = writer.FormDataContentType()
			body = bytes.NewReader(data.Bytes())
		default:
			body = strings.NewReader(sample.value)
		}
		request = httptest.NewRequest(http.MethodPost, "http://edge.test/submit", body)
		request.Header.Set("Content-Type", contentType)
	case "ua", "header":
		request = httptest.NewRequest(http.MethodGet, "http://edge.test/", nil)
		request.Header.Set("User-Agent", sample.value)
	case "cookie":
		request = httptest.NewRequest(http.MethodGet, "http://edge.test/", nil)
		request.Header.Set("Cookie", "input="+strings.ReplaceAll(sample.value, " ", "%20"))
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

func BenchmarkWAFWorstCase(b *testing.B) {
	rules := loadManagedRules(b)
	phase, err := NewPhase(rules, nil)
	if err != nil {
		b.Fatal(err)
	}
	for _, kb := range []int{8, 64, 256} {
		for _, shape := range []string{"repeated_aho", "deep_json", "multipart"} {
			b.Run(fmt.Sprintf("%s_%dKB", shape, kb), func(b *testing.B) {
				limit := kb * 1024
				var payload string
				contentType := "text/plain"
				switch shape {
				case "repeated_aho":
					payload = repeatToLimit("select union membership script alert plain ", limit)
				case "deep_json":
					contentType = "application/json"
					payload = "{" + strings.Repeat(`"a":[{`, limit/6) + `"x":"ok"` + strings.Repeat("}]", limit/6) + "}"
				case "multipart":
					contentType = "multipart/form-data; boundary=bench-boundary"
					payload = repeatToLimit("--bench-boundary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nplain-field\r\n", limit)
				}
				b.ReportAllocs()
				b.SetBytes(int64(limit))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r := httptest.NewRequest(http.MethodPost, "http://edge.test/submit", strings.NewReader(payload))
					r.Header.Set("Content-Type", contentType)
					c := reqctx.New(r, nil, "bench", nil)
					c.Entitlements.MaxBodyBytes = limit
					c.Site = &wafcore.Site{ID: "bench", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 4, BodyLimitKB: kb, BudgetMS: 2}}
					_ = phase.Handle(c)
					reqctx.Release(c)
				}
			})
		}
	}
	b.Run("200_params", func(b *testing.B) {
		var query strings.Builder
		for i := 0; i < 200; i++ {
			if i > 0 {
				query.WriteByte('&')
			}
			fmt.Fprintf(&query, "p%d=%s", i, url.QueryEscape("select union membership and alert settings"))
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r := httptest.NewRequest(http.MethodGet, "http://edge.test/search?"+query.String(), nil)
			c := reqctx.New(r, nil, "bench", nil)
			c.Site = &wafcore.Site{ID: "bench", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 4, BudgetMS: 2}}
			_ = phase.Handle(c)
			reqctx.Release(c)
		}
	})
}

func repeatToLimit(value string, limit int) string {
	if limit <= 0 || value == "" {
		return ""
	}
	return strings.Repeat(value, (limit+len(value)-1)/len(value))[:limit]
}
