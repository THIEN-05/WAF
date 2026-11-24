package waf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	"sync"
	"sync/atomic"
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
	budgetPhase, _ := NewPhase(nil, func() time.Time { clock = clock.Add(60 * time.Millisecond); return clock })
	ctx2 := reqctx.New(httptest.NewRequest("GET", "http://edge.test/", nil), nil, "id", nil)
	ctx2.Site = &wafcore.Site{FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "block"}}
	got = budgetPhase.Handle(ctx2)
	if got.Action != reqctx.ActionBlock || got.RuleID != "waf_budget" {
		t.Fatalf("budget failure: %+v", got)
	}
}

func BenchmarkWAF(b *testing.B) {
	rules, err := LoadYAML(strings.NewReader("- id: sqli\n  phase: request\n  targets: [args]\n  pattern: 'union\\s+select'\n  severity: critical\n  paranoia: 1\n  tags: [owasp-sqli]\n  prefilter: [union, select]\n"), 256)
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

func TestWAFCorpusMetrics(t *testing.T) {
	rules := loadManagedRules(t)
	phase, err := NewPhase(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	corpusDir := corpusDirectory(t)
	attackFile, cleanFile := "attacks-v2.tsv", "clean-v2.tsv"
	if os.Getenv("WAF_CORPUS_DIR") != "" {
		attackFile, cleanFile = "attacks.tsv", "clean.tsv"
	}
	attacks := readCorpusFile(t, corpusDir, attackFile)
	clean := readCorpusFile(t, corpusDir, cleanFile)
	attackCounts := make(map[string]int)
	for _, sample := range attacks {
		attackCounts[sample.group]++
	}
	for group, count := range attackCounts {
		if count < 40 {
			t.Fatalf("attack group %s has %d samples; want at least 40", group, count)
		}
	}
	fprMax := corpusThreshold(t, "WAF_FPR_MAX", 0)
	tprMin := corpusThreshold(t, "WAF_TPR_MIN", 0)
	label := "DEV"
	if os.Getenv("WAF_CORPUS_DIR") != "" {
		label = "EXTERNAL"
	}
	t.Logf("%s corpus=%s attacks=%d clean=%d", label, corpusDir, len(attacks), len(clean))
	t.Log("metric\tgroup\tparanoia\tdetected/total\trate\tthreshold")
	for paranoia := 1; paranoia <= 4; paranoia++ {
		attackHits := make(map[string]int)
		attackTotal := make(map[string]int)
		for _, sample := range attacks {
			attackTotal[sample.group]++
			if hasCorpusTag(phase, sample, paranoia, sample.group) {
				attackHits[sample.group]++
			} else if paranoia == 1 {
				t.Logf("%s MISS\t%s\t%s\t%q", label, sample.group, sample.target, sample.value)
			}
		}
		groups := make([]string, 0, len(attackTotal))
		for group := range attackTotal {
			groups = append(groups, group)
		}
		sort.Strings(groups)
		for _, group := range groups {
			rate := float64(attackHits[group]) / float64(attackTotal[group])
			t.Logf("%s TPR\t%s\t%d\t%d/%d\t%.3f\t%.3f", label, group, paranoia, attackHits[group], attackTotal[group], rate, tprMin)
			if tprMin > 0 && rate+1e-12 < tprMin {
				t.Errorf("%s TPR %s paranoia %d = %.3f, below configured minimum %.3f", strings.ToLower(label), group, paranoia, rate, tprMin)
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
			t.Logf("%s FPR\t%s\t%d\t%d/%d\t%.3f\t%.3f", label, group, paranoia, cleanHits[group], cleanTotal[group], rate, fprMax)
			if rate > fprMax+1e-12 {
				t.Errorf("FPR %s paranoia %d = %.3f, exceeds configured maximum %.3f", group, paranoia, rate, fprMax)
			}
		}
	}
	if len(clean) < 300 {
		t.Fatalf("clean corpus has %d samples; want at least 300", len(clean))
	}
}

func corpusDirectory(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("WAF_CORPUS_DIR"); dir != "" {
		return dir
	}
	return filepath.Join("..", "..", "..", "test", "corpus", "waf", "dev")
}

func readCorpusFile(t *testing.T, dir, name string) []corpusSample {
	t.Helper()
	file, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("open corpus %s: %v", filepath.Join(dir, name), err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close external corpus %s: %v", name, err)
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

func TestDevCorpusTPR(t *testing.T) {
	rules := loadManagedRules(t)
	phase, err := NewPhase(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	attacks := readCorpus(t, "dev", "attacks.tsv")
	t.Log("LEGACY DEV metric\tgroup\tparanoia\tdetected/total\trate")
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
			t.Logf("LEGACY DEV TPR\t%s\t%d\t%d/%d\t%.3f", group, paranoia, hits[group], totals[group], rate)
		}
	}
}

func TestAttackMutations(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	attacks := readCorpus(t, "dev", "attacks-v2.tsv")
	var caughtBaseTotal, caughtBaseHits, missedBaseTotal, missedBaseHits int
	var misses []string
	for _, sample := range attacks {
		if sample.group == "protocol" {
			continue
		}
		baseDetected := hasCorpusTag(phase, sample, 1, sample.group)
		encoded := strings.ReplaceAll(url.QueryEscape(sample.value), "+", "%20")
		doubleEncoded := strings.ReplaceAll(url.QueryEscape(encoded), "+", "%20")
		mutations := []string{encoded, doubleEncoded}
		switch sample.group {
		case "sqli":
			mutations = append(mutations, strings.ToUpper(sample.value))
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
			mutations = append(mutations, strings.ReplaceAll(sample.value, " ", "\t"))
		case "ssrf":
			mutations = append(mutations, strings.ToUpper(sample.value))
		default:
			if strings.Contains(sample.value, " ") {
				mutations = append(mutations, strings.ReplaceAll(sample.value, " ", "\t"))
			}
		}
		for _, mutation := range mutations {
			candidate := corpusSample{group: sample.group, target: sample.target, value: mutation}
			got := hasCorpusTag(phase, candidate, 1, sample.group)
			if baseDetected {
				caughtBaseTotal++
				if got {
					caughtBaseHits++
				}
			} else {
				missedBaseTotal++
				if got {
					missedBaseHits++
				}
			}
			if !got {
				misses = append(misses, fmt.Sprintf("%s\tbase_detected=%v\t%s\t%q", sample.group, baseDetected, sample.target, mutation))
			}
		}
	}
	ratio := func(hits, total int) float64 {
		if total == 0 {
			return 0
		}
		return float64(hits) / float64(total)
	}
	t.Logf("MUTATION from_caught_samples=%d/%d rate=%.3f", caughtBaseHits, caughtBaseTotal, ratio(caughtBaseHits, caughtBaseTotal))
	t.Logf("MUTATION from_missed_samples=%d/%d rate=%.3f", missedBaseHits, missedBaseTotal, ratio(missedBaseHits, missedBaseTotal))
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
		{"waf-sqli-p4c-001", "sqli", "args", "name=' OR 9=9", "name=order status for report"},
		{"waf-xss-p4c-001", "xss", "args", "<svg><animate onbegin=alert(1)>", "SVG animation event documentation"},
		{"waf-rce-p4c-001", "rce", "args", "cmd=%0a/usr/bin/id", "python code prints hello"},
		{"waf-ssrf-p4c-001", "ssrf", "args", "url=http://[::1]:8080/admin", "url=http://203.0.113.10/public"},
		{"waf-sensitive-files-p4c-001", "sensitive", "path", "/actuator/env", "/.well-known/security.txt"},
		{"waf-scanner-ua-p4c-001", "scanner", "ua", "Mozilla/5.0 WPScan/3.8", "Mozilla/5.0 Chrome/130"},
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

func TestParanoiaRulesHaveLevelSpecificPositiveAndNegativeCases(t *testing.T) {
	rules := loadManagedRules(t)
	cases := []struct{ id, tag, target, positive, negative string }{
		{"waf-sqli-p2-001", "sqli-boolean", "args", "q=1 OR name RLIKE name", "q=search for RLIKE documentation"},
		{"waf-sqli-p3-001", "sqli-union", "args", "q=1 UNION DISTINCT SELECT email FROM accounts", "q=union distinct names in a list"},
		{"waf-sqli-p4-001", "sqli-exfiltration", "args", "q=INTO DUMPFILE /tmp/out", "q=download an outfile report"},
		{"waf-rce-p2-001", "shell-enumeration", "args", "cmd=;printf PATH=$PATH", "cmd=printf PATH in a shell tutorial"},
		{"waf-rce-p3-001", "shell-pipeline", "args", "cmd=curl x.invalid | sh", "cmd=curl a page and print a result"},
		{"waf-rce-p4-001", "shell-obfuscation", "args", "cmd=base64 -d /tmp/x | sh; chmod +x /bin/x", "cmd=base64 -d file in a guide"},
		{"waf-traversal-p2-001", "encoded-traversal", "args", "file=..%2fsecret.txt", "file=report%2fsummary.txt"},
		{"waf-traversal-p3-001", "unicode-traversal", "args", "file=%u002e%u002e%2fsecret", "file=normal-image.png"},
		{"waf-traversal-p4-001", "lfi", "path", "/../etc/passwd", "/etc/hosts.example"},
		{"waf-deser-p2-001", "serialized-object", "args", "v=!!python/object:builtins.object", "v=python object serialization guide"},
		{"waf-deser-p3-001", "gadget-chain", "args", "v=payload.__reduce__()", "v=reduce the collection size"},
		{"waf-deser-p4-001", "gadget-chain", "args", "v=java.security.SignedObject", "v=java security signed objects documentation"},
	}
	byID := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			rule, ok := byID[tc.id]
			if !ok {
				t.Fatalf("rule not loaded: %s", tc.id)
			}
			phase, err := NewPhase([]Rule{rule}, nil)
			if err != nil {
				t.Fatal(err)
			}
			positive := corpusDecision(phase, corpusSample{group: tc.tag, target: tc.target, value: tc.positive}, rule.Paranoia)
			if !containsString(positive.Tags, tc.tag) {
				t.Fatalf("level %d positive did not match: %+v", rule.Paranoia, positive)
			}
			negative := corpusDecision(phase, corpusSample{group: tc.tag, target: tc.target, value: tc.negative}, rule.Paranoia)
			if containsString(negative.Tags, tc.tag) {
				t.Fatalf("level %d negative matched: %+v", rule.Paranoia, negative)
			}
		})
	}
}

func TestP4DWeakGroupRulesHavePositiveAndNegativeCases(t *testing.T) {
	rules := loadManagedRules(t)
	phase, err := NewPhase(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, group, target, positive, negative string
	}{
		{"sqli numeric comparison", "sqli", "args", "id=7 OR 8>2", "id=7 or higher is allowed"},
		{"sqli having tautology", "sqli", "args", "id=7 HAVING 6=6", "id=7 having six records"},
		{"rce encoded newline", "rce", "args", "cmd=x%0aid", "cmd=show id examples"},
		{"deserialization typed json marker", "deserialization", "json", `{"$type":"System.Diagnostics.Process"}`, `{"type":"documentation"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			positive := corpusDecision(phase, corpusSample{group: tc.group, target: tc.target, value: tc.positive}, 2)
			if !containsString(positive.Tags, tc.group) {
				t.Fatalf("positive missed: %+v", positive)
			}
			negative := corpusDecision(phase, corpusSample{group: tc.group, target: tc.target, value: tc.negative}, 2)
			if containsString(negative.Tags, tc.group) {
				t.Fatalf("negative matched: %+v", negative)
			}
		})
	}
}

func TestWorstCaseShapesRespectWorkCapsAndFuse(t *testing.T) {
	rules := loadManagedRules(t)
	for _, shape := range []string{"200_params", "repeated_aho", "deep_json", "multipart_many_parts"} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(shape+"_"+mode, func(t *testing.T) {
				phase, err := NewPhase(rules, nil)
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
				ctx.Site = &wafcore.Site{ID: "s", Plan: "enterprise", Entitlements: wafcore.Entitlements{MaxBodyBytes: 256 * 1024}, FailMode: mode, WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 4, BodyLimitKB: 64, BudgetMS: 2000}}
				decision := phase.Handle(ctx)
				want := reqctx.ActionAllow
				if mode == "closed" {
					want = reqctx.ActionBlock
				}
				if containsString(decision.Tags, "waf_budget_exceeded") {
					t.Fatalf("deterministic workload must not trip wall fuse: shape=%s decision=%+v", shape, decision)
				}
				if containsString(decision.Tags, "waf_scan_truncated") && decision.Action != want && decision.Action != reqctx.ActionLogOnly {
					t.Fatalf("work cap did not follow fail mode/monitor: shape=%s mode=%s decision=%+v", shape, mode, decision)
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

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (failingBody) Close() error             { return nil }

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
				plan := "free"
				if kb == 64 {
					plan = "pro"
				}
				if kb == 256 {
					plan = "enterprise"
				}
				ctx.Site = &wafcore.Site{ID: "s", Plan: plan, Entitlements: wafcore.Entitlements{MaxBodyBytes: kb * 1024}, FailMode: failMode, WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 1, BodyLimitKB: kb, BudgetMS: 1}}
				started := time.Now()
				decision := phase.Handle(ctx)
				elapsed := time.Since(started)
				if !ctx.BodyLoaded() || elapsed < 2*time.Millisecond {
					t.Fatalf("body was not read within enforced budget path: loaded=%v elapsed=%s", ctx.BodyLoaded(), elapsed)
				}
				if got := len(ctx.BodyText()); got != kb*1024 || ctx.BodyTruncated() {
					t.Fatalf("WAF body buffer: got %d bytes truncated=%v, want complete %d-byte package scope", got, ctx.BodyTruncated(), kb*1024)
				}
				want := reqctx.ActionAllow
				if failMode == "closed" {
					want = reqctx.ActionBlock
				}
				if decision.Action != want || decision.RuleID != "waf_budget" {
					t.Fatalf("budget decision=%+v want action=%v", decision, want)
				}
				if !strings.Contains(decision.Reason, "fuse exceeded") {
					t.Fatalf("budget reason missing: %+v", decision)
				}
				if !containsString(decision.Tags, "waf_budget_exceeded") {
					t.Fatalf("budget tag missing: %+v", decision)
				}
				replayed, err := io.ReadAll(r.Body)
				if err != nil || len(replayed) != kb*1024 {
					t.Fatalf("origin replay lost body: len=%d err=%v want=%d", len(replayed), err, kb*1024)
				}
				reqctx.Release(ctx)
			})
		}
	}
}

func TestLargeBodyAttackAtPrefixCannotBeSkipped(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), func() time.Time { return time.Time{} })
	if err != nil {
		t.Fatal(err)
	}
	payload := "id=1 UNION SELECT password FROM users&" + strings.Repeat("safe=1&", 40_000)
	request := httptest.NewRequest(http.MethodPost, "http://edge.test/submit", strings.NewReader(payload))
	request.Header.Set("Content-Type", "text/plain")
	ctx := reqctx.New(request, nil, "large-body", nil)
	ctx.Entitlements.MaxBodyBytes = 256 * 1024
	ctx.Site = &wafcore.Site{ID: "s", Plan: "free", FailMode: "open", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "medium", Paranoia: 1, BodyLimitKB: 256, BudgetMS: 2}}
	decision := phase.Handle(ctx)
	if decision.Action != reqctx.ActionBlock || !containsString(decision.Tags, "sqli") {
		t.Fatalf("large body prefix escaped WAF: %+v", decision)
	}
	if !ctx.BodyTruncated() || len(ctx.BodyText()) != 8*1024 {
		t.Fatalf("large body was not bounded: truncated=%v prefix=%d", ctx.BodyTruncated(), len(ctx.BodyText()))
	}
	replayed, err := io.ReadAll(request.Body)
	if err != nil || len(replayed) != len(payload) {
		t.Fatalf("origin replay: got %d bytes err=%v want=%d", len(replayed), err, len(payload))
	}
	reqctx.Release(ctx)
}

func TestBodyTruncationScoresAndPlanFailModeDefaults(t *testing.T) {
	phase, err := NewPhase([]Rule{{ID: "body-probe", Phase: "request", Targets: []string{"body"}, Pattern: "^never-match$", Severity: "warning", Paranoia: 1}}, func() time.Time { return time.Time{} })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		plan string
		want string
	}{{plan: "free", want: "open"}, {plan: "pro", want: "closed"}} {
		t.Run(tc.plan, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://edge.test/submit", strings.NewReader(strings.Repeat("x", 20*1024)))
			request.Header.Set("Content-Type", "text/plain")
			ctx := reqctx.New(request, nil, "truncate", nil)
			ctx.Entitlements.MaxBodyBytes = 16 * 1024
			capKB := 8
			maxBytes := 8 * 1024
			if tc.plan == "pro" {
				capKB = 16
				maxBytes = 16 * 1024
			}
			ctx.Site = &wafcore.Site{ID: "s", Plan: tc.plan, Entitlements: wafcore.Entitlements{MaxBodyBytes: maxBytes}, WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "high", BodyLimitKB: capKB, TruncatedBodyScore: 3, BudgetMS: 2000}}
			decision := phase.Handle(ctx)
			if decision.RuleID != "waf_body_truncated" || decision.Score != 3 || !containsString(decision.Tags, "waf_body_truncated") {
				t.Fatalf("truncation must be an anomaly with the configured score: %+v", decision)
			}
			wantAction := reqctx.ActionBlock
			if tc.want == "open" {
				wantAction = reqctx.ActionAllow
			}
			if decision.Action != wantAction {
				t.Fatalf("truncation fail mode action=%v want %v", decision.Action, wantAction)
			}
			budgetDecision := phase.budgetFailure(ctx, 0, "test budget")
			want := reqctx.ActionAllow
			if tc.want == "closed" {
				want = reqctx.ActionBlock
			}
			if budgetDecision.Action != want {
				t.Fatalf("plan %s budget action=%v, want %v", tc.plan, budgetDecision.Action, want)
			}
			reqctx.Release(ctx)
		})
	}
}

func TestUnscannedBodyIsMarkedAsTruncated(t *testing.T) {
	phase, err := NewPhase([]Rule{{ID: "body-probe", Phase: "request", Targets: []string{"body"}, Pattern: "^never-match$", Severity: "warning", Paranoia: 1}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, contentType string
		limit             int
	}{
		{name: "scan budget consumed before body", contentType: "application/json", limit: 1},
		{name: "unsupported body media type", contentType: "application/octet-stream", limit: 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(strings.Repeat("x", 16*1024)))
			request.Header.Set("Content-Type", tc.contentType)
			ctx := reqctx.New(request, nil, "body-skip", nil)
			ctx.Entitlements.MaxBodyBytes = 16 * 1024
			ctx.Site = &wafcore.Site{ID: "s", FailMode: "open", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 1, BodyLimitKB: 16, ScanLimitBytes: tc.limit, TruncatedBodyScore: 3, BudgetMS: 2000}}
			decision := phase.Handle(ctx)
			if decision.Score != 3 || !containsString(decision.Tags, "waf_body_truncated") {
				t.Fatalf("unscanned body must carry an anomaly score and tag: %+v", decision)
			}
			if ctx.BodyLoaded() {
				t.Fatal("WAF buffered body despite skipping its scan")
			}
			reqctx.Release(ctx)
		})
	}
}

func TestBodyReadErrorIsMarkedAsTruncated(t *testing.T) {
	phase, err := NewPhase([]Rule{{ID: "body-probe", Phase: "request", Targets: []string{"body"}, Pattern: "^never-match$", Severity: "warning", Paranoia: 1}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://edge.test/submit", nil)
	request.Body = failingBody{}
	request.Header.Set("Content-Type", "text/plain")
	ctx := reqctx.New(request, nil, "body-error", nil)
	ctx.Site = &wafcore.Site{ID: "s", FailMode: "open", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 1, TruncatedBodyScore: 3}}
	decision := phase.Handle(ctx)
	if decision.RuleID != "waf_body_read_error" || decision.Score != 3 || !containsString(decision.Tags, "waf_body_truncated") || containsString(decision.Tags, "waf_budget_exceeded") {
		t.Fatalf("body read error must leave a truncation anomaly: %+v", decision)
	}
	if decision.Action != reqctx.ActionAllow {
		t.Fatalf("explicit fail-open on read error: got %v", decision.Action)
	}
	reqctx.Release(ctx)
}

func TestBodyReadTimeoutEmitsTimeoutTag(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://edge.test/", nil)
	r.Header.Set("Content-Type", "text/plain")
	ctx := reqctx.New(r, nil, "body-timeout", nil)
	ctx.Site = &wafcore.Site{ID: "s", Plan: "free", WAF: wafcore.WAFConfig{Mode: "block", BudgetMS: 2000}}
	ctx.MarkBodyReadError(context.DeadlineExceeded)
	decision := phase.Handle(ctx)
	if decision.RuleID != "waf_body_read_timeout" || decision.Action != reqctx.ActionAllow || containsString(decision.Tags, "waf_budget_exceeded") || !containsString(decision.Tags, "waf_body_truncated") || !containsString(decision.Tags, "waf_body_read_timeout") {
		t.Fatalf("body timeout decision/tags=%+v", decision)
	}
	reqctx.Release(ctx)
}

func TestScanWindowBypassMatrixAcrossTargets(t *testing.T) {
	rule := Rule{ID: "test-window-sqli", Phase: "request", Targets: []string{"path", "args", "headers", "cookies", "body"}, Pattern: `union\s+select`, Severity: "critical", Paranoia: 1, Prefilter: []string{"union", "select"}, Tags: []string{"test-sqli"}}
	phase, err := NewPhase([]Rule{rule}, nil)
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{"path", "query", "header", "cookie", "form", "json", "xml", "multipart"}
	for _, target := range targets {
		for _, offset := range []int{1, 2, 8, 60} {
			for _, placement := range []string{"middle", "end"} {
				t.Run(fmt.Sprintf("%s/%dKB/%s", target, offset, placement), func(t *testing.T) {
					pad := strings.Repeat("x", offset*1024)
					if offset == 2 {
						pad = strings.Repeat("%41", offset*1024/3) + strings.Repeat("x", offset*1024%3)
					}
					if offset == 8 {
						pad = strings.Repeat("/**/", offset*1024/4)
					}
					suffix := ""
					if placement == "middle" {
						suffix = strings.Repeat("z", offset*1024)
					}
					request := httptest.NewRequest(http.MethodGet, "http://edge.test/", nil)
					includeBody := false
					setBody := func(contentType, raw string) {
						request.Method = http.MethodPost
						request.Body = io.NopCloser(strings.NewReader(raw))
						request.ContentLength = int64(len(raw))
						request.Header.Set("Content-Type", contentType)
						includeBody = true
					}
					switch target {
					case "path":
						request.URL.Path = "/" + pad + "UNION/**/SELECT" + suffix
					case "query":
						request.URL.RawQuery = "p=" + pad + "UNION%2F**%2FSELECT" + suffix
					case "header":
						request.Header.Set("Referer", pad+"UNION/**/SELECT"+suffix)
					case "cookie":
						request.Header.Set("Cookie", "p="+pad+"UNION/**/SELECT"+suffix)
					case "form":
						setBody("application/x-www-form-urlencoded", "p="+pad+"UNION%2F**%2FSELECT"+suffix)
					case "json":
						setBody("application/json", `{"pad":"`+pad+suffix+`","q":"UNION/**/SELECT"}`)
					case "xml":
						setBody("application/xml", `<r><pad>`+pad+suffix+`</pad><q>UNION/**/SELECT</q></r>`)
					case "multipart":
						var b strings.Builder
						b.WriteString("--b\r\nContent-Disposition: form-data; name=\"pad\"\r\n\r\n" + pad + suffix + "\r\n--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nUNION/**/SELECT\r\n--b--\r\n")
						setBody("multipart/form-data; boundary=b", b.String())
					}
					ctx := reqctx.New(request, nil, "window-bypass", nil)
					ctx.Path = request.URL.Path
					ctx.Query = request.URL.RawQuery
					ctx.Site = &wafcore.Site{ID: "s", Plan: "enterprise", Entitlements: wafcore.Entitlements{MaxBodyBytes: 256 * 1024}, WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 1, BodyLimitKB: 256, BudgetMS: 2000}}
					decision := phase.Handle(ctx)
					if decision.Action != reqctx.ActionBlock || !containsString(decision.Tags, "test-sqli") {
						t.Fatalf("payload outside a regex window: body=%v decision=%+v", includeBody, decision)
					}
					reqctx.Release(ctx)
				})
			}
		}
	}
}

func TestPackageBodyCapTruncationUsesFailMode(t *testing.T) {
	phase, err := NewPhase([]Rule{{ID: "body-probe", Phase: "request", Targets: []string{"body"}, Pattern: `never-match`, Severity: "warning", Paranoia: 1, Prefilter: []string{"never"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		plan, fail string
		want       reqctx.Action
	}{{"free", "", reqctx.ActionAllow}, {"pro", "", reqctx.ActionBlock}} {
		t.Run(tc.plan, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(strings.Repeat("x", 70*1024)+"UNION SELECT"))
			request.Header.Set("Content-Type", "text/plain")
			ctx := reqctx.New(request, nil, "cap", nil)
			ctx.Site = &wafcore.Site{ID: "s", Plan: tc.plan, FailMode: tc.fail, WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "low", Paranoia: 1, BudgetMS: 2000}}
			got := phase.Handle(ctx)
			if got.Action != tc.want || !containsString(got.Tags, "waf_body_truncated") || got.RuleID != "waf_body_truncated" {
				t.Fatalf("truncated body decision=%+v want action=%v", got, tc.want)
			}
			reqctx.Release(ctx)
		})
	}
}

func TestRegexWindowLimitKeepsBodyHeadAndTail(t *testing.T) {
	phase, err := NewPhase([]Rule{{ID: "test-window-limit", Phase: "request", Targets: []string{"body"}, Pattern: `union\s+select`, Severity: "critical", Paranoia: 1, Prefilter: []string{"union", "select"}, Tags: []string{"test-sqli"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("UNION harmless documentation phrase ", 6000) + "UNION SELECT"
	r := httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	ctx := reqctx.New(r, nil, "window-limit", nil)
	ctx.Site = &wafcore.Site{ID: "s", Plan: "enterprise", Entitlements: wafcore.Entitlements{MaxBodyBytes: 256 * 1024}, FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "high", Paranoia: 1, BodyLimitKB: 256, BudgetMS: 2000}}
	got := phase.Handle(ctx)
	if got.Action != reqctx.ActionBlock || !containsString(got.Tags, "test-sqli") || !containsString(got.Tags, "waf_scan_truncated") {
		t.Fatalf("head/tail window selection missed final payload or failed closed: %+v", got)
	}
	reqctx.Release(ctx)
}

func TestLargeCleanBodiesFPR(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	falsePositives, total := 0, 0
	for paranoia := 1; paranoia <= 4; paranoia++ {
		levelFalsePositives := 0
		for i := 0; i < 30; i++ {
			contentType := "application/json"
			body := fmt.Sprintf(`{"note":"select union drop script alert are examples in documentation","id":%d,"text":"ordinary clean technical content %s"}`, i, strings.Repeat("readme ", 650))
			switch i % 4 {
			case 1:
				contentType = "application/x-www-form-urlencoded"
				body = "message=" + url.QueryEscape("O'Neil searched for select, union, drop, script and alert in a manual "+strings.Repeat("ordinary ", 400))
			case 2:
				contentType = "text/plain"
				body = "C:\\Users\\O'Neil\\Documents\\select-union-drop-script-alert.txt " + strings.Repeat("normal-upload ", 500)
			case 3:
				var data bytes.Buffer
				writer := multipart.NewWriter(&data)
				_ = writer.WriteField("readme", "select union drop script alert are ordinary words "+strings.Repeat("uploaded documentation ", 250))
				_ = writer.Close()
				contentType = writer.FormDataContentType()
				body = data.String()
			}
			r := httptest.NewRequest(http.MethodPost, "http://edge.test/api", strings.NewReader(body))
			r.Header.Set("Content-Type", contentType)
			ctx := reqctx.New(r, nil, "large-clean", nil)
			ctx.Site = &wafcore.Site{ID: "s", Plan: "free", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "high", Paranoia: paranoia, BudgetMS: 2000}}
			decision := phase.Handle(ctx)
			if decision.Score > 0 {
				falsePositives++
				levelFalsePositives++
				t.Logf("large-clean false-positive p%d sample=%d content-type=%s decision=%+v body-bytes=%d truncated=%v", paranoia, i, contentType, decision, len(body), ctx.BodyTruncated())
			}
			total++
			reqctx.Release(ctx)
		}
		t.Logf("large-clean paranoia=%d false_positive=%d/30 FPR=%.2f%%", paranoia, levelFalsePositives, float64(levelFalsePositives)*100/30)
	}
	if falsePositives > 0 {
		t.Fatalf("large clean body FPR exceeded configured 0%%: %d/%d", falsePositives, total)
	}
}

func TestWAFParallel50ReportsP99AndBudgetAction(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	const workers, perWorker = 50, 5
	latencies := make(chan int64, workers*perWorker)
	budgetFailures := make(chan reqctx.Decision, workers*perWorker)
	var attackCaught atomic.Int64
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				body := `{"message":"ordinary search for select union drop script alert","worker":` + strconv.Itoa(worker) + `,"text":"` + strings.Repeat("safe documentation ", 350) + `"}`
				wafMode := "monitor"
				if i == 0 {
					body = `{"q":"UNION SELECT password FROM users","text":"` + strings.Repeat("safe ", 200) + `"}`
					wafMode = "block"
				}
				r := httptest.NewRequest(http.MethodPost, "http://edge.test/api", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				ctx := reqctx.New(r, nil, "parallel", nil)
				ctx.Site = &wafcore.Site{ID: "s", Plan: "enterprise", Entitlements: wafcore.Entitlements{MaxBodyBytes: 256 * 1024}, FailMode: "closed", WAF: wafcore.WAFConfig{Mode: wafMode, Sensitivity: "high", Paranoia: 4, BodyLimitKB: 256}}
				started := time.Now()
				decision := phase.Handle(ctx)
				if i == 0 && decision.Action == reqctx.ActionBlock {
					attackCaught.Add(1)
				}
				latencies <- time.Since(started).Nanoseconds()
				if containsString(decision.Tags, "waf_budget_exceeded") {
					budgetFailures <- decision
				}
				reqctx.Release(ctx)
			}
		}(worker)
	}
	wg.Wait()
	close(latencies)
	close(budgetFailures)
	samples := make([]int64, 0, workers*perWorker)
	for sample := range latencies {
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	budgetCount := 0
	for decision := range budgetFailures {
		budgetCount++
		if decision.Action != reqctx.ActionBlock || !containsString(decision.Tags, "waf_budget_exceeded") {
			t.Fatalf("paid budget failure did not fail closed: %+v", decision)
		}
	}
	if budgetCount == len(samples) {
		t.Fatalf("CPU contention must not turn all 50-goroutine requests into fuse failures: %d/%d", budgetCount, len(samples))
	}
	cleanFPR := 0
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest(http.MethodPost, "http://edge.test/api", strings.NewReader(`{"message":"`+strings.Repeat("ordinary documentation ", 180)+`"}`))
		r.Header.Set("Content-Type", "application/json")
		ctx := reqctx.New(r, nil, "parallel-clean", nil)
		ctx.Site = &wafcore.Site{ID: "s", Plan: "enterprise", FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 4, BodyLimitKB: 8}}
		d := phase.Handle(ctx)
		if d.Action != reqctx.ActionAllow {
			cleanFPR++
		}
		reqctx.Release(ctx)
	}
	if cleanFPR != 0 {
		t.Fatalf("clean FPR increased under concurrent load: %d/20", cleanFPR)
	}
	if attackCaught.Load() != workers {
		t.Fatalf("prefix attack was not caught for all concurrent attackers: %d/%d", attackCaught.Load(), workers)
	}
	t.Logf("parallel-50 body=8KB p50=%d ns p99=%d ns fuse_exceeded=%d/%d clean_false_positive=%d/20 prefix_attacks_blocked=%d/%d; GOMAXPROCS=%d CPUs=%d", samples[len(samples)*50/100], samples[(len(samples)*99+99)/100-1], budgetCount, len(samples), cleanFPR, attackCaught.Load(), workers, runtime.GOMAXPROCS(0), runtime.NumCPU())
}

func TestWAFDeterministicWorkCapsDoNotBecomeWallFuseFailures(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	body := repeatToLimit("ordinary safe text ", 256*1024)
	r := httptest.NewRequest(http.MethodPost, "http://edge.test/upload", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	ctx := reqctx.New(r, nil, "work-cap", nil)
	ctx.Site = &wafcore.Site{ID: "s", Plan: "free", FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 4, BodyLimitKB: 256}}
	d := phase.Handle(ctx)
	if !containsString(d.Tags, "waf_body_truncated") {
		t.Fatalf("body beyond Free package cap must be marked truncated: %+v", d)
	}
	if containsString(d.Tags, "waf_budget_exceeded") {
		t.Fatalf("deterministic package cap must not be reported as wall fuse: %+v", d)
	}
	if d.Action != reqctx.ActionBlock {
		t.Fatalf("explicit fail-closed truncation expected block, got %+v", d)
	}
	reqctx.Release(ctx)
}

func TestWAFOverloadTierThresholds(t *testing.T) {
	cases := []struct {
		name                string
		active, procs, ewma int64
		ratio               float64
		recent              int64
		current, want       int64
	}{
		{"normal", 4, 4, 0, 0, 0, 0, 0}, {"drop-paranoia", 5, 4, 0, 0, 0, 0, 1}, {"reduce-scope", 8, 4, 0, 0, 0, 0, 2}, {"latency-paranoia", 1, 4, 12_000_000, 0, 0, 0, 1}, {"latency-scope", 1, 4, 30_000_000, 0, 0, 0, 2}, {"fuse-mode", 1, 4, 0, 0.25, 32, 0, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := overloadTier(tc.active, tc.procs, tc.ewma, tc.ratio, tc.recent, tc.current); got != tc.want {
				t.Fatalf("tier=%d want=%d", got, tc.want)
			}
		})
	}
}

func TestWAFFuseExpandsOnlyForRunnableBacklog(t *testing.T) {
	base := 100 * time.Millisecond
	if got := effectiveFuse(base, 4, 4); got != base {
		t.Fatalf("no backlog fuse=%s want=%s", got, base)
	}
	if got := effectiveFuse(base, 8, 4); got <= base {
		t.Fatalf("queued work should compensate scheduler wait, fuse=%s", got)
	}
	if got := effectiveFuse(5*time.Second, 100, 1); got > maxFuse {
		t.Fatalf("adaptive fuse exceeded hard ceiling: %s", got)
	}
}

func TestWAFFailClosedCleanTrafficUnderConcurrency(t *testing.T) {
	phase, err := NewPhase(loadManagedRules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	const workers, perWorker = 50, 5
	var wg sync.WaitGroup
	var rejected atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				r := httptest.NewRequest(http.MethodGet, "http://edge.test/search?q=ordinary+documentation", nil)
				ctx := reqctx.New(r, nil, "fail-closed-load", nil)
				ctx.Site = &wafcore.Site{ID: "s", Plan: "enterprise", FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 4}}
				d := phase.Handle(ctx)
				if d.Action == reqctx.ActionBlock && containsString(d.Tags, "waf_budget_exceeded") {
					rejected.Add(1)
				}
				reqctx.Release(ctx)
			}
		}()
	}
	wg.Wait()
	if n := rejected.Load(); n != 0 {
		t.Fatalf("load alone caused fail-closed rejection: %d/%d", n, workers*perWorker)
	}
}

func TestWAFParallel50GOMAXPROCSMatrix(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(original)
	procs := []int{2, 4, runtime.NumCPU()}
	seen := map[int]bool{}
	for _, n := range procs {
		if n < 1 || seen[n] {
			continue
		}
		seen[n] = true
		t.Run(fmt.Sprintf("gomaxprocs_%d", n), func(t *testing.T) {
			runtime.GOMAXPROCS(n)
			phase, err := NewPhase(loadManagedRules(t), nil)
			if err != nil {
				t.Fatal(err)
			}
			const workers, each = 50, 5
			var wg sync.WaitGroup
			var cleanReject, fuse atomic.Int64
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < each; i++ {
						r := httptest.NewRequest(http.MethodPost, "http://edge.test/", strings.NewReader(`{"q":"ordinary documentation `+strings.Repeat("safe ", 200)+`"}`))
						r.Header.Set("Content-Type", "application/json")
						c := reqctx.New(r, nil, "load", nil)
						c.Site = &wafcore.Site{ID: "s", Plan: "enterprise", FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "high", Paranoia: 4, BodyLimitKB: 8}}
						d := phase.Handle(c)
						if d.Action == reqctx.ActionBlock {
							cleanReject.Add(1)
						}
						if containsString(d.Tags, "waf_budget_exceeded") {
							fuse.Add(1)
						}
						reqctx.Release(c)
					}
				}()
			}
			wg.Wait()
			if cleanReject.Load() != 0 {
				t.Fatalf("clean fail-closed requests rejected=%d/%d", cleanReject.Load(), workers*each)
			}
			if fuse.Load() == workers*each {
				t.Fatalf("all clean requests hit fuse: %d", fuse.Load())
			}
			t.Logf("concurrency=50 GOMAXPROCS=%d CPUs=%d clean-fpr=%d/%d fuse=%d/%d", n, runtime.NumCPU(), cleanReject.Load(), workers*each, fuse.Load(), workers*each)
		})
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
	for _, kb := range []int{8, 64, 256} {
		for _, shape := range []string{"repeated_aho", "deep_json", "multipart"} {
			b.Run(fmt.Sprintf("%s_%dKB", shape, kb), func(b *testing.B) {
				phase, err := NewPhase(rules, nil)
				if err != nil {
					b.Fatal(err)
				}
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
				latencies := make([]int64, 0, min(b.N, 256))
				workExceeded, fuseExceeded := 0, 0
				for i := 0; i < b.N; i++ {
					started := time.Now()
					r := httptest.NewRequest(http.MethodPost, "http://edge.test/submit", strings.NewReader(payload))
					r.Header.Set("Content-Type", contentType)
					c := reqctx.New(r, nil, "bench", nil)
					c.Entitlements.MaxBodyBytes = limit
					plan := "free"
					if kb == 64 {
						plan = "pro"
					}
					if kb == 256 {
						plan = "enterprise"
					}
					c.Site = &wafcore.Site{ID: "bench", Plan: plan, Entitlements: wafcore.Entitlements{MaxBodyBytes: limit}, WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 4, BodyLimitKB: kb, BudgetMS: 2}}
					decision := phase.Handle(c)
					if containsString(decision.Tags, "waf_work_exhausted") {
						workExceeded++
					}
					if containsString(decision.Tags, "waf_budget_exceeded") {
						fuseExceeded++
					}
					reqctx.Release(c)
					if i < 256 {
						if elapsed := time.Since(started).Nanoseconds(); elapsed > 0 {
							latencies = append(latencies, elapsed)
						}
					}
				}
				reportLatencyPercentiles(b, latencies)
				b.ReportMetric(float64(workExceeded)*100/float64(b.N), "work-cap-%")
				b.ReportMetric(float64(fuseExceeded)*100/float64(b.N), "fuse-%")
			})
		}
	}
	b.Run("200_params", func(b *testing.B) {
		phase, err := NewPhase(rules, nil)
		if err != nil {
			b.Fatal(err)
		}
		var query strings.Builder
		for i := 0; i < 200; i++ {
			if i > 0 {
				query.WriteByte('&')
			}
			fmt.Fprintf(&query, "p%d=%s", i, url.QueryEscape("select union membership and alert settings"))
		}
		b.ReportAllocs()
		b.ResetTimer()
		latencies := make([]int64, 0, min(b.N, 256))
		workExceeded, fuseExceeded := 0, 0
		for i := 0; i < b.N; i++ {
			started := time.Now()
			r := httptest.NewRequest(http.MethodGet, "http://edge.test/search?"+query.String(), nil)
			c := reqctx.New(r, nil, "bench", nil)
			c.Site = &wafcore.Site{ID: "bench", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 4, BudgetMS: 2}}
			decision := phase.Handle(c)
			if containsString(decision.Tags, "waf_work_exhausted") {
				workExceeded++
			}
			if containsString(decision.Tags, "waf_budget_exceeded") {
				fuseExceeded++
			}
			reqctx.Release(c)
			if i < 256 {
				if elapsed := time.Since(started).Nanoseconds(); elapsed > 0 {
					latencies = append(latencies, elapsed)
				}
			}
		}
		reportLatencyPercentiles(b, latencies)
		b.ReportMetric(float64(workExceeded)*100/float64(b.N), "work-cap-%")
		b.ReportMetric(float64(fuseExceeded)*100/float64(b.N), "fuse-%")
	})
}

func BenchmarkWAFLoadMatrix(b *testing.B) {
	previousLogWriter := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(previousLogWriter)
	rules := loadManagedRules(b)
	for _, concurrency := range []int{1, 10, 50, 200} {
		for _, kb := range []int{8, 64, 256} {
			for _, shape := range []string{"repeated_aho", "deep_json", "multipart", "200_params"} {
				name := fmt.Sprintf("%s_%dKB_g%d", shape, kb, concurrency)
				b.Run(name, func(b *testing.B) {
					phase, err := NewPhase(rules, nil)
					if err != nil {
						b.Fatal(err)
					}
					limit := kb * 1024
					plan := "free"
					if kb == 64 {
						plan = "pro"
					}
					if kb == 256 {
						plan = "enterprise"
					}
					contentType := "text/plain"
					payload := repeatToLimit("ordinary safe documentation ", limit)
					target := http.MethodPost
					urlPath := "http://edge.test/submit"
					switch shape {
					case "repeated_aho":
						payload = repeatToLimit("select union membership script alert plain ", limit)
					case "deep_json":
						contentType = "application/json"
						payload = "{" + strings.Repeat(`"a":[{`, limit/6) + `"x":"ordinary"` + strings.Repeat("}]", limit/6) + "}"
					case "multipart":
						contentType = "multipart/form-data; boundary=bench-boundary"
						payload = repeatToLimit("--bench-boundary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nplain-field\r\n", limit)
					case "200_params":
						target = http.MethodGet
						contentType = ""
						var q strings.Builder
						for i := 0; i < 200; i++ {
							if i > 0 {
								q.WriteByte('&')
							}
							fmt.Fprintf(&q, "p%d=%s", i, url.QueryEscape("ordinary documentation and safe search text"))
						}
						urlPath = "http://edge.test/search?" + q.String()
					}
					total := b.N
					samples := make([]int64, total)
					var work, fuse atomic.Int64
					jobs := make(chan int, total)
					for i := 0; i < total; i++ {
						jobs <- i
					}
					close(jobs)
					b.ReportAllocs()
					b.ResetTimer()
					var wg sync.WaitGroup
					for w := 0; w < concurrency; w++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							for i := range jobs {
								started := time.Now()
								r := httptest.NewRequest(target, urlPath, strings.NewReader(payload))
								if contentType != "" {
									r.Header.Set("Content-Type", contentType)
								}
								c := reqctx.New(r, nil, "bench-load", nil)
								c.Site = &wafcore.Site{ID: "bench", Plan: plan, Entitlements: wafcore.Entitlements{MaxBodyBytes: limit}, FailMode: "closed", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "low", Paranoia: 4, BodyLimitKB: kb}}
								d := phase.Handle(c)
								samples[i] = time.Since(started).Nanoseconds()
								if containsString(d.Tags, "waf_work_exhausted") {
									work.Add(1)
								}
								if containsString(d.Tags, "waf_budget_exceeded") {
									fuse.Add(1)
								}
								reqctx.Release(c)
							}
						}()
					}
					wg.Wait()
					b.StopTimer()
					reportLatencyPercentiles(b, samples)
					b.ReportMetric(float64(work.Load())*100/float64(total), "work-cap-%")
					b.ReportMetric(float64(fuse.Load())*100/float64(total), "fuse-%")
				})
			}
		}
	}
}

func reportLatencyPercentiles(b *testing.B, samples []int64) {
	b.Helper()
	if len(samples) < 10 {
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	pick := func(percentile int) int64 {
		index := (len(samples)*percentile + 99) / 100
		if index < 1 {
			index = 1
		}
		return samples[index-1]
	}
	b.ReportMetric(float64(pick(50)), "p50-ns")
	b.ReportMetric(float64(pick(99)), "p99-ns")
}

func repeatToLimit(value string, limit int) string {
	if limit <= 0 || value == "" {
		return ""
	}
	return strings.Repeat(value, (limit+len(value)-1)/len(value))[:limit]
}
