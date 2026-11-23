package waf

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

type scanTarget struct {
	kind  string
	param string
	raw   string
	path  bool
}

type Phase struct {
	rules     []compiledRule
	prefilter *automaton
	now       func() time.Time
}

func NewPhase(rules []Rule, now func() time.Time) (*Phase, error) {
	compiled, prefilter, err := compileRules(rules)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Phase{rules: compiled, prefilter: prefilter, now: now}, nil
}

func (p *Phase) Name() string { return "waf" }

func (p *Phase) Handle(ctx *reqctx.RequestCtx) reqctx.Decision {
	if ctx.Site == nil {
		return wafDecision(reqctx.ActionAllow, "waf_no_site", 0, "no routed site", nil)
	}
	mode := ctx.Site.WAF.Mode
	if mode == "off" {
		return wafDecision(reqctx.ActionAllow, "waf_off", 0, "WAF disabled", nil)
	}
	threshold := sensitivityThreshold(ctx.Site.WAF.Sensitivity)
	paranoia := ctx.Site.WAF.Paranoia
	if paranoia == 0 {
		paranoia = 1
	}
	budget := 2 * time.Millisecond
	if ctx.Site.WAF.BudgetMS > 0 {
		budget = time.Duration(ctx.Site.WAF.BudgetMS) * time.Millisecond
	}
	started := p.now()
	if p.overBudget(started, budget) {
		return p.budgetFailure(ctx, 0, "WAF request budget exceeded")
	}
	if err := ctx.BodyReadError(); err != nil {
		return p.budgetFailure(ctx, 0, "request body read failed: "+err.Error())
	}
	needBody := false
	for _, rule := range p.rules {
		if rule.rule.Paranoia <= paranoia && containsTarget(rule.rule.Targets, "body") &&
			!excluded(ctx.Site.WAF.Exclusions, rule.rule.ID, ctx.Path, "") {
			needBody = true
			break
		}
	}
	targets := collectTargets(ctx, needBody)
	if err := ctx.BodyReadError(); err != nil {
		return p.budgetFailure(ctx, 0, "request body read failed: "+err.Error())
	}
	if ctx.BodyTruncated() {
		ctx.AddTag("waf.body_truncated")
	}
	matched := make(map[string]compiledRule)
	score := 0
	tags := make([]string, 0, 8)
	seenTags := make(map[string]struct{})
	for _, target := range targets {
		if p.overBudget(started, budget) {
			return p.budgetFailure(ctx, score, "WAF request budget exceeded")
		}
		values := normalizedValues(target)
		for _, rule := range p.rules {
			if rule.rule.Paranoia > paranoia {
				continue
			}
			if !containsTarget(rule.rule.Targets, target.kind) || excluded(ctx.Site.WAF.Exclusions, rule.rule.ID, ctx.Path, target.param) {
				continue
			}
			prefilterMatched := len(rule.prefilter) == 0
			for _, value := range values {
				found := make(map[string]struct{})
				p.prefilter.scan(strings.ToLower(value), found)
				for word := range found {
					if _, ok := rule.prefilter[word]; ok {
						prefilterMatched = true
						break
					}
				}
				if prefilterMatched && rule.pattern.MatchString(value) {
					if _, already := matched[rule.rule.ID]; !already {
						matched[rule.rule.ID] = rule
						score += rule.points
						for _, tag := range rule.rule.Tags {
							if _, exists := seenTags[tag]; !exists && len(tags) < 32 {
								seenTags[tag] = struct{}{}
								tags = append(tags, tag)
								ctx.AddTag(tag)
							}
						}
						ctx.WAFScore = score
						if mode != "monitor" && score >= threshold {
							return thresholdDecision(ctx, mode, score, threshold, rule.rule.ID, ctx.Tags())
						}
					}
					break
				}
				if p.overBudget(started, budget) {
					return p.budgetFailure(ctx, score, "WAF request budget exceeded")
				}
			}
		}
	}
	if score == 0 {
		return wafDecision(reqctx.ActionAllow, "waf_allow", 0, "no managed rule matched", nil)
	}
	if mode == "monitor" {
		return wafDecision(reqctx.ActionLogOnly, firstRuleID(matched), score, "WAF monitor match", ctx.Tags())
	}
	return wafDecision(reqctx.ActionAllow, firstRuleID(matched), score, fmt.Sprintf("WAF score %d below threshold %d", score, threshold), ctx.Tags())
}

func (p *Phase) overBudget(start time.Time, budget time.Duration) bool {
	return p.now().Sub(start) > budget
}

func (p *Phase) budgetFailure(ctx *reqctx.RequestCtx, score int, reason string) reqctx.Decision {
	ctx.WAFScore = score
	ctx.AddTag("waf.budget_exceeded")
	if ctx.Site.FailMode == "closed" {
		return wafDecision(reqctx.ActionBlock, "waf_budget", score, reason+" (fail closed)", ctx.Tags())
	}
	return wafDecision(reqctx.ActionAllow, "waf_budget", score, reason+" (fail open)", ctx.Tags())
}

func collectTargets(ctx *reqctx.RequestCtx, includeBody bool) []scanTarget {
	targets := []scanTarget{{kind: "path", raw: ctx.Path, path: true}}
	for name, values := range ctx.QueryValues() {
		for _, value := range values {
			targets = append(targets, scanTarget{kind: "args", param: name, raw: name + "=" + value})
		}
	}
	if ctx.Request != nil {
		for _, name := range []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For"} {
			for _, value := range ctx.Request.Header.Values(name) {
				targets = append(targets, scanTarget{kind: "headers", param: name, raw: value})
			}
		}
		for _, cookie := range ctx.Request.Cookies() {
			targets = append(targets, scanTarget{kind: "cookies", param: cookie.Name, raw: cookie.Name + "=" + cookie.Value})
		}
		targets = append(targets, collectProtocolTargets(ctx.Request)...)
		if includeBody && supportedBodyType(ctx.Request.Header.Get("Content-Type")) {
			body := ctx.BodyText()
			if strings.HasPrefix(strings.ToLower(ctx.Request.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
				if values, err := url.ParseQuery(body); err == nil {
					for name, entries := range values {
						for _, value := range entries {
							targets = append(targets, scanTarget{kind: "body", param: name, raw: name + "=" + value})
						}
					}
				}
			}
			targets = append(targets, scanTarget{kind: "body", raw: body})
		}
	}
	return targets
}

func collectProtocolTargets(r *http.Request) []scanTarget {
	var targets []scanTarget
	if r.Host == "" {
		targets = append(targets, scanTarget{kind: "protocol", param: "host", raw: "missing_host"})
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect:
	default:
		targets = append(targets, scanTarget{kind: "protocol", param: "method", raw: "unusual_method=" + r.Method})
	}
	_, hasCL := r.Header[http.CanonicalHeaderKey("Content-Length")]
	_, hasTE := r.Header[http.CanonicalHeaderKey("Transfer-Encoding")]
	if hasCL && (hasTE || len(r.TransferEncoding) > 0) {
		targets = append(targets, scanTarget{kind: "protocol", param: "framing", raw: "content_length_transfer_encoding"})
	}
	if len(r.Header.Values("Content-Length")) > 1 {
		targets = append(targets, scanTarget{kind: "protocol", param: "framing", raw: "duplicate_content_length"})
	}
	return targets
}

func supportedBodyType(raw string) bool {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return false
	}
	return mediaType == "application/x-www-form-urlencoded" ||
		mediaType == "application/json" || mediaType == "application/xml" ||
		mediaType == "text/xml" || strings.HasPrefix(mediaType, "text/") ||
		mediaType == "multipart/form-data"
}

func normalizedValues(target scanTarget) []string {
	result := []string{target.raw}
	value := Normalize(target.raw, target.path)
	if value.Decoded != target.raw {
		result = append(result, value.Decoded)
	}
	if value.Value != value.Decoded {
		result = append(result, value.Value)
	}
	if value.DoubleEncoded {
		result = append(result, "double-encoded "+value.Decoded)
	}
	if value.Traversal {
		result = append(result, "../")
	}
	return result
}

func containsTarget(targets []string, target string) bool {
	for _, candidate := range targets {
		if candidate == target {
			return true
		}
	}
	return false
}

func excluded(exclusions []wafcore.WAFExclusion, ruleID, path, param string) bool {
	for _, exclusion := range exclusions {
		if exclusion.RuleID == ruleID && (exclusion.Path == "" || exclusion.Path == path) &&
			(exclusion.Param == "" || exclusion.Param == param) {
			return true
		}
	}
	return false
}

func sensitivityThreshold(sensitivity string) int {
	switch strings.ToLower(sensitivity) {
	case "low":
		return 10
	case "high":
		return 3
	default:
		return 5
	}
}

func thresholdDecision(ctx *reqctx.RequestCtx, mode string, score, threshold int, ruleID string, tags []string) reqctx.Decision {
	if mode == "monitor" {
		return wafDecision(reqctx.ActionLogOnly, ruleID, score, "WAF monitor threshold reached", tags)
	}
	if mode == "challenge" {
		return wafDecision(reqctx.ActionChallenge, ruleID, score, fmt.Sprintf("WAF score %d reached threshold %d", score, threshold), tags)
	}
	return wafDecision(reqctx.ActionBlock, ruleID, score, fmt.Sprintf("WAF score %d reached threshold %d", score, threshold), tags)
}

func firstRuleID(matches map[string]compiledRule) string {
	for _, rule := range matches {
		return rule.rule.ID
	}
	return "waf_match"
}

func wafDecision(action reqctx.Action, ruleID string, score int, reason string, tags []string) reqctx.Decision {
	return reqctx.Decision{Action: action, RuleID: ruleID, Phase: "waf", Score: score, Reason: reason, Tags: append([]string(nil), tags...)}
}
