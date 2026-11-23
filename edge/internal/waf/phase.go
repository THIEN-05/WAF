package waf

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sort"
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

const (
	defaultRequestScanBytes = 4 * 1024
	maxRequestScanBytes     = 4 * 1024
	maxTargetScanBytes      = 2 * 1024
	maxBodyScanBytes        = 1 * 1024
	maxQueryParseBytes      = 8 * 1024
	maxQueryParams          = 64
)

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
	targets, inputTruncated := collectTargets(ctx, needBody)
	maxBytes := defaultRequestScanBytes
	if configured := ctx.Site.WAF.ScanLimitBytes; configured > 0 && configured < maxRequestScanBytes {
		maxBytes = configured
	}
	remaining := maxBytes
	matched := make(map[string]struct{})
	firstMatchedRule := ""
	score := 0
	tags := make([]string, 0, 8)
	seenTags := make(map[string]struct{})
	bodyTruncated := false
	addTags := func(rule compiledRule) {
		for _, tag := range rule.rule.Tags {
			if _, exists := seenTags[tag]; !exists && len(tags) < 32 {
				seenTags[tag] = struct{}{}
				tags = append(tags, tag)
				ctx.AddTag(tag)
			}
		}
	}
	for _, target := range targets {
		if p.overBudget(started, budget) {
			return p.budgetFailure(ctx, score, "WAF request budget exceeded")
		}
		if target.kind == "body" {
			if ctx.Request == nil || !supportedBodyType(ctx.Request.Header.Get("Content-Type")) {
				if ctx.Request != nil && ctx.Request.Body != nil && ctx.Request.Body != http.NoBody {
					bodyTruncated = true
				}
				continue
			}
			if remaining <= 0 {
				inputTruncated = true
				bodyTruncated = true
				break
			}
			limit := maxBodyScanBytes
			if limit > remaining {
				limit = remaining
			}
			target.raw = ctx.BodyPrefix(limit)
			if err := ctx.BodyReadError(); err != nil {
				return p.budgetFailure(ctx, score, "request body read failed: "+err.Error())
			}
			bodyTruncated = ctx.BodyTruncated()
			if p.overBudget(started, budget) {
				return p.budgetFailure(ctx, score, "WAF request budget exceeded while buffering body prefix")
			}
		}
		if len(target.raw) > maxTargetScanBytes {
			target.raw = target.raw[:maxTargetScanBytes]
			inputTruncated = true
		}
		if len(target.raw) > remaining {
			target.raw = target.raw[:remaining]
			inputTruncated = true
		}
		remaining -= len(target.raw)
		if target.raw == "" {
			continue
		}
		normalized, ok := normalizeBounded(target.raw, target.path, func() bool { return p.overBudget(started, budget) })
		if !ok {
			return p.budgetFailure(ctx, score, "WAF request budget exceeded during normalization")
		}
		values := []string{target.raw}
		if normalized.Decoded != target.raw {
			values = append(values, normalized.Decoded)
		}
		if normalized.Value != normalized.Decoded {
			values = append(values, normalized.Value)
		}
		if normalized.DoubleEncoded {
			values = append(values, "double-encoded "+normalized.Decoded)
		}
		if normalized.Traversal {
			values = append(values, "../")
		}
		for _, value := range values {
			if p.overBudget(started, budget) {
				return p.budgetFailure(ctx, score, "WAF request budget exceeded between normalization and rule evaluation")
			}
			found := make(map[string]struct{})
			p.prefilter.scan(strings.ToLower(value), found)
			for ruleIndex, rule := range p.rules {
				if ruleIndex%4 == 0 && p.overBudget(started, budget) {
					return p.budgetFailure(ctx, score, "WAF request budget exceeded between rule groups")
				}
				if rule.rule.Paranoia > paranoia {
					continue
				}
				if !containsTarget(rule.rule.Targets, target.kind) || excluded(ctx.Site.WAF.Exclusions, rule.rule.ID, ctx.Path, target.param) {
					continue
				}
				prefilterMatched := len(rule.prefilter) == 0
				for word := range found {
					if _, ok := rule.prefilter[word]; ok {
						prefilterMatched = true
						break
					}
				}
				if !prefilterMatched || !rule.pattern.MatchString(value) {
					continue
				}
				if _, already := matched[rule.rule.ID]; already {
					continue
				}
				matched[rule.rule.ID] = struct{}{}
				if firstMatchedRule == "" {
					firstMatchedRule = rule.rule.ID
				}
				score += rule.points
				addTags(rule)
				ctx.WAFScore = score
				if mode != "monitor" && score >= threshold {
					return thresholdDecision(ctx, mode, score, threshold, rule.rule.ID, ctx.Tags())
				}
			}
		}
	}
	if bodyTruncated {
		ctx.AddTag("waf_body_truncated")
		if !hasString(tags, "waf_body_truncated") {
			tags = append(tags, "waf_body_truncated")
		}
		truncatedScore := ctx.Site.WAF.TruncatedBodyScore
		if truncatedScore == 0 {
			truncatedScore = 3
		}
		score += truncatedScore
		ctx.WAFScore = score
		if mode != "monitor" && score >= threshold {
			return thresholdDecision(ctx, mode, score, threshold, "waf_body_truncated", ctx.Tags())
		}
		if firstMatchedRule == "" {
			firstMatchedRule = "waf_body_truncated"
		}
	}
	if inputTruncated {
		ctx.AddTag("waf_scan_truncated")
		if !hasString(tags, "waf_scan_truncated") {
			tags = append(tags, "waf_scan_truncated")
		}
	}
	if score == 0 && !inputTruncated {
		return wafDecision(reqctx.ActionAllow, "waf_allow", 0, "no managed rule matched", nil)
	}
	if mode == "monitor" {
		return wafDecision(reqctx.ActionLogOnly, firstMatchedRule, score, "WAF monitor match or incomplete bounded scan", ctx.Tags())
	}
	if inputTruncated && firstMatchedRule == "" {
		return p.budgetFailure(ctx, score, "WAF scan byte limit exceeded")
	}
	return wafDecision(reqctx.ActionAllow, firstMatchedRuleOrAllow(firstMatchedRule), score, fmt.Sprintf("WAF score %d below threshold %d", score, threshold), ctx.Tags())
}

func (p *Phase) overBudget(start time.Time, budget time.Duration) bool {
	return p.now().Sub(start) > budget
}

func (p *Phase) budgetFailure(ctx *reqctx.RequestCtx, score int, reason string) reqctx.Decision {
	if ctx.BodyTruncated() && !hasString(ctx.Tags(), "waf_body_truncated") {
		ctx.AddTag("waf_body_truncated")
		truncatedScore := ctx.Site.WAF.TruncatedBodyScore
		if truncatedScore == 0 {
			truncatedScore = 3
		}
		score += truncatedScore
		reason += "; body prefix incomplete"
	}
	ctx.WAFScore = score
	ctx.AddTag("waf_budget_exceeded")
	if effectiveFailMode(ctx) == "closed" {
		return wafDecision(reqctx.ActionBlock, "waf_budget", score, reason+" (fail closed)", ctx.Tags())
	}
	return wafDecision(reqctx.ActionAllow, "waf_budget", score, reason+" (fail open)", ctx.Tags())
}

func effectiveFailMode(ctx *reqctx.RequestCtx) string {
	if ctx.Site.FailMode == "open" || ctx.Site.FailMode == "closed" {
		return ctx.Site.FailMode
	}
	if strings.EqualFold(ctx.Site.Plan, "free") {
		return "open"
	}
	return "closed"
}

func collectTargets(ctx *reqctx.RequestCtx, includeBody bool) ([]scanTarget, bool) {
	targets := []scanTarget{{kind: "path", raw: ctx.Path, path: true}}
	truncated := false
	query := ctx.Query
	if len(query) > maxQueryParseBytes {
		query = query[:maxQueryParseBytes]
		truncated = true
	}
	queryValues, _ := url.ParseQuery(query)
	names := make([]string, 0, len(queryValues))
	for name := range queryValues {
		names = append(names, name)
	}
	sort.Strings(names)
	paramCount := 0
	for _, name := range names {
		values := queryValues[name]
		for _, value := range values {
			if paramCount >= maxQueryParams {
				truncated = true
				break
			}
			targets = append(targets, scanTarget{kind: "args", param: name, raw: name + "=" + value})
			paramCount++
		}
		if paramCount >= maxQueryParams {
			break
		}
	}
	if ctx.Request != nil {
		for _, name := range []string{"User-Agent", "Referer", "X-Forwarded-For"} {
			values := ctx.Request.Header.Values(name)
			if len(values) > 4 {
				values = values[:4]
				truncated = true
			}
			for _, value := range values {
				if len(value) > 1024 {
					value = value[:1024]
					truncated = true
				}
				targets = append(targets, scanTarget{kind: "headers", param: name, raw: value})
			}
		}
		cookieHeader := ctx.Request.Header.Get("Cookie")
		if len(cookieHeader) > 4096 {
			cookieHeader = cookieHeader[:4096]
			truncated = true
		}
		cookieParts := strings.Split(cookieHeader, ";")
		if len(cookieParts) > 64 {
			cookieParts = cookieParts[:64]
			truncated = true
		}
		for _, part := range cookieParts {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok {
				targets = append(targets, scanTarget{kind: "cookies", param: strings.TrimSpace(name), raw: strings.TrimSpace(value)})
			}
		}
		targets = append(targets, collectProtocolTargets(ctx.Request)...)
		if includeBody {
			targets = append(targets, scanTarget{kind: "body"})
		}
	}
	return targets, truncated
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

func firstMatchedRuleOrAllow(ruleID string) string {
	if ruleID == "" {
		return "waf_allow"
	}
	return ruleID
}

func hasString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func wafDecision(action reqctx.Action, ruleID string, score int, reason string, tags []string) reqctx.Decision {
	return reqctx.Decision{Action: action, RuleID: ruleID, Phase: "waf", Score: score, Reason: reason, Tags: append([]string(nil), tags...)}
}
