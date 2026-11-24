package waf

import (
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

type regexCandidate struct{ text string }
type queuedRegexCandidate struct {
	target scanTarget
	text   string
}

const (
	defaultRequestScanBytes = 1024 * 1024
	maxRequestScanBytes     = 1024 * 1024
	maxTargetScanBytes      = 256 * 1024
	maxBodyScanBytes        = 256 * 1024
	maxQueryParseBytes      = 256 * 1024
	maxQueryParams          = 200
	scanChunkBytes          = 4096
	scanChunkOverlap        = maxRegexWindowBytes
	defaultFuse             = 100 * time.Millisecond
	maxFuse                 = 5 * time.Second
)

type workLimit struct {
	bytes, normalizeSteps, regexWindows int
}

type workMeter struct {
	limit                               workLimit
	bytes, normalizeSteps, regexWindows int
}

func planWorkLimit(plan string) workLimit {
	switch strings.ToLower(plan) {
	case "pro":
		return workLimit{256 * 1024, 512, 192}
	case "business":
		return workLimit{384 * 1024, 768, 256}
	case "enterprise":
		return workLimit{512 * 1024, 1024, 384}
	default:
		return workLimit{128 * 1024, 256, 128}
	}
}

type Phase struct {
	rules       []compiledRule
	prefilter   *automaton
	now         func() time.Time
	active      atomic.Int64
	requests    atomic.Uint64
	fuses       atomic.Uint64
	workCaps    atomic.Uint64
	degrade1    atomic.Uint64
	degrade2    atomic.Uint64
	degrade3    atomic.Uint64
	lastLevel   atomic.Int64
	ewmaNanos   atomic.Int64
	lastTierLog atomic.Int64
	outcomeMu   sync.Mutex
	outcomes    [64]bool
	outcomeN    int
	outcomeAt   int
}

type OverloadMetrics struct {
	Active, EWMAWAFNanos                                               int64
	Requests, FuseTrips, WorkCaps, DropParanoia, ReduceScope, FailMode uint64
}

func (p *Phase) Metrics() OverloadMetrics {
	return OverloadMetrics{Active: p.active.Load(), EWMAWAFNanos: p.ewmaNanos.Load(), Requests: p.requests.Load(), FuseTrips: p.fuses.Load(), WorkCaps: p.workCaps.Load(), DropParanoia: p.degrade1.Load(), ReduceScope: p.degrade2.Load(), FailMode: p.degrade3.Load()}
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

func (p *Phase) Handle(ctx *reqctx.RequestCtx) (decision reqctx.Decision) {
	phaseStarted := time.Now()
	active := p.active.Add(1)
	defer func() {
		sample := time.Since(phaseStarted).Nanoseconds()
		old := p.ewmaNanos.Load()
		for !p.ewmaNanos.CompareAndSwap(old, (old*7+sample)/8) {
			old = p.ewmaNanos.Load()
		}
		p.active.Add(-1)
		p.outcomeMu.Lock()
		p.outcomes[p.outcomeAt] = hasString(decision.Tags, "waf_budget_exceeded")
		p.outcomeAt = (p.outcomeAt + 1) % len(p.outcomes)
		if p.outcomeN < len(p.outcomes) {
			p.outcomeN++
		}
		p.outcomeMu.Unlock()
	}()
	p.requests.Add(1)
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
	level := int64(0)
	procs := int64(max(1, runtime.GOMAXPROCS(0)))
	if active-procs >= procs {
		level = 1
	}
	if active-procs >= 4*procs {
		level = 2
	}
	requests, fuseTrips := p.recentFuseRatio()
	level = overloadTier(active, procs, p.ewmaNanos.Load(), fuseTrips, requests, level)
	if prev := p.lastLevel.Swap(level); prev != level {
		nowLog := time.Now().UnixNano()
		last := p.lastTierLog.Load()
		if nowLog-last > 100_000_000 && p.lastTierLog.CompareAndSwap(last, nowLog) {
			log.Printf("waf overload tier changed: level=%d active=%d estimated_runnable_queue=%d ewma_ns=%d fuse_ratio=%.3f", level, active, max(int64(0), active-procs), p.ewmaNanos.Load(), fuseTrips)
		}
	}
	if level >= 3 {
		p.degrade3.Add(1)
		ctx.AddTag("waf_degraded_fail_mode")
		if effectiveFailMode(ctx) == "closed" {
			return wafDecision(reqctx.ActionBlock, "waf_overload", 0, "persistent WAF fuse ratio; fail closed", ctx.Tags())
		}
		return wafDecision(reqctx.ActionAllow, "waf_overload", 0, "persistent WAF fuse ratio; fail open", ctx.Tags())
	}
	if level >= 1 && paranoia > 1 {
		paranoia = 1
		p.degrade1.Add(1)
		ctx.AddTag("waf_degraded_paranoia")
	}
	fuse := defaultFuse
	if ctx.Site.WAF.BudgetMS > 0 {
		fuse = time.Duration(ctx.Site.WAF.BudgetMS) * time.Millisecond
		if fuse > maxFuse {
			fuse = maxFuse
		}
	}
	started := p.now()
	if p.overFuse(started, fuse) {
		return p.budgetFailure(ctx, 0, "WAF request budget exceeded")
	}
	if err := ctx.BodyReadError(); err != nil {
		return p.bodyReadFailure(ctx, 0, "request body read failed: "+err.Error())
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
	work := workMeter{limit: planWorkLimit(ctx.Site.Plan)}
	if level >= 2 {
		work.limit.bytes /= 2
		work.limit.normalizeSteps /= 2
		work.limit.regexWindows /= 2
		p.degrade2.Add(1)
		ctx.AddTag("waf_degraded_scope")
	}
	if work.limit.bytes < maxBytes {
		maxBytes = work.limit.bytes
	}
	remaining := maxBytes
	workTruncated := false
	matched := make(map[string]struct{})
	firstMatchedRule := ""
	score := 0
	tags := make([]string, 0, 8)
	seenTags := make(map[string]struct{})
	bodyTruncated := false
	bodyTruncationScored := false
	markScanTruncated := func() {
		inputTruncated = true
		ctx.AddTag("waf_scan_truncated")
		if !hasString(tags, "waf_scan_truncated") && len(tags) < 32 {
			tags = append(tags, "waf_scan_truncated")
		}
	}
	markBodyTruncated := func() {
		bodyTruncated = true
		ctx.AddTag("waf_body_truncated")
		if !hasString(tags, "waf_body_truncated") && len(tags) < 32 {
			tags = append(tags, "waf_body_truncated")
		}
		if !bodyTruncationScored {
			truncatedScore := ctx.Site.WAF.TruncatedBodyScore
			if truncatedScore == 0 {
				truncatedScore = 3
			}
			score += truncatedScore
			ctx.WAFScore = score
			bodyTruncationScored = true
		}
	}
	addTags := func(rule compiledRule) {
		for _, tag := range rule.rule.Tags {
			if _, exists := seenTags[tag]; !exists && len(tags) < 32 {
				seenTags[tag] = struct{}{}
				tags = append(tags, tag)
				ctx.AddTag(tag)
			}
		}
	}
	evaluate := func(target scanTarget, candidate string) (reqctx.Decision, bool) {
		if p.overFuse(started, fuse) {
			return p.budgetFailure(ctx, score, "WAF request fuse exceeded between regex windows"), true
		}
		found := make(map[string]struct{})
		p.prefilter.scan(candidate, found)
		for _, rule := range p.rules {
			if rule.rule.Paranoia > paranoia || !containsTarget(rule.rule.Targets, target.kind) || excluded(ctx.Site.WAF.Exclusions, rule.rule.ID, ctx.Path, target.param) {
				continue
			}
			prefilterMatched := len(rule.prefilter) == 0
			for word := range found {
				if _, ok := rule.prefilter[word]; ok {
					prefilterMatched = true
					break
				}
			}
			if !prefilterMatched || !rule.pattern.MatchString(candidate) {
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
				return thresholdDecision(ctx, mode, score, threshold, rule.rule.ID, ctx.Tags()), true
			}
		}
		return reqctx.Decision{}, false
	}
	requestWindowCount := 0
	var deferredTail []queuedRegexCandidate
	for _, target := range targets {
		if p.overFuse(started, fuse) {
			return p.budgetFailure(ctx, score, "WAF request fuse exceeded")
		}
		if target.kind == "body" {
			if ctx.Request == nil || !supportedBodyType(ctx.Request.Header.Get("Content-Type")) {
				if ctx.Request != nil && ctx.Request.Body != nil && ctx.Request.Body != http.NoBody {
					markBodyTruncated()
				}
				continue
			}
			if remaining <= 0 {
				markScanTruncated()
				markBodyTruncated()
				break
			}
			limit := min(maxBodyScanBytes, ctx.Site.EffectiveBodyLimitBytes())
			if limit > remaining {
				limit = remaining
			}
			target.raw = ctx.BodyPrefix(limit)
			if err := ctx.BodyReadError(); err != nil {
				return p.bodyReadFailure(ctx, score, "request body read failed: "+err.Error())
			}
			if ctx.BodyTruncated() {
				markBodyTruncated()
			}
			if p.overFuse(started, fuse) {
				return p.budgetFailure(ctx, score, "WAF request fuse exceeded while buffering body prefix")
			}
		}
		if len(target.raw) > maxTargetScanBytes {
			target.raw = sampleHeadTail(target.raw, maxTargetScanBytes)
			markScanTruncated()
			if target.kind == "body" {
				markBodyTruncated()
			}
		}
		if len(target.raw) > remaining {
			target.raw = sampleHeadTail(target.raw, remaining)
			markScanTruncated()
			if target.kind == "body" {
				markBodyTruncated()
			}
		}
		if len(target.raw) > work.limit.bytes-work.bytes {
			workTruncated = true
			target.raw = sampleHeadTail(target.raw, max(0, work.limit.bytes-work.bytes))
			markScanTruncated()
			if target.kind == "body" {
				markBodyTruncated()
			}
		}
		work.bytes += len(target.raw)
		remaining -= len(target.raw)
		if target.raw == "" {
			continue
		}
		var headCandidates, tailCandidates []regexCandidate
		targetWindowCount := 0
		chunks := scanChunks(target.raw, target.kind == "body")
		chunks = prioritizeHeadTail(chunks)
		for _, rawChunk := range chunks {
			if work.normalizeSteps >= work.limit.normalizeSteps || p.overFuse(started, fuse) {
				workTruncated = work.normalizeSteps >= work.limit.normalizeSteps
				markScanTruncated()
				if target.kind == "body" {
					markBodyTruncated()
				}
				break
			}
			work.normalizeSteps++
			normalized, ok := normalizeBounded(rawChunk, target.path, func() bool { return p.overFuse(started, fuse) })
			if !ok {
				return p.budgetFailure(ctx, score, "WAF request fuse exceeded during normalization")
			}
			values := []string{rawChunk}
			if normalized.Decoded != rawChunk {
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
				if p.overFuse(started, fuse) {
					return p.budgetFailure(ctx, score, "WAF request fuse exceeded between normalization and rule evaluation")
				}
				lowerValue := strings.ToLower(value)
				var windows []scanWindow
				var complete bool
				remainingWindows := work.limit.regexWindows - work.regexWindows
				if target.kind == "body" && remainingWindows > maxRegexWindowsPerRequest {
					remainingWindows = maxRegexWindowsPerRequest
				}
				if hasUnfilteredRule(p.rules, target.kind, ctx.Site.WAF.Exclusions, ctx.Path) {
					windows, complete = boundedWindowsLimit(len(lowerValue), remainingWindows)
				} else {
					windows, complete = p.prefilter.windowsLimit(lowerValue, remainingWindows, func() bool { return p.overFuse(started, fuse) })
				}
				if !complete {
					workTruncated = true
					markScanTruncated()
					if target.kind == "body" {
						markBodyTruncated()
					}
				}
				for _, window := range windows {
					if work.regexWindows >= work.limit.regexWindows {
						workTruncated = true
						complete = false
						break
					}
					targetWindowCount++
					work.regexWindows++
					if targetWindowCount > maxRegexWindowsPerRequest {
						workTruncated = true
						markScanTruncated()
						if target.kind == "body" {
							markBodyTruncated()
						}
					}
					if p.overFuse(started, fuse) {
						return p.budgetFailure(ctx, score, "WAF request fuse exceeded during keyword scan")
					}
					start, end := min(window.start, len(lowerValue)), min(window.end, len(lowerValue))
					if start > end {
						continue
					}
					candidate := lowerValue[start:end]
					if len(headCandidates) < maxRegexWindowsPerRequest/2 {
						headCandidates = append(headCandidates, regexCandidate{text: candidate})
					} else {
						tailCandidates = append(tailCandidates, regexCandidate{text: candidate})
						if len(tailCandidates) > maxRegexWindowsPerRequest/2 {
							tailCandidates = tailCandidates[1:]
						}
					}
				}
			}
		}
		if bodyTruncated && !bodyTruncationScored {
			markBodyTruncated()
		}
		candidates := make([]regexCandidate, 0, len(headCandidates)+len(tailCandidates))
		candidates = append(candidates, headCandidates...)
		candidates = append(candidates, tailCandidates...)
		for _, scan := range candidates {
			requestWindowCount++
			queued := queuedRegexCandidate{target: target, text: scan.text}
			if requestWindowCount <= maxRegexWindowsPerRequest/2 {
				if decision, terminal := evaluate(queued.target, queued.text); terminal {
					return decision
				}
			} else {
				deferredTail = append(deferredTail, queued)
				if len(deferredTail) > maxRegexWindowsPerRequest/2 {
					deferredTail = deferredTail[1:]
				}
			}
			if requestWindowCount > maxRegexWindowsPerRequest {
				markScanTruncated()
				if target.kind == "body" {
					markBodyTruncated()
				}
			}
		}
	}
	for _, queued := range deferredTail {
		if decision, terminal := evaluate(queued.target, queued.text); terminal {
			return decision
		}
	}
	if workTruncated {
		ctx.AddTag("waf_work_exhausted")
		p.workCaps.Add(1)
	}
	if bodyTruncated {
		markBodyTruncated()
		if effectiveFailMode(ctx) == "closed" {
			return wafDecision(reqctx.ActionBlock, "waf_body_truncated", score, "body is incomplete for this plan (fail closed)", ctx.Tags())
		}
		return wafDecision(reqctx.ActionAllow, "waf_body_truncated", score, "body is incomplete for this plan (fail open)", ctx.Tags())
	}
	if inputTruncated {
		markScanTruncated()
		if effectiveFailMode(ctx) == "closed" {
			return wafDecision(reqctx.ActionBlock, "waf_scan_truncated", score, "WAF target exceeded bounded scan range (fail closed)", ctx.Tags())
		}
	}
	if score == 0 && !inputTruncated {
		return wafDecision(reqctx.ActionAllow, "waf_allow", 0, "no managed rule matched", ctx.Tags())
	}
	if mode == "monitor" {
		return wafDecision(reqctx.ActionLogOnly, firstMatchedRule, score, "WAF monitor match or incomplete bounded scan", ctx.Tags())
	}
	if inputTruncated && firstMatchedRule == "" {
		if effectiveFailMode(ctx) == "closed" {
			return wafDecision(reqctx.ActionBlock, "waf_scan_truncated", score, "WAF deterministic work limit exceeded (fail closed)", ctx.Tags())
		}
		return wafDecision(reqctx.ActionAllow, "waf_scan_truncated", score, "WAF deterministic work limit exceeded (fail open)", ctx.Tags())
	}
	return wafDecision(reqctx.ActionAllow, firstMatchedRuleOrAllow(firstMatchedRule), score, fmt.Sprintf("WAF score %d below threshold %d", score, threshold), ctx.Tags())
}

func scanChunks(raw string, body bool) []string {
	if !body || len(raw) <= scanChunkBytes {
		return []string{raw}
	}
	step := scanChunkBytes - scanChunkOverlap
	chunks := make([]string, 0, (len(raw)+step-1)/step)
	for start := 0; start < len(raw); start += step {
		end := min(start+scanChunkBytes, len(raw))
		chunks = append(chunks, raw[start:end])
		if end == len(raw) {
			break
		}
	}
	return chunks
}

// prioritizeHeadTail lets the deterministic regex-window cap inspect both ends
// of the bytes actually buffered before spending work on the middle.
func prioritizeHeadTail(chunks []string) []string {
	if len(chunks) < 3 {
		return chunks
	}
	out := make([]string, 0, len(chunks))
	left, right := 0, len(chunks)-1
	for left <= right {
		out = append(out, chunks[left])
		left++
		if left <= right {
			out = append(out, chunks[right])
			right--
		}
	}
	return out
}

func sampleHeadTail(raw string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(raw) <= limit {
		return raw
	}
	if limit == 1 {
		return raw[:1]
	}
	head := (limit - 1) / 2
	tail := limit - 1 - head
	return raw[:head] + "\x01" + raw[len(raw)-tail:]
}

func hasUnfilteredRule(rules []compiledRule, target string, exclusions []wafcore.WAFExclusion, path string) bool {
	for _, rule := range rules {
		if len(rule.prefilter) == 0 && containsTarget(rule.rule.Targets, target) && !excluded(exclusions, rule.rule.ID, path, "") {
			return true
		}
	}
	return false
}

func boundedWindowsLimit(length, limit int) ([]scanWindow, bool) {
	if limit < 0 {
		limit = 0
	}
	if length <= 0 {
		return nil, true
	}
	if length <= maxRegexWindowBytes {
		return []scanWindow{{0, length}}, true
	}
	out := make([]scanWindow, 0, maxRegexWindowsPerRequest)
	for start := 0; start < length; start += maxRegexWindowBytes / 2 {
		end := min(start+maxRegexWindowBytes, length)
		out = append(out, scanWindow{start, end})
		if len(out) > limit {
			half := limit / 2
			if half == 0 {
				return nil, false
			}
			selected := append(append(make([]scanWindow, 0, maxRegexWindowsPerRequest), out[:half]...), out[len(out)-half:]...)
			return selected, false
		}
		if end == length {
			break
		}
	}
	return out, true
}

func (p *Phase) overFuse(start time.Time, fuse time.Duration) bool {
	active := p.active.Load()
	procs := int64(max(1, runtime.GOMAXPROCS(0)))
	return p.now().Sub(start) > effectiveFuse(fuse, active, procs)
}

func effectiveFuse(fuse time.Duration, active, procs int64) time.Duration {
	procs = max(1, procs)
	if active > procs {
		ratio := float64(active) / float64(procs)
		scale := 1 + ratio*ratio*ratio*ratio*ratio*ratio*ratio*ratio
		fuse = time.Duration(float64(fuse) * scale)
		if fuse > maxFuse {
			fuse = maxFuse
		}
	}
	return fuse
}

func (p *Phase) recentFuseRatio() (int64, float64) {
	p.outcomeMu.Lock()
	defer p.outcomeMu.Unlock()
	f := int64(0)
	for i := 0; i < p.outcomeN; i++ {
		if p.outcomes[i] {
			f++
		}
	}
	if p.outcomeN == 0 {
		return 0, 0
	}
	return int64(p.outcomeN), float64(f) / float64(p.outcomeN)
}

func overloadTier(active, procs, ewmaNanos int64, fuseRatio float64, recent, current int64) int64 {
	level := current
	backlog := max(int64(0), active-procs)
	if backlog >= procs {
		level = 2
	} else if backlog > 0 && level < 1 {
		level = 1
	}
	if ewmaNanos >= 30_000_000 {
		level = 2
	} else if ewmaNanos >= 12_000_000 && level < 1 {
		level = 1
	}
	if recent >= 32 && fuseRatio >= 0.25 && active <= procs {
		level = 3
	}
	return level
}

func (p *Phase) budgetFailure(ctx *reqctx.RequestCtx, score int, reason string) reqctx.Decision {
	p.fuses.Add(1)
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
	if ctx.BodyReadTimedOut() {
		ctx.AddTag("waf_body_read_timeout")
	}
	if effectiveFailMode(ctx) == "closed" {
		return wafDecision(reqctx.ActionBlock, "waf_budget", score, reason+" (fail closed)", ctx.Tags())
	}
	return wafDecision(reqctx.ActionAllow, "waf_budget", score, reason+" (fail open)", ctx.Tags())
}

func (p *Phase) bodyReadFailure(ctx *reqctx.RequestCtx, score int, reason string) reqctx.Decision {
	ruleID := "waf_body_read_error"
	if ctx.BodyTruncated() && !hasString(ctx.Tags(), "waf_body_truncated") {
		ctx.AddTag("waf_body_truncated")
		addTruncatedBodyScore(ctx, &score)
	}
	if ctx.BodyReadTimedOut() {
		ctx.AddTag("waf_body_read_timeout")
		ruleID = "waf_body_read_timeout"
	}
	ctx.WAFScore = score
	if effectiveFailMode(ctx) == "closed" {
		return wafDecision(reqctx.ActionBlock, ruleID, score, reason+" (fail closed)", ctx.Tags())
	}
	return wafDecision(reqctx.ActionAllow, ruleID, score, reason+" (fail open)", ctx.Tags())
}

func addTruncatedBodyScore(ctx *reqctx.RequestCtx, score *int) {
	v := ctx.Site.WAF.TruncatedBodyScore
	if v == 0 {
		v = 3
	}
	*score += v
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
		query = sampleHeadTail(query, maxQueryParseBytes)
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
				if len(value) > maxTargetScanBytes {
					value = sampleHeadTail(value, maxTargetScanBytes)
					truncated = true
				}
				targets = append(targets, scanTarget{kind: "headers", param: name, raw: value})
			}
		}
		cookieHeader := ctx.Request.Header.Get("Cookie")
		if len(cookieHeader) > maxTargetScanBytes {
			cookieHeader = sampleHeadTail(cookieHeader, maxTargetScanBytes)
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
