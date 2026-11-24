package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

type RateLimitExecutor interface {
	HandlePolicy(*reqctx.RequestCtx, string) reqctx.Decision
}

type compiledRule struct {
	rule     wafcore.Rule
	match    func(wafcore.Ctx) bool
	usesBody bool
	logOnly  bool
}

type Phase struct {
	rules   map[string][]compiledRule
	limiter RateLimitExecutor
	now     func() time.Time
}

func NewPhase(snapshot *wafcore.Snapshot, limiter RateLimitExecutor, now func() time.Time) (*Phase, error) {
	if now == nil {
		now = time.Now
	}
	p := &Phase{rules: make(map[string][]compiledRule), limiter: limiter, now: now}
	if snapshot == nil {
		return p, nil
	}
	for i := range snapshot.Sites {
		site := &snapshot.Sites[i]
		compiled := make([]compiledRule, 0, len(site.Rules))
		for _, rule := range site.Rules {
			match, err := wafcore.Compile(rule.Expression, wafcore.DefaultLimits())
			if err != nil {
				return nil, fmt.Errorf("site %s rule %s: %w", site.ID, rule.ID, err)
			}
			compiled = append(compiled, compiledRule{
				rule: rule, match: match,
				usesBody: wafcore.ExpressionUsesField(rule.Expression, "http.body"),
				logOnly:  rule.Mode == "log",
			})
		}
		sort.SliceStable(compiled, func(i, j int) bool {
			return compiled[i].rule.Priority < compiled[j].rule.Priority
		})
		p.rules[site.ID] = compiled
	}
	return p, nil
}

func (p *Phase) Name() string { return "rules" }

func (p *Phase) Handle(ctx *reqctx.RequestCtx) reqctx.Decision {
	if ctx.Site == nil {
		return ruleDecision(reqctx.ActionAllow, "rules_no_site", "no routed site")
	}
	if ctx.PhaseSkipped("rules") {
		return ruleDecision(reqctx.ActionAllow, "rules_skipped", "custom rules phase skipped")
	}
	var lastLog reqctx.Decision
	for _, rule := range p.rules[ctx.Site.ID] {
		if rule.rule.ExpiresAt != nil && !p.now().Before(*rule.rule.ExpiresAt) {
			continue
		}
		if rule.usesBody {
			_ = ctx.BodyText()
			if ctx.BodyReadError() != nil {
				return reqctx.Decision{Action: reqctx.ActionAllow, RuleID: "waf_body_read", Phase: p.Name(), Reason: "request body could not be inspected"}
			}
		}
		if !rule.match(ctx) {
			continue
		}
		if rule.logOnly {
			lastLog = ruleDecision(reqctx.ActionLogOnly, rule.rule.ID, "custom rule matched in log mode (action "+rule.rule.Action+")")
			continue
		}
		decision := p.execute(ctx, rule.rule)
		if decision.Action == reqctx.ActionLogOnly {
			lastLog = decision
			continue
		}
		if decision.Terminal() {
			decision.Tags = ctx.Tags()
			return decision
		}
		if rule.rule.Action == "allow" {
			decision.Tags = ctx.Tags()
			ctx.SkipPhase("waf")
			return decision
		}
		if rule.rule.Action == "skip" {
			decision.Tags = ctx.Tags()
			ctx.SkipPhase(rule.rule.Phase)
			return decision
		}
	}
	if lastLog.Action == reqctx.ActionLogOnly {
		lastLog.Tags = ctx.Tags()
		return lastLog
	}
	d := ruleDecision(reqctx.ActionAllow, "rules_allow", "no custom rule matched")
	d.Tags = ctx.Tags()
	return d
}

func (p *Phase) execute(ctx *reqctx.RequestCtx, rule wafcore.Rule) reqctx.Decision {
	switch rule.Action {
	case "allow":
		return ruleDecision(reqctx.ActionAllow, rule.ID, "custom rule allowed request")
	case "block":
		return ruleDecision(reqctx.ActionBlock, rule.ID, "custom rule blocked request")
	case "challenge":
		return ruleDecision(reqctx.ActionChallenge, rule.ID, "custom rule requires challenge")
	case "log":
		return ruleDecision(reqctx.ActionLogOnly, rule.ID, "custom rule matched (log only)")
	case "rate_limit":
		if p.limiter == nil {
			return ruleDecision(reqctx.ActionBlock, rule.ID, "rate limit executor is unavailable")
		}
		decision := p.limiter.HandlePolicy(ctx, rule.Policy)
		decision.RuleID = rule.ID
		decision.Phase = p.Name()
		decision.Reason = "custom rule rate_limit policy " + rule.Policy + ": " + decision.Reason
		return decision
	case "tag":
		ctx.AddTag(rule.Tag)
		d := ruleDecision(reqctx.ActionAllow, rule.ID, "custom rule added tag")
		d.Tags = []string{rule.Tag}
		return d
	case "skip":
		ctx.SkipPhase(rule.Phase)
		return ruleDecision(reqctx.ActionAllow, rule.ID, "custom rule skipped phase "+rule.Phase)
	default:
		return ruleDecision(reqctx.ActionBlock, rule.ID, "unsupported action in compiled rule")
	}
}

func ruleDecision(action reqctx.Action, ruleID, reason string) reqctx.Decision {
	return reqctx.Decision{Action: action, RuleID: ruleID, Phase: "rules", Reason: reason}
}
