package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

type BanWriter interface {
	Ban(net.IP, time.Duration) error
}

type Phase struct {
	Limiter *Limiter
	Bans    BanWriter

	mu       sync.RWMutex
	policies map[policyKey][]compiledPolicy
}

type policyKey struct {
	version uint64
	siteID  string
}

type compiledPolicy struct {
	config wafcore.RateLimit
	match  func(wafcore.Ctx) bool
	err    error
}

func NewPhase(limiter *Limiter, bans BanWriter) *Phase {
	if limiter == nil {
		limiter = NewLimiter(Config{})
	}
	return &Phase{Limiter: limiter, Bans: bans, policies: map[policyKey][]compiledPolicy{}}
}

func (p *Phase) Name() string { return "ratelimit" }

func (p *Phase) Handle(ctx *reqctx.RequestCtx) reqctx.Decision {
	if ctx.Site == nil {
		return reqctx.Decision{Action: reqctx.ActionAllow, RuleID: "ratelimit_no_site", Phase: p.Name(), Score: 0, Reason: "no routed site"}
	}
	for _, policy := range p.policy(ctx) {
		if policy.err != nil {
			return rateDecision(reqctx.ActionBlock, policy.config.ID, 0, "rate limit policy invalid: "+policy.err.Error())
		}
		if !policy.match(ctx) {
			continue
		}
		keyPart, err := counterKey(policy.config.Key, ctx)
		if err != nil {
			return rateDecision(reqctx.ActionBlock, policy.config.ID, 0, err.Error())
		}
		scope := fmt.Sprintf("v%d:%s:%s:%s:%s", versionOf(ctx), ctx.Site.ID, policy.config.ID, policy.config.Algorithm, keyPart)
		window := time.Duration(policy.config.WindowS) * time.Second
		var allowed bool
		var retry time.Duration
		if policy.config.Algorithm == "sliding_window" {
			allowed, retry, err = p.Limiter.AllowSliding(ctx.Site.ID, scope, policy.config.Limit, window, ctx.Site.Entitlements.MaxCounterKeys)
		} else {
			allowed, retry, err = p.Limiter.AllowToken(ctx.Site.ID, scope, policy.config.Limit, window, ctx.Site.Entitlements.MaxCounterKeys)
		}
		if err != nil && err != ErrCounterCapacity {
			return rateDecision(reqctx.ActionBlock, policy.config.ID, retry, "rate limit evaluation failed: "+err.Error())
		}
		if allowed {
			continue
		}
		if policy.config.BanS > 0 && p.Bans != nil && ctx.ClientIP != nil {
			_ = p.Bans.Ban(ctx.ClientIP, time.Duration(policy.config.BanS)*time.Second)
		}
		action := reqctx.ActionRateLimited
		if policy.config.Action == "challenge" {
			action = reqctx.ActionChallenge
		}
		if retry <= 0 {
			retry = window
		}
		return rateDecision(action, policy.config.ID, retry, "rate limit exceeded ("+policy.config.Action+")")
	}
	return reqctx.Decision{Action: reqctx.ActionAllow, RuleID: "ratelimit_allow", Phase: p.Name(), Score: 0, Reason: "no rate limit matched"}
}

func rateDecision(action reqctx.Action, ruleID string, retry time.Duration, reason string) reqctx.Decision {
	return reqctx.Decision{Action: action, RuleID: ruleID, Phase: "ratelimit", Score: 0, RetryAfter: retry, Reason: reason}
}

func (p *Phase) policy(ctx *reqctx.RequestCtx) []compiledPolicy {
	key := policyKey{siteID: ctx.Site.ID, version: versionOf(ctx)}
	p.mu.RLock()
	policies, ok := p.policies[key]
	p.mu.RUnlock()
	if ok {
		return policies
	}
	policies = make([]compiledPolicy, 0, len(ctx.Site.RateLimits))
	for _, config := range ctx.Site.RateLimits {
		compiled := compiledPolicy{config: config}
		if config.Match == "" {
			compiled.err = fmt.Errorf("match expression is required")
		} else {
			compiled.match, compiled.err = wafcore.Compile(config.Match, wafcore.DefaultLimits())
		}
		if config.Action != "block" && config.Action != "challenge" && config.Action != "throttle" {
			compiled.err = fmt.Errorf("unsupported action %q", config.Action)
		}
		if config.Key != "ip" && config.Key != "ip+path" && config.Key != "ja3" && config.Key != "site" && !strings.HasPrefix(config.Key, "header:") && !strings.HasPrefix(config.Key, "cookie:") {
			compiled.err = fmt.Errorf("unsupported counter key %q", config.Key)
		}
		if (strings.HasPrefix(config.Key, "header:") && strings.TrimSpace(strings.TrimPrefix(config.Key, "header:")) == "") || (strings.HasPrefix(config.Key, "cookie:") && strings.TrimSpace(strings.TrimPrefix(config.Key, "cookie:")) == "") {
			compiled.err = fmt.Errorf("header/cookie counter key requires a name")
		}
		if config.Algorithm != "" && config.Algorithm != "token_bucket" && config.Algorithm != "sliding_window" {
			compiled.err = fmt.Errorf("unsupported algorithm %q", config.Algorithm)
		}
		policies = append(policies, compiled)
	}
	p.mu.Lock()
	p.policies[key] = policies
	if len(p.policies) > 10_000 {
		p.policies = map[policyKey][]compiledPolicy{key: policies}
	}
	p.mu.Unlock()
	return policies
}

func counterKey(kind string, ctx *reqctx.RequestCtx) (string, error) {
	var value string
	switch {
	case kind == "ip":
		if ctx.ClientIP != nil {
			value = ctx.ClientIP.String()
		}
	case kind == "ip+path":
		ip := ""
		if ctx.ClientIP != nil {
			ip = ctx.ClientIP.String()
		}
		value = ip + "\x00" + ctx.Path
	case kind == "ja3":
		value = ctx.JA3
	case kind == "site":
		value = "site"
	case strings.HasPrefix(kind, "header:"):
		value = ctx.Header(strings.TrimSpace(strings.TrimPrefix(kind, "header:")))
	case strings.HasPrefix(kind, "cookie:"):
		value = ctx.Cookie(strings.TrimSpace(strings.TrimPrefix(kind, "cookie:")))
	default:
		return "", fmt.Errorf("unsupported counter key %q", kind)
	}
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:]), nil
}

func versionOf(ctx *reqctx.RequestCtx) uint64 {
	if ctx.Snapshot == nil {
		return 0
	}
	return ctx.Snapshot.Version
}
