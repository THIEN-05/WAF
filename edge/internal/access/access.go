package access

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

type UnderAttack interface {
	Evaluate(*reqctx.RequestCtx) reqctx.Decision
}

type DisabledUnderAttack struct{}

func (DisabledUnderAttack) Evaluate(*reqctx.RequestCtx) reqctx.Decision { return reqctx.Decision{} }

type Phase struct {
	Resolver GeoResolver
	Bans     *BanTable
	Global   *PrefixTree
	Attack   UnderAttack

	mu       sync.RWMutex
	policies map[policyKey]sitePolicy
}

type policyKey struct {
	version uint64
	siteID  string
}

type sitePolicy struct {
	allowIPs       *PrefixTree
	blockIPs       *PrefixTree
	blockCountries map[string]struct{}
	blockASNs      map[uint32]struct{}
	err            error
}

func NewPhase(resolver GeoResolver, bans *BanTable, global *PrefixTree, attack UnderAttack) *Phase {
	if bans == nil {
		bans = NewBanTable(100_000, time.Now)
	}
	if attack == nil {
		attack = DisabledUnderAttack{}
	}
	return &Phase{Resolver: resolver, Bans: bans, Global: global, Attack: attack, policies: map[policyKey]sitePolicy{}}
}

func (p *Phase) Name() string { return "access" }

func (p *Phase) Handle(ctx *reqctx.RequestCtx) reqctx.Decision {
	if ctx.Site == nil {
		return reqctx.Decision{Action: reqctx.ActionAllow, RuleID: "access_no_site", Phase: p.Name(), Score: 0, Reason: "no routed site"}
	}
	policy := p.policy(ctx)
	if policy.err != nil {
		return accessDecision(reqctx.ActionBlock, "access_config", "site access configuration invalid: "+policy.err.Error())
	}
	ip := ctx.ClientIP
	if policy.allowIPs.Contains(ip) {
		return accessDecision(reqctx.ActionAllow, "allow_ip", "client IP is allow-listed")
	}
	if p.Bans.IsBanned(ip) {
		return accessDecision(reqctx.ActionBlock, "temporary_ban", "client IP is temporarily banned")
	}
	if policy.blockIPs.Contains(ip) {
		return accessDecision(reqctx.ActionBlock, "block_ip", "client IP matches site blocklist")
	}
	if len(policy.blockCountries) != 0 || len(policy.blockASNs) != 0 {
		p.resolveGeo(ctx)
		if _, blocked := policy.blockCountries[strings.ToUpper(ctx.GeoCountry)]; blocked && ctx.GeoCountry != "" {
			return accessDecision(reqctx.ActionBlock, "block_country", "client country is blocked")
		}
		if _, blocked := policy.blockASNs[ctx.GeoASN]; blocked && ctx.GeoASN != 0 {
			return accessDecision(reqctx.ActionBlock, "block_asn", "client ASN is blocked")
		}
	}
	if p.Global.Contains(ip) {
		return accessDecision(reqctx.ActionBlock, "global_blocklist", "client IP matches global blocklist")
	}
	decision := p.Attack.Evaluate(ctx)
	if decision.Action != reqctx.ActionAllow {
		if decision.Phase == "" {
			decision.Phase = p.Name()
		}
		if decision.RuleID == "" {
			decision.RuleID = "under_attack"
		}
		return decision
	}
	return accessDecision(reqctx.ActionAllow, "access_allow", "no access policy matched")
}

func accessDecision(action reqctx.Action, ruleID, reason string) reqctx.Decision {
	return reqctx.Decision{Action: action, RuleID: ruleID, Phase: "access", Score: 0, Reason: reason}
}

func (p *Phase) resolveGeo(ctx *reqctx.RequestCtx) {
	if ctx.GeoResolved {
		return
	}
	ctx.GeoResolved = true
	if p.Resolver == nil || ctx.ClientIP == nil {
		return
	}
	info, err := p.Resolver.Resolve(ctx.ClientIP)
	if err != nil {
		return // Geo data is optional; resolver failure defaults to allow for geo-only policies.
	}
	ctx.GeoCountry = strings.ToUpper(info.Country)
	ctx.GeoASN = info.ASN
}

func (p *Phase) policy(ctx *reqctx.RequestCtx) sitePolicy {
	key := policyKey{siteID: ctx.Site.ID}
	if ctx.Snapshot != nil {
		key.version = ctx.Snapshot.Version
	}
	p.mu.RLock()
	policy, ok := p.policies[key]
	p.mu.RUnlock()
	if ok {
		return policy
	}
	policy = compilePolicy(*ctx.Site)
	p.mu.Lock()
	p.policies[key] = policy
	if len(p.policies) > 10_000 {
		p.policies = map[policyKey]sitePolicy{key: policy}
	}
	p.mu.Unlock()
	return policy
}

func compilePolicy(site wafcore.Site) sitePolicy {
	plan := strings.ToLower(site.Plan)
	rank := map[string]int{"free": 0, "pro": 1, "business": 2, "enterprise": 3}[plan]
	if _, ok := map[string]struct{}{"free": {}, "pro": {}, "business": {}, "enterprise": {}}[plan]; !ok {
		return sitePolicy{err: fmt.Errorf("unsupported plan %q", site.Plan)}
	}
	if len(site.Access.BlockCountries) != 0 && rank < 1 {
		return sitePolicy{err: fmt.Errorf("plan %q does not include country blocking", site.Plan)}
	}
	if len(site.Access.BlockASNs) != 0 && rank < 2 {
		return sitePolicy{err: fmt.Errorf("plan %q does not include ASN blocking", site.Plan)}
	}
	allow, err := NewPrefixTree(site.Access.AllowIPs)
	if err != nil {
		return sitePolicy{err: err}
	}
	block, err := NewPrefixTree(site.Access.BlockIPs)
	if err != nil {
		return sitePolicy{err: err}
	}
	countries := make(map[string]struct{}, len(site.Access.BlockCountries))
	for _, country := range site.Access.BlockCountries {
		country = strings.ToUpper(strings.TrimSpace(country))
		if len(country) != 2 {
			return sitePolicy{err: fmt.Errorf("invalid country code %q", country)}
		}
		countries[country] = struct{}{}
	}
	asns := make(map[uint32]struct{}, len(site.Access.BlockASNs))
	for _, asn := range site.Access.BlockASNs {
		asns[asn] = struct{}{}
	}
	return sitePolicy{allowIPs: allow, blockIPs: block, blockCountries: countries, blockASNs: asns}
}

type BanTable struct {
	mu      sync.Mutex
	entries map[string]time.Time
	maxKeys int
	now     func() time.Time
}

func NewBanTable(maxKeys int, now func() time.Time) *BanTable {
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	if now == nil {
		now = time.Now
	}
	return &BanTable{entries: make(map[string]time.Time), maxKeys: maxKeys, now: now}
}

func (b *BanTable) Ban(ip net.IP, ttl time.Duration) error {
	if b == nil {
		return fmt.Errorf("ban table is nil")
	}
	if ip == nil || ttl <= 0 {
		return fmt.Errorf("IP and positive ban TTL are required")
	}
	key := ip.String()
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if expires, exists := b.entries[key]; exists && expires.After(now) {
		b.entries[key] = now.Add(ttl)
		return nil
	}
	b.cleanupLocked(now)
	if len(b.entries) >= b.maxKeys {
		return fmt.Errorf("temporary ban table is full")
	}
	b.entries[key] = now.Add(ttl)
	return nil
}

func (b *BanTable) IsBanned(ip net.IP) bool {
	if b == nil || ip == nil {
		return false
	}
	now := b.now()
	key := ip.String()
	b.mu.Lock()
	defer b.mu.Unlock()
	expires, ok := b.entries[key]
	if !ok {
		return false
	}
	if !expires.After(now) {
		delete(b.entries, key)
		return false
	}
	return true
}

func (b *BanTable) Cleanup() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cleanupLocked(b.now())
}

func (b *BanTable) cleanupLocked(now time.Time) int {
	removed := 0
	for key, expires := range b.entries {
		if !expires.After(now) {
			delete(b.entries, key)
			removed++
		}
	}
	return removed
}
