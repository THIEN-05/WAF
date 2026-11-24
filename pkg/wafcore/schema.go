package wafcore

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const SnapshotSchemaVersion = 1
const LogSchemaVersion = 1

type Snapshot struct {
	SchemaVersion int          `json:"schema_version" yaml:"schema_version"`
	Version       uint64       `json:"version" yaml:"version"`
	GeneratedAt   time.Time    `json:"generated_at" yaml:"generated_at"`
	Global        GlobalConfig `json:"global" yaml:"global"`
	Sites         []Site       `json:"sites" yaml:"sites"`
}

type GlobalConfig struct {
	BlocklistsVersion uint64 `json:"blocklists_version" yaml:"blocklists_version"`
	ManagedRuleset    string `json:"managed_ruleset" yaml:"managed_ruleset"`
}

type Entitlements struct {
	MaxRules       int  `json:"max_rules" yaml:"max_rules"`
	MaxBodyBytes   int  `json:"max_body_bytes" yaml:"max_body_bytes"`
	MaxRegexBytes  int  `json:"max_regex_bytes" yaml:"max_regex_bytes"`
	MaxCounterKeys int  `json:"max_counter_keys" yaml:"max_counter_keys"`
	BotJSChallenge bool `json:"bot_js_challenge" yaml:"bot_js_challenge"`
	BotCaptcha     bool `json:"bot_captcha" yaml:"bot_captcha"`
	VerifiedBots   bool `json:"verified_bots" yaml:"verified_bots"`
}

type Site struct {
	ID           string           `json:"id" yaml:"id"`
	TenantID     string           `json:"tenant_id" yaml:"tenant_id"`
	Status       string           `json:"status" yaml:"status"`
	Plan         string           `json:"plan" yaml:"plan"`
	Entitlements Entitlements     `json:"entitlements" yaml:"entitlements"`
	Domains      []string         `json:"domains" yaml:"domains"`
	Origins      []Origin         `json:"origins" yaml:"origins"`
	FailMode     string           `json:"fail_mode" yaml:"fail_mode"`
	WAF          WAFConfig        `json:"waf" yaml:"waf"`
	Access       AccessConfig     `json:"access" yaml:"access"`
	RateLimits   []RateLimit      `json:"rate_limits" yaml:"rate_limits"`
	Rules        []Rule           `json:"rules" yaml:"rules"`
	Bot          BotConfig        `json:"bot" yaml:"bot"`
	Cache        CacheConfig      `json:"cache" yaml:"cache"`
	Secrets      SecretReferences `json:"secrets" yaml:"secrets"`
}

type Origin struct {
	URL        string `json:"url" yaml:"url"`
	Weight     int    `json:"weight" yaml:"weight"`
	HostHeader string `json:"host_header,omitempty" yaml:"host_header,omitempty"`
	TLSVerify  bool   `json:"tls_verify" yaml:"tls_verify"`
}

type WAFConfig struct {
	Mode               string         `json:"mode" yaml:"mode"`
	Sensitivity        string         `json:"sensitivity" yaml:"sensitivity"`
	BodyLimitKB        int            `json:"body_limit_kb" yaml:"body_limit_kb"`
	Paranoia           int            `json:"paranoia,omitempty" yaml:"paranoia,omitempty"`
	BudgetMS           int            `json:"budget_ms,omitempty" yaml:"budget_ms,omitempty"`
	ScanLimitBytes     int            `json:"scan_limit_bytes,omitempty" yaml:"scan_limit_bytes,omitempty"`
	TruncatedBodyScore int            `json:"truncated_body_score,omitempty" yaml:"truncated_body_score,omitempty"`
	Exclusions         []WAFExclusion `json:"exclusions" yaml:"exclusions"`
}

type WAFExclusion struct {
	RuleID string `json:"rule_id" yaml:"rule_id"`
	Path   string `json:"path,omitempty" yaml:"path,omitempty"`
	Param  string `json:"param,omitempty" yaml:"param,omitempty"`
}

type AccessConfig struct {
	AllowIPs       []string `json:"allow_ips" yaml:"allow_ips"`
	BlockIPs       []string `json:"block_ips" yaml:"block_ips"`
	BlockCountries []string `json:"block_countries" yaml:"block_countries"`
	BlockASNs      []uint32 `json:"block_asns" yaml:"block_asns"`
}

type RateLimit struct {
	ID        string `json:"id" yaml:"id"`
	Match     string `json:"match" yaml:"match"`
	Key       string `json:"key" yaml:"key"`
	Algorithm string `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Limit     uint64 `json:"limit" yaml:"limit"`
	WindowS   uint32 `json:"window_s" yaml:"window_s"`
	Action    string `json:"action" yaml:"action"`
	BanS      uint32 `json:"ban_s" yaml:"ban_s"`
}

type Rule struct {
	ID         string     `json:"id" yaml:"id"`
	Priority   int        `json:"priority" yaml:"priority"`
	Expression string     `json:"expr" yaml:"expr"`
	Action     string     `json:"action" yaml:"action"`
	Mode       string     `json:"mode,omitempty" yaml:"mode,omitempty"`
	Policy     string     `json:"policy,omitempty" yaml:"policy,omitempty"`
	Tag        string     `json:"tag,omitempty" yaml:"tag,omitempty"`
	Phase      string     `json:"phase,omitempty" yaml:"phase,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

type BotConfig struct {
	Mode                string `json:"mode" yaml:"mode"`
	Threshold           int    `json:"threshold" yaml:"threshold"`
	ChallengeDifficulty int    `json:"challenge_difficulty,omitempty" yaml:"challenge_difficulty,omitempty"`
}

type CacheConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type SecretReferences struct {
	ChallengeHMACKeyID  string            `json:"challenge_hmac_key_id,omitempty" yaml:"challenge_hmac_key_id,omitempty"`
	OriginCredentialIDs []string          `json:"origin_credential_ids,omitempty" yaml:"origin_credential_ids,omitempty"`
	Additional          map[string]string `json:"additional,omitempty" yaml:"additional,omitempty"`
}

// Validate returns actionable, site-scoped schema errors. Secret values never belong in a snapshot.
func (s Snapshot) Validate() error {
	var errs []string
	if s.SchemaVersion != SnapshotSchemaVersion {
		errs = append(errs, fmt.Sprintf("schema_version: got %d, supported %d", s.SchemaVersion, SnapshotSchemaVersion))
	}
	if s.Version == 0 {
		errs = append(errs, "version: must be greater than zero")
	}
	if s.GeneratedAt.IsZero() {
		errs = append(errs, "generated_at: is required")
	}
	if len(s.Global.ManagedRuleset) == 0 {
		errs = append(errs, "global.managed_ruleset: is required")
	}
	seen := map[string]struct{}{}
	for i, site := range s.Sites {
		p := fmt.Sprintf("sites[%d]", i)
		if site.ID == "" {
			errs = append(errs, p+".id: is required")
		}
		if site.TenantID == "" {
			errs = append(errs, p+".tenant_id: is required")
		}
		if site.ID != "" {
			if _, ok := seen[site.ID]; ok {
				errs = append(errs, p+".id: duplicate site id")
			}
			seen[site.ID] = struct{}{}
		}
		if site.Status != "active" && site.Status != "pending" && site.Status != "suspended" {
			errs = append(errs, p+".status: must be active, pending, or suspended")
		}
		if site.Plan == "" {
			errs = append(errs, p+".plan: is required")
		}
		if site.FailMode != "open" && site.FailMode != "closed" {
			errs = append(errs, p+".fail_mode: must be open or closed")
		}
		if len(site.Domains) == 0 {
			errs = append(errs, p+".domains: at least one domain is required")
		}
		for j, d := range site.Domains {
			if d == "" || strings.ContainsAny(d, " /\t\r\n") {
				errs = append(errs, fmt.Sprintf("%s.domains[%d]: invalid domain", p, j))
			}
		}
		if len(site.Origins) == 0 {
			errs = append(errs, p+".origins: at least one origin is required")
		}
		for j, o := range site.Origins {
			u, e := url.Parse(o.URL)
			if e != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				errs = append(errs, fmt.Sprintf("%s.origins[%d].url: must be an absolute http or https URL", p, j))
			}
			if o.Weight < 0 {
				errs = append(errs, fmt.Sprintf("%s.origins[%d].weight: must not be negative", p, j))
			}
		}
		if site.WAF.Mode != "" && site.WAF.Mode != "off" && site.WAF.Mode != "monitor" && site.WAF.Mode != "block" && site.WAF.Mode != "challenge" {
			errs = append(errs, p+".waf.mode: must be off, monitor, block, or challenge")
		}
		if site.Bot.Mode != "" && site.Bot.Mode != "off" && site.Bot.Mode != "monitor" && site.Bot.Mode != "block" && site.Bot.Mode != "challenge" {
			errs = append(errs, p+".bot.mode: must be off, monitor, block, or challenge")
		}
		if site.Bot.Threshold < 0 || site.Bot.Threshold > 100 {
			errs = append(errs, p+".bot.threshold: must be between 0 and 100")
		}
		if site.Bot.ChallengeDifficulty < 0 || site.Bot.ChallengeDifficulty > 24 {
			errs = append(errs, p+".bot.challenge_difficulty: must be between 0 and 24")
		}
		if site.Entitlements.BotJSChallenge && site.Secrets.ChallengeHMACKeyID == "" {
			errs = append(errs, p+".secrets.challenge_hmac_key_id: required when bot JS challenge is entitled")
		}
		if strings.EqualFold(site.Plan, "free") && (site.Entitlements.BotJSChallenge || site.Entitlements.BotCaptcha) {
			errs = append(errs, p+".entitlements: Free plan cannot enable bot JS challenge or CAPTCHA")
		}
		if len(site.Secrets.ChallengeHMACKeyID) > 64 || strings.ContainsAny(site.Secrets.ChallengeHMACKeyID, " /\\\t\r\n") {
			errs = append(errs, p+".secrets.challenge_hmac_key_id: invalid key identifier")
		}
		if site.WAF.BodyLimitKB < 0 {
			errs = append(errs, p+".waf.body_limit_kb: must not be negative")
		}
		if site.WAF.Sensitivity != "" && site.WAF.Sensitivity != "low" && site.WAF.Sensitivity != "medium" && site.WAF.Sensitivity != "high" {
			errs = append(errs, p+".waf.sensitivity: must be low, medium, or high")
		}
		if site.WAF.BodyLimitKB > 0 && site.Entitlements.MaxBodyBytes > 0 && site.WAF.BodyLimitKB*1024 > site.Entitlements.MaxBodyBytes {
			errs = append(errs, p+".waf.body_limit_kb: exceeds entitlement max_body_bytes")
		}
		if site.WAF.Paranoia < 0 || site.WAF.Paranoia > 4 {
			errs = append(errs, p+".waf.paranoia: must be between 1 and 4 when set")
		}
		if site.WAF.BudgetMS < 0 {
			errs = append(errs, p+".waf.budget_ms: must not be negative")
		}
		if site.WAF.ScanLimitBytes < 0 || site.WAF.ScanLimitBytes > 4*1024 {
			errs = append(errs, p+".waf.scan_limit_bytes: must be between 0 and 4096")
		}
		if site.WAF.TruncatedBodyScore < 0 || site.WAF.TruncatedBodyScore > 5 {
			errs = append(errs, p+".waf.truncated_body_score: must be between 0 and 5")
		}
		for j, exclusion := range site.WAF.Exclusions {
			if exclusion.RuleID == "" || (exclusion.Path == "" && exclusion.Param == "") {
				errs = append(errs, fmt.Sprintf("%s.waf.exclusions[%d]: rule_id and path or param are required", p, j))
			}
		}
		if site.Entitlements.MaxRules > 0 && len(site.Rules) > site.Entitlements.MaxRules {
			errs = append(errs, fmt.Sprintf("%s.rules: %d rules exceed entitlement max_rules %d", p, len(site.Rules), site.Entitlements.MaxRules))
		}
		if site.Entitlements.MaxRegexBytes > 0 {
			for j, r := range site.Rules {
				if len(extractMatches(r.Expression)) > 0 {
					for _, pattern := range extractMatches(r.Expression) {
						if len(pattern) > site.Entitlements.MaxRegexBytes {
							errs = append(errs, fmt.Sprintf("%s.rules[%d].expr: regex is %d bytes, limit is %d", p, j, len(pattern), site.Entitlements.MaxRegexBytes))
						}
					}
				}
			}
		}
		for j, r := range site.Rules {
			if r.ID == "" {
				errs = append(errs, fmt.Sprintf("%s.rules[%d].id: is required", p, j))
			}
			if r.Expression == "" {
				errs = append(errs, fmt.Sprintf("%s.rules[%d].expr: is required", p, j))
			}
			if r.Action != "allow" && r.Action != "block" && r.Action != "challenge" && r.Action != "log" && r.Action != "rate_limit" && r.Action != "tag" && r.Action != "skip" {
				errs = append(errs, fmt.Sprintf("%s.rules[%d].action: unsupported action %q", p, j, r.Action))
			}
			if r.Mode != "" && r.Mode != "log" {
				errs = append(errs, fmt.Sprintf("%s.rules[%d].mode: must be log when set", p, j))
			}
			if r.Action == "rate_limit" && r.Policy == "" {
				errs = append(errs, fmt.Sprintf("%s.rules[%d].policy: required for rate_limit action", p, j))
			}
			if r.Action == "tag" && r.Tag == "" {
				errs = append(errs, fmt.Sprintf("%s.rules[%d].tag: required for tag action", p, j))
			}
			if r.Action == "skip" && r.Phase == "" {
				errs = append(errs, fmt.Sprintf("%s.rules[%d].phase: required for skip action", p, j))
			}
			if r.Action == "skip" && r.Phase != "ratelimit" && r.Phase != "rules" && r.Phase != "waf" && r.Phase != "bot" && r.Phase != "cache" && r.Phase != "proxy" {
				errs = append(errs, fmt.Sprintf("%s.rules[%d].phase: unsupported phase %q", p, j, r.Phase))
			}
		}
		for j, rl := range site.RateLimits {
			if rl.ID == "" {
				errs = append(errs, fmt.Sprintf("%s.rate_limits[%d].id: is required", p, j))
			}
			if rl.Limit == 0 || rl.WindowS == 0 {
				errs = append(errs, fmt.Sprintf("%s.rate_limits[%d]: limit and window_s must be greater than zero", p, j))
			}
			if rl.Algorithm != "" && rl.Algorithm != "token_bucket" && rl.Algorithm != "sliding_window" {
				errs = append(errs, fmt.Sprintf("%s.rate_limits[%d].algorithm: must be token_bucket or sliding_window", p, j))
			}
			validKey := rl.Key == "ip" || rl.Key == "ip+path" || rl.Key == "ja3" || rl.Key == "site" || strings.HasPrefix(rl.Key, "header:") || strings.HasPrefix(rl.Key, "cookie:")
			if !validKey || (strings.HasPrefix(rl.Key, "header:") && strings.TrimSpace(strings.TrimPrefix(rl.Key, "header:")) == "") || (strings.HasPrefix(rl.Key, "cookie:") && strings.TrimSpace(strings.TrimPrefix(rl.Key, "cookie:")) == "") {
				errs = append(errs, fmt.Sprintf("%s.rate_limits[%d].key: unsupported counter key %q", p, j, rl.Key))
			}
			if rl.Action != "block" && rl.Action != "challenge" && rl.Action != "throttle" {
				errs = append(errs, fmt.Sprintf("%s.rate_limits[%d].action: must be block, challenge, or throttle", p, j))
			}
		}
		for j, cidr := range append(append([]string{}, site.Access.AllowIPs...), site.Access.BlockIPs...) {
			if _, _, e := net.ParseCIDR(cidr); e != nil {
				if net.ParseIP(cidr) == nil {
					errs = append(errs, fmt.Sprintf("%s.access.ip[%d]: invalid IP or CIDR %q", p, j, cidr))
				}
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("snapshot validation failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

var matchesCallRE = regexp.MustCompile(`(?i)matches\s+'((?:\\.|[^'])*)'`)

func extractMatches(s string) []string {
	out := matchesCallRE.FindAllStringSubmatch(s, -1)
	r := make([]string, 0, len(out))
	for _, m := range out {
		r = append(r, m[1])
	}
	return r
}

type LogEvent struct {
	SchemaVersion int       `json:"schema_version"`
	TS            time.Time `json:"ts"`
	RequestID     string    `json:"request_id"`
	SiteID        string    `json:"site_id"`
	TenantID      string    `json:"tenant_id"`
	EdgeID        string    `json:"edge_id"`
	Region        string    `json:"region"`
	ClientIP      string    `json:"client_ip"`
	Country       string    `json:"country"`
	ASN           uint32    `json:"asn"`
	JA3           string    `json:"ja3"`
	Method        string    `json:"method"`
	Host          string    `json:"host"`
	Path          string    `json:"path"`
	Status        uint16    `json:"status"`
	BytesIn       uint64    `json:"bytes_in"`
	BytesOut      uint64    `json:"bytes_out"`
	LatencyMS     uint32    `json:"latency_ms"`
	UpstreamMS    uint32    `json:"upstream_ms"`
	Action        string    `json:"action"`
	RuleID        string    `json:"rule_id"`
	WAFScore      uint16    `json:"waf_score"`
	BotScore      uint8     `json:"bot_score"`
	CacheStatus   string    `json:"cache_status"`
	Tags          []string  `json:"tags"`
}

func (e LogEvent) Validate() error {
	if e.SchemaVersion != LogSchemaVersion {
		return fmt.Errorf("schema_version: got %d, supported %d", e.SchemaVersion, LogSchemaVersion)
	}
	if e.TS.IsZero() {
		return fmt.Errorf("ts: is required")
	}
	if e.SiteID == "" || e.TenantID == "" || e.RequestID == "" {
		return fmt.Errorf("request_id, site_id, and tenant_id are required")
	}
	if e.ClientIP != "" && net.ParseIP(e.ClientIP) == nil {
		return fmt.Errorf("client_ip: invalid IP address")
	}
	return nil
}

type SiteStats1m struct {
	Minute      time.Time `json:"minute"`
	TenantID    string    `json:"tenant_id"`
	SiteID      string    `json:"site_id"`
	Requests    uint64    `json:"requests"`
	Blocked     uint64    `json:"blocked"`
	Challenged  uint64    `json:"challenged"`
	RateLimited uint64    `json:"rate_limited"`
	CacheHits   uint64    `json:"cache_hits"`
	BytesOut    uint64    `json:"bytes_out"`
	Status5xx   uint64    `json:"status_5xx"`
}

func (s SiteStats1m) Validate() error {
	if s.Minute.IsZero() {
		return fmt.Errorf("minute: is required")
	}
	if s.Minute.Second() != 0 || s.Minute.Nanosecond() != 0 {
		return fmt.Errorf("minute: must be aligned to a minute")
	}
	if s.TenantID == "" || s.SiteID == "" {
		return fmt.Errorf("tenant_id and site_id are required")
	}
	return nil
}
