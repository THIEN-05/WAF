package bot

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
)

type Phase struct {
	Challenges   *ChallengeManager
	Verified     VerifiedBotChecker
	IPTrust      IPReputation
	Fingerprints FingerprintReputation
	mu           sync.Mutex
	behavior     map[string]*behavior
	maxKeys      int
	now          func() time.Time
}
type behavior struct {
	count, notFound int
	staticCount     int
	windowStart     time.Time
	windowCount     int
	lastPath        string
	sequential      int
}
type VerifiedBotChecker interface{ IsVerified(string, net.IP) bool }
type IPReputation interface{ Score(net.IP, uint32) int }
type FingerprintReputation interface{ IsAutomation(string, string) bool }
type NoReputation struct{}

func (NoReputation) Score(net.IP, uint32) int { return 0 }

func NewPhase(ch *ChallengeManager, verified VerifiedBotChecker) *Phase {
	return &Phase{Challenges: ch, Verified: verified, IPTrust: NoReputation{}, behavior: map[string]*behavior{}, maxKeys: 100_000, now: time.Now}
}
func (p *Phase) Name() string { return "bot" }
func (p *Phase) Handle(c *reqctx.RequestCtx) reqctx.Decision {
	if c.Site == nil || c.Site.Bot.Mode == "" || c.Site.Bot.Mode == "off" {
		return reqctx.Decision{Action: reqctx.ActionAllow, Phase: "bot", Reason: "bot detection disabled"}
	}
	if c.Site.Entitlements.VerifiedBots && p.Verified != nil && p.Verified.IsVerified(c.Header("User-Agent"), c.ClientIP) {
		c.BotVerified = true
		c.AddTag("verified_bot")
		c.BotScore = 0
		return reqctx.Decision{Action: reqctx.ActionAllow, Phase: "bot", Reason: "verified search bot", Tags: []string{"verified_bot"}}
	}
	now := p.now()
	key := c.Site.ID + "|" + c.ClientIP.String()
	p.mu.Lock()
	b := p.behavior[key]
	if b == nil {
		if len(p.behavior) >= p.maxKeys {
			p.evictOneLocked()
		}
		b = &behavior{windowStart: now}
		p.behavior[key] = b
	}
	b.count++
	if now.Sub(b.windowStart) >= 10*time.Second || now.Before(b.windowStart) {
		b.windowStart, b.windowCount = now, 0
	}
	b.windowCount++
	if c.Path != b.lastPath {
		if pathSequence(b.lastPath, c.Path) {
			b.sequential++
		}
		b.lastPath = c.Path
	}
	if staticPath(c.Path) {
		b.staticCount++
	}
	validCookie := c.Site.Entitlements.BotJSChallenge && p.Challenges != nil && p.Challenges.ValidCookie(c.Cookie(VerificationCookie), c.Site.ID, c.Header("User-Agent"), c.ClientIP, now)
	count, nf, seq, rate, staticCount := b.count, b.notFound, b.sequential, b.windowCount, b.staticCount
	p.mu.Unlock()
	score := 0
	ua := strings.ToLower(c.Header("User-Agent"))
	switch {
	case ua == "":
		score += 18
	case containsAny(ua, "curl/", "python-requests", "go-http-client", "scrapy", "wget/", "java/"):
		score += 24
	}
	if containsAny(ua, "googlebot", "bingbot", "duckduckbot") {
		score += 20
	}
	if containsAny(ua, "headless", "phantomjs", "selenium", "playwright", "puppeteer") {
		score += 35
	}
	if c.Header("Accept") == "" {
		score += 8
	}
	if c.Header("Accept-Language") == "" {
		score += 6
	}
	if strings.Contains(ua, "chrome/") && c.JA3 != "" && p.Fingerprints != nil && p.Fingerprints.IsAutomation(c.JA3, c.JA4) {
		score += 25
	}
	if p.IPTrust != nil {
		score += p.IPTrust.Score(c.ClientIP, c.GeoASN)
	}
	if rate > 8 {
		score += min(20, (rate-8)*2)
	}
	if nf > 0 && count > 0 {
		score += min(20, nf*30/count)
	}
	if seq >= 3 {
		score += min(15, seq*3)
	}
	if count >= 10 && staticCount == 0 {
		score += 8
	}
	if count >= 3 && !validCookie {
		score += 8
	}
	if validCookie {
		score -= 20
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	c.BotScore = score
	threshold := c.Site.Bot.Threshold
	if threshold <= 0 {
		threshold = 70
	}
	if score < threshold || c.Site.Bot.Mode == "monitor" {
		return reqctx.Decision{Action: reqctx.ActionAllow, Phase: "bot", Score: score, Reason: "bot score below enforcement threshold"}
	}
	if c.Site.Bot.Mode == "challenge" && c.Site.Entitlements.BotJSChallenge && p.Challenges != nil {
		diff := c.Site.Bot.ChallengeDifficulty
		if diff == 0 {
			diff = 18
		}
		keyID := c.Site.Secrets.ChallengeHMACKeyID
		c.BotChallengeToken, _ = p.Challenges.IssueForKey(c.Site.ID, keyID, c.Header("User-Agent"), c.ClientIP, diff, now)
		return reqctx.Decision{Action: reqctx.ActionChallenge, Phase: "bot", RuleID: "bot-score", Score: score, Reason: "bot score exceeded threshold"}
	}
	if c.Site.Bot.Mode == "block" {
		return reqctx.Decision{Action: reqctx.ActionBlock, Phase: "bot", RuleID: "bot-score", Score: score, Reason: "bot score exceeded threshold"}
	}
	return reqctx.Decision{Action: reqctx.ActionAllow, Phase: "bot", Score: score, Reason: "challenge not entitled"}
}
func (p *Phase) RecordResponse(siteID string, ip net.IP, path string, status int) {
	if status != http.StatusNotFound {
		return
	}
	key := siteID + "|" + ip.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if b := p.behavior[key]; b != nil {
		b.notFound++
	}
}
func (p *Phase) evictOneLocked() {
	for k := range p.behavior {
		delete(p.behavior, k)
		return
	}
}
func pathSequence(a, b string) bool {
	if a == "" || len(a) > 120 || len(b) > 120 {
		return false
	}
	i := len(a) - 1
	for i >= 0 && a[i] >= '0' && a[i] <= '9' {
		i--
	}
	if i == len(a)-1 {
		return false
	}
	j := len(b) - 1
	for j >= 0 && b[j] >= '0' && b[j] <= '9' {
		j--
	}
	if a[:i+1] != b[:j+1] {
		return false
	}
	var x, y int
	for _, v := range a[i+1:] {
		x = x*10 + int(v-'0')
	}
	for _, v := range b[j+1:] {
		y = y*10 + int(v-'0')
	}
	return y == x+1
}
func containsAny(s string, values ...string) bool {
	for _, v := range values {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
func staticPath(path string) bool {
	p := strings.ToLower(path)
	return containsAny(p, ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
