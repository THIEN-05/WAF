package snapshot

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/example/wafplatform/controlplane/internal/platform/secret"
	"github.com/example/wafplatform/pkg/wafcore"
)

type Candidate struct {
	Site           wafcore.Site
	ManagedRuleset string
	Err            error
}

type Record struct {
	Version   uint64
	Checksum  string
	Signature []byte
	ObjectKey string
	Signed    []byte
}

// Repository owns the consistent configuration read and snapshot metadata transactions.
type Repository interface {
	LoadRegion(context.Context, string) ([]Candidate, error)
	Latest(context.Context, string) (Record, error)
	Reserve(context.Context, string) (uint64, error)
	Publish(context.Context, string, Record) ([]string, error)
	Fail(context.Context, string, uint64) error
}

type Objects interface {
	Get(context.Context, string) ([]byte, error)
	Put(context.Context, string, []byte) error
	Delete(context.Context, string) error
}

type Signer interface {
	Sign(context.Context, wafcore.Snapshot) ([]byte, error)
}

type SecretSigner struct {
	Store secret.Store
	KeyID string
}

func (s SecretSigner) Sign(ctx context.Context, snapshot wafcore.Snapshot) ([]byte, error) {
	if s.Store == nil || s.KeyID == "" {
		return nil, errors.New("snapshot signing key is not configured")
	}
	raw, err := s.Store.Get(ctx, "snapshot-signing/"+s.KeyID)
	if err != nil {
		return nil, fmt.Errorf("load snapshot signing key: %w", err)
	}
	defer clear(raw)
	key := ed25519.PrivateKey(raw)
	return wafcore.SignSnapshot(snapshot, s.KeyID, key)
}

type Warning struct{ SiteID, Message string }

type Builder struct {
	Repository Repository
	Objects    Objects
	Signer     Signer
	PublicKeys map[string]ed25519.PublicKey
	Now        func() time.Time
	OnWarning  func(Warning)
}

func (b *Builder) Build(ctx context.Context, region string) (Record, error) {
	if !validRegion(region) {
		return Record{}, errors.New("invalid snapshot region")
	}
	if b.Repository == nil || b.Objects == nil || b.Signer == nil {
		return Record{}, errors.New("snapshot repository, object store, and signer are required")
	}
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	candidates, err := b.Repository.LoadRegion(ctx, region)
	if err != nil {
		return Record{}, fmt.Errorf("load region configuration: %w", err)
	}
	previous, previousErr := b.Repository.Latest(ctx, region)
	var old *wafcore.Snapshot
	if previousErr == nil {
		raw, getErr := b.Objects.Get(ctx, previous.ObjectKey)
		if getErr == nil {
			verified, verifyErr := wafcore.VerifySnapshot(raw, b.PublicKeys)
			if verifyErr == nil {
				old = &verified
			} else {
				b.warn("", "previous region snapshot failed signature validation; per-site fallback unavailable")
			}
		} else {
			b.warn("", "previous region snapshot unavailable; per-site fallback unavailable")
		}
	} else if !errors.Is(previousErr, ErrNoSnapshot) {
		return Record{}, fmt.Errorf("load previous region snapshot: %w", previousErr)
	}
	version, err := b.Repository.Reserve(ctx, region)
	if err != nil {
		return Record{}, fmt.Errorf("reserve snapshot version: %w", err)
	}
	snapshot := wafcore.Snapshot{SchemaVersion: wafcore.SnapshotSchemaVersion, Version: version, GeneratedAt: now().UTC(), Global: wafcore.GlobalConfig{ManagedRuleset: "managed-v1"}, Sites: make([]wafcore.Site, 0, len(candidates))}
	for _, candidate := range candidates {
		if candidate.ManagedRuleset != "" {
			snapshot.Global.ManagedRuleset = candidate.ManagedRuleset
			break
		}
	}
	oldSites := make(map[string]wafcore.Site)
	if old != nil {
		for _, site := range old.Sites {
			oldSites[site.ID] = site
		}
	}
	for _, candidate := range candidates {
		site := candidate.Site
		if candidate.Err == nil {
			applyEntitlementCaps(&site)
			if site.Entitlements.BotJSChallenge && site.Secrets.ChallengeHMACKeyID == "" {
				site.Entitlements.BotJSChallenge = false
				if site.Bot.Mode == "challenge" {
					site.Bot.Mode = "monitor"
				}
				b.warn(site.ID, "bot JS challenge disabled because its signing key reference is missing")
				applyEntitlementCaps(&site)
			}
			candidate.Err = validateSite(site)
		}
		if candidate.Err != nil {
			b.warn(site.ID, candidate.Err.Error())
			if oldSite, ok := oldSites[site.ID]; ok {
				snapshot.Sites = append(snapshot.Sites, oldSite)
			} else if previousErr == nil && old == nil {
				_ = b.Repository.Fail(ctx, region, version)
				return Record{}, fmt.Errorf("cannot isolate site %q failure because the active snapshot is unavailable: %w", site.ID, candidate.Err)
			}
			continue
		}
		snapshot.Sites = append(snapshot.Sites, site)
	}
	if err = snapshot.Validate(); err != nil {
		_ = b.Repository.Fail(ctx, region, version)
		return Record{}, fmt.Errorf("assembled region snapshot is invalid: %w", err)
	}
	signed, err := b.Signer.Sign(ctx, snapshot)
	if err != nil {
		_ = b.Repository.Fail(ctx, region, version)
		return Record{}, fmt.Errorf("sign region snapshot: %w", err)
	}
	envelope, err := decodeSignedEnvelope(signed)
	if err != nil {
		_ = b.Repository.Fail(ctx, region, version)
		return Record{}, err
	}
	objectKey := fmt.Sprintf("snapshots/%s/%d.json.gz", region, version)
	if err = b.Objects.Put(ctx, objectKey, signed); err != nil {
		_ = b.Repository.Fail(ctx, region, version)
		return Record{}, fmt.Errorf("store signed snapshot: %w", err)
	}
	record := Record{Version: version, Checksum: envelope.Checksum, Signature: mustHex(envelope.Signature), ObjectKey: objectKey, Signed: signed}
	removed, err := b.Repository.Publish(ctx, region, record)
	if err != nil {
		_ = b.Repository.Fail(ctx, region, version)
		_ = b.Objects.Delete(ctx, objectKey)
		return Record{}, fmt.Errorf("publish snapshot metadata: %w", err)
	}
	for _, key := range removed {
		_ = b.Objects.Delete(ctx, key)
	}
	return record, nil
}

func (b *Builder) warn(siteID, message string) {
	if b.OnWarning != nil {
		b.OnWarning(Warning{SiteID: siteID, Message: message})
	}
}

func validateSite(site wafcore.Site) error {
	for _, rule := range site.Rules {
		if _, err := wafcore.Compile(rule.Expression, wafcore.DefaultLimits()); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
	}
	for _, policy := range site.RateLimits {
		if _, err := wafcore.Compile(policy.Match, wafcore.DefaultLimits()); err != nil {
			return fmt.Errorf("rate-limit policy %s: %w", policy.ID, err)
		}
	}
	snapshot := wafcore.Snapshot{SchemaVersion: wafcore.SnapshotSchemaVersion, Version: 1, GeneratedAt: time.Unix(1, 0).UTC(), Global: wafcore.GlobalConfig{ManagedRuleset: "validation"}, Sites: []wafcore.Site{site}}
	return snapshot.Validate()
}

func validRegion(region string) bool {
	if region == "" || len(region) > 64 {
		return false
	}
	for _, r := range region {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
		if !valid {
			return false
		}
	}
	return true
}

func applyEntitlementCaps(site *wafcore.Site) {
	if site.Entitlements.MaxRules > 0 && len(site.Rules) > site.Entitlements.MaxRules {
		site.Rules = site.Rules[:site.Entitlements.MaxRules]
	}
	if site.Entitlements.MaxRateLimitPolicies > 0 && len(site.RateLimits) > site.Entitlements.MaxRateLimitPolicies {
		site.RateLimits = site.RateLimits[:site.Entitlements.MaxRateLimitPolicies]
	}
	if site.Entitlements.MaxBodyBytes > 0 && site.WAF.BodyLimitKB > 0 {
		maxKB := site.Entitlements.MaxBodyBytes / 1024
		if maxKB == 0 || site.WAF.BodyLimitKB > maxKB {
			site.WAF.BodyLimitKB = maxKB
		}
	}
	if !site.Entitlements.BotJSChallenge {
		site.Secrets.ChallengeHMACKeyID = ""
	}
	if !site.Entitlements.BotJSChallenge && !site.Entitlements.BotCaptcha && site.Bot.Mode == "challenge" {
		site.Bot.Mode = "monitor"
	}
}

type snapshotEnvelope struct {
	Checksum  string `json:"checksum_sha256"`
	Signature string `json:"signature_ed25519"`
}

func decodeSignedEnvelope(raw []byte) (snapshotEnvelope, error) {
	var env snapshotEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return snapshotEnvelope{}, fmt.Errorf("decode signer envelope: %w", err)
	}
	if len(env.Checksum) != 64 {
		return snapshotEnvelope{}, errors.New("signer returned invalid checksum")
	}
	if _, err := hex.DecodeString(env.Signature); err != nil {
		return snapshotEnvelope{}, errors.New("signer returned invalid signature")
	}
	return env, nil
}

func mustHex(raw string) []byte { b, _ := hex.DecodeString(raw); return b }

var ErrNoSnapshot = errors.New("no published snapshot")
