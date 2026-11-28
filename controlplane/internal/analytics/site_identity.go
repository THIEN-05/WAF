package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type RedisSiteResolver struct {
	Cache redis.UniversalClient
	Pool  *pgxpool.Pool
	TTL   time.Duration
}

func (r RedisSiteResolver) ResolveSite(ctx context.Context, rawSiteID string) (SiteIdentity, error) {
	siteID, err := uuid.Parse(rawSiteID)
	if err != nil || r.Cache == nil || r.Pool == nil {
		return SiteIdentity{}, errors.New("invalid site identity lookup")
	}
	key := "analytics:site-tenant:" + siteID.String()
	if raw, cacheErr := r.Cache.Get(ctx, key).Result(); cacheErr == nil {
		var identity SiteIdentity
		if json.Unmarshal([]byte(raw), &identity) == nil && identity.TenantID != "" && identity.RetentionDay > 0 {
			return identity, nil
		}
	}
	var identity SiteIdentity
	var entitlements string
	err = r.Pool.QueryRow(ctx, `SELECT s.tenant_id::text,p.entitlements::text
  FROM public.sites s
  JOIN public.subscriptions sub ON sub.tenant_id=s.tenant_id AND sub.status='active'
  JOIN public.plans p ON p.id=sub.plan_id
  WHERE s.id=$1 AND s.deleted_at IS NULL AND s.status='active'
  ORDER BY sub.created_at DESC LIMIT 1`, siteID).Scan(&identity.TenantID, &entitlements)
	if errors.Is(err, pgx.ErrNoRows) {
		return SiteIdentity{}, errors.New("unknown ingest site")
	}
	if err != nil {
		return SiteIdentity{}, fmt.Errorf("lookup ingest site policy: %w", err)
	}
	var plan struct {
		Limits map[string]json.RawMessage `json:"limits"`
	}
	if err = json.Unmarshal([]byte(entitlements), &plan); err != nil {
		return SiteIdentity{}, errors.New("invalid site retention policy")
	}
	retention, err := strconv.ParseUint(string(plan.Limits["log_retention_days"]), 10, 16)
	if err != nil || retention == 0 {
		return SiteIdentity{}, errors.New("site retention policy is unavailable")
	}
	identity.RetentionDay = uint16(retention)
	encoded, _ := json.Marshal(identity)
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	_ = r.Cache.Set(ctx, key, encoded, ttl).Err()
	return identity, nil
}
