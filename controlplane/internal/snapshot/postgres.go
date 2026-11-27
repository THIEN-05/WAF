package snapshot

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct{ Pool *pgxpool.Pool }

var ErrStaleBuild = errors.New("snapshot build finished behind a newer active version")

func (p PostgresRepository) LoadRegion(ctx context.Context, region string) ([]Candidate, error) {
	if p.Pool == nil {
		return nil, fmt.Errorf("snapshot database pool is required")
	}
	_ = region // Sites are replicated to every region until site placement is part of the schema.
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT s.id::text,s.tenant_id::text,s.status,s.fail_mode,p.code,p.entitlements::text,
  coalesce(w.mode,'block'),coalesce(w.sensitivity,'medium'),coalesce(w.body_limit_kb,8),coalesce(w.ruleset_version,'managed-v1'),coalesce(w.exclusions,'[]'::jsonb)::text
  FROM public.sites s
  JOIN LATERAL (SELECT plan_id FROM public.subscriptions sub WHERE sub.tenant_id=s.tenant_id AND sub.status='active' ORDER BY sub.created_at DESC LIMIT 1) sub ON true
  JOIN public.plans p ON p.id=sub.plan_id
  LEFT JOIN public.waf_settings w ON w.site_id=s.id
  WHERE s.deleted_at IS NULL AND s.status IN ('active','pending_dns','pending') ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	type base struct {
		id, tenant, status, failMode, plan, entitlementJSON string
		wafMode, sensitivity                                string
		bodyKB                                              int
		ruleset, exclusions                                 string
	}
	var bases []base
	for rows.Next() {
		var row base
		if err = rows.Scan(&row.id, &row.tenant, &row.status, &row.failMode, &row.plan, &row.entitlementJSON, &row.wafMode, &row.sensitivity, &row.bodyKB, &row.ruleset, &row.exclusions); err != nil {
			rows.Close()
			return nil, err
		}
		bases = append(bases, row)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	out := make([]Candidate, 0, len(bases))
	for _, row := range bases {
		savepoint := "snapshot_site_" + strconv.Itoa(len(out))
		if _, err = tx.Exec(ctx, "SAVEPOINT "+savepoint); err != nil {
			return nil, err
		}
		site, siteErr := p.loadSite(ctx, tx, row.id, row.tenant, row.status, row.failMode, row.plan, row.entitlementJSON, row.wafMode, row.sensitivity, row.bodyKB, row.exclusions)
		if siteErr != nil {
			if _, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); err != nil {
				return nil, err
			}
		}
		if _, err = tx.Exec(ctx, "RELEASE SAVEPOINT "+savepoint); err != nil {
			return nil, err
		}
		out = append(out, Candidate{Site: site, ManagedRuleset: row.ruleset, Err: siteErr})
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (p PostgresRepository) loadSite(ctx context.Context, tx pgx.Tx, id, tenantID, status, failMode, plan, rawEntitlements, wafMode, sensitivity string, bodyKB int, rawExclusions string) (wafcore.Site, error) {
	if wafMode == "enforce" {
		wafMode = "block"
	}
	site := wafcore.Site{ID: id, TenantID: tenantID, Status: status, Plan: plan, FailMode: failMode, WAF: wafcore.WAFConfig{Mode: wafMode, Sensitivity: sensitivity, BodyLimitKB: bodyKB}, Rules: []wafcore.Rule{}, RateLimits: []wafcore.RateLimit{}, Domains: []string{}, Origins: []wafcore.Origin{}}
	if site.Status == "pending_dns" || site.Status == "pending" {
		site.Status = "pending"
	}
	var entitlement struct {
		Limits   map[string]int64 `json:"limits"`
		Features map[string]any   `json:"features"`
	}
	if err := json.Unmarshal([]byte(rawEntitlements), &entitlement); err != nil {
		return site, fmt.Errorf("decode plan entitlement: %w", err)
	}
	site.Entitlements.MaxRules = max(0, int(entitlement.Limits["custom_rules"]))
	site.Entitlements.MaxRateLimitPolicies = max(0, int(entitlement.Limits["rate_limit_policies"]))
	site.Entitlements.MaxBodyBytes = max(0, int(entitlement.Limits["waf_body_kb"]*1024))
	if feature, _ := entitlement.Features["bot"].(string); feature == "js_challenge" || feature == "custom" {
		site.Entitlements.BotJSChallenge = true
	}
	if feature, _ := entitlement.Features["bot"].(string); feature == "captcha" || feature == "custom" {
		site.Entitlements.BotCaptcha = true
	}
	if err := json.Unmarshal([]byte(rawExclusions), &site.WAF.Exclusions); err != nil {
		return site, fmt.Errorf("decode WAF exclusions: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT hostname FROM public.domains WHERE site_id=$1 AND tenant_id=$2 AND verification_status='active' ORDER BY hostname`, id, tenantID)
	if err != nil {
		return site, err
	}
	for rows.Next() {
		var host string
		if err = rows.Scan(&host); err != nil {
			rows.Close()
			return site, err
		}
		site.Domains = append(site.Domains, host)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return site, err
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT url,weight,host_header,tls_mode FROM public.origins WHERE site_id=$1 AND tenant_id=$2 ORDER BY weight DESC,id`, id, tenantID)
	if err != nil {
		return site, err
	}
	for rows.Next() {
		var origin wafcore.Origin
		var tlsMode string
		if err = rows.Scan(&origin.URL, &origin.Weight, &origin.HostHeader, &tlsMode); err != nil {
			rows.Close()
			return site, err
		}
		origin.TLSVerify = tlsMode == "full_strict"
		site.Origins = append(site.Origins, origin)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return site, err
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT id::text,priority,expression,action,mode,expires_at,action_params::text FROM public.rules WHERE site_id=$1 AND tenant_id=$2 AND enabled AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>now()) ORDER BY priority,id`, id, tenantID)
	if err != nil {
		return site, err
	}
	for rows.Next() {
		var rule wafcore.Rule
		var expires *time.Time
		var params string
		if err = rows.Scan(&rule.ID, &rule.Priority, &rule.Expression, &rule.Action, &rule.Mode, &expires, &params); err != nil {
			rows.Close()
			return site, err
		}
		// The database stores the full rule execution mode ("enforce" or
		// "log"), while wafcore uses an empty mode for normal enforcement and
		// "log" only for monitor-only rules.
		rule.Mode = ruleModeFromDatabase(rule.Mode)
		rule.ExpiresAt = expires
		var actionParams map[string]string
		if err = json.Unmarshal([]byte(params), &actionParams); err != nil {
			rows.Close()
			return site, fmt.Errorf("rule %s action params: %w", rule.ID, err)
		}
		rule.Policy, rule.Tag, rule.Phase = actionParams["policy"], actionParams["tag"], actionParams["phase"]
		site.Rules = append(site.Rules, rule)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return site, err
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT match_expr,key_expr,request_limit,window_seconds,action,ban_seconds,id::text FROM public.rate_limit_policies WHERE site_id=$1 AND tenant_id=$2 ORDER BY id`, id, tenantID)
	if err != nil {
		return site, err
	}
	for rows.Next() {
		var rule wafcore.RateLimit
		if err = rows.Scan(&rule.Match, &rule.Key, &rule.Limit, &rule.WindowS, &rule.Action, &rule.BanS, &rule.ID); err != nil {
			rows.Close()
			return site, err
		}
		site.RateLimits = append(site.RateLimits, rule)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return site, err
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT type,value,action FROM public.access_lists WHERE site_id=$1 AND tenant_id=$2 ORDER BY id`, id, tenantID)
	if err != nil {
		return site, err
	}
	for rows.Next() {
		var kind, value, action string
		if err = rows.Scan(&kind, &value, &action); err != nil {
			rows.Close()
			return site, err
		}
		switch {
		case action == "allow" && (kind == "ip" || kind == "cidr"):
			site.Access.AllowIPs = append(site.Access.AllowIPs, value)
		case action == "block":
			switch kind {
			case "country":
				site.Access.BlockCountries = append(site.Access.BlockCountries, strings.ToUpper(value))
			case "asn":
				n, e := strconv.ParseUint(value, 10, 32)
				if e != nil {
					rows.Close()
					return site, fmt.Errorf("invalid ASN access value %q", value)
				}
				site.Access.BlockASNs = append(site.Access.BlockASNs, uint32(n))
			default:
				site.Access.BlockIPs = append(site.Access.BlockIPs, value)
			}
		default:
			rows.Close()
			return site, fmt.Errorf("unsupported access list type/action %q/%q", kind, action)
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return site, err
	}
	rows.Close()
	var botJSON, cacheJSON string
	if err = tx.QueryRow(ctx, `SELECT coalesce(settings,'{}'::jsonb)::text FROM public.bot_settings WHERE site_id=$1 AND tenant_id=$2`, id, tenantID).Scan(&botJSON); err != nil && err != pgx.ErrNoRows {
		return site, err
	}
	if err == nil {
		var botSettings struct {
			wafcore.BotConfig
			ChallengeHMACKeyID  string            `json:"challenge_hmac_key_id"`
			OriginCredentialIDs []string          `json:"origin_credential_ids"`
			Additional          map[string]string `json:"additional_secrets"`
		}
		if err = json.Unmarshal([]byte(botJSON), &botSettings); err != nil {
			return site, fmt.Errorf("decode bot settings: %w", err)
		}
		site.Bot = botSettings.BotConfig
		site.Secrets.ChallengeHMACKeyID = botSettings.ChallengeHMACKeyID
		site.Secrets.OriginCredentialIDs = botSettings.OriginCredentialIDs
		site.Secrets.Additional = botSettings.Additional
	}
	if err = tx.QueryRow(ctx, `SELECT coalesce(settings,'{}'::jsonb)::text FROM public.cache_settings WHERE site_id=$1 AND tenant_id=$2`, id, tenantID).Scan(&cacheJSON); err != nil && err != pgx.ErrNoRows {
		return site, err
	}
	if err == nil {
		if err = json.Unmarshal([]byte(cacheJSON), &site.Cache); err != nil {
			return site, fmt.Errorf("decode cache settings: %w", err)
		}
	}
	if len(site.Domains) == 0 {
		return site, fmt.Errorf("site has no DNS-verified domain")
	}
	if len(site.Origins) == 0 {
		return site, fmt.Errorf("site has no origin")
	}
	return site, nil
}

func ruleModeFromDatabase(mode string) string {
	if mode == "enforce" {
		return ""
	}
	return mode
}

func (p PostgresRepository) Latest(ctx context.Context, region string) (Record, error) {
	var rec Record
	err := p.Pool.QueryRow(ctx, `SELECT version,checksum,signature,object_key FROM public.config_snapshots WHERE scope=$1 AND rollout_state='active' ORDER BY version DESC LIMIT 1`, region).Scan(&rec.Version, &rec.Checksum, &rec.Signature, &rec.ObjectKey)
	if err == pgx.ErrNoRows {
		return Record{}, ErrNoSnapshot
	}
	return rec, err
}

// ResolveEdge binds the verified client certificate to its registered edge row.
// The certificate serial is stored as lowercase hexadecimal during enrollment.
func (p PostgresRepository) ResolveEdge(ctx context.Context, cert *x509.Certificate) (string, string, error) {
	if p.Pool == nil || cert == nil || cert.SerialNumber == nil {
		return "", "", fmt.Errorf("edge certificate identity is required")
	}
	serial := strings.ToLower(cert.SerialNumber.Text(16))
	var edgeID, region string
	err := p.Pool.QueryRow(ctx, `SELECT id::text,region FROM public.edges WHERE lower(cert_serial)=$1 AND status IN ('ready','active')`, serial).Scan(&edgeID, &region)
	if err != nil {
		return "", "", err
	}
	return edgeID, region, nil
}

func (p PostgresRepository) Reserve(ctx context.Context, region string) (uint64, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`, region); err != nil {
		return 0, err
	}
	var version uint64
	if err = tx.QueryRow(ctx, `SELECT nextval('public.config_snapshot_global_version_seq')`).Scan(&version); err != nil {
		return 0, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO public.config_snapshots(id,scope,version,checksum,signature,object_key,rollout_state) VALUES($1,$2,$3,'',decode('','hex'),'','building')`, id, region, version); err != nil {
		return 0, err
	}
	return version, tx.Commit(ctx)
}

func (p PostgresRepository) Publish(ctx context.Context, region string, record Record) ([]string, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`, region); err != nil {
		return nil, err
	}
	var activeVersion uint64
	activeErr := tx.QueryRow(ctx, `SELECT version FROM public.config_snapshots WHERE scope=$1 AND rollout_state='active' ORDER BY version DESC LIMIT 1`, region).Scan(&activeVersion)
	if activeErr != nil && activeErr != pgx.ErrNoRows {
		return nil, activeErr
	}
	if activeErr == nil && activeVersion >= record.Version {
		return nil, ErrStaleBuild
	}
	if _, err = tx.Exec(ctx, `UPDATE public.config_snapshots SET rollout_state='superseded',updated_at=now() WHERE scope=$1 AND rollout_state='active'`, region); err != nil {
		return nil, err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.config_snapshots SET checksum=$3,signature=$4,object_key=$5,rollout_state='active',updated_at=now() WHERE scope=$1 AND version=$2 AND rollout_state='building'`, region, record.Version, record.Checksum, record.Signature, record.ObjectKey)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, fmt.Errorf("snapshot reservation not found")
	}
	rows, err := tx.Query(ctx, `DELETE FROM public.config_snapshots WHERE scope=$1 AND version NOT IN (SELECT version FROM public.config_snapshots WHERE scope=$1 ORDER BY version DESC LIMIT 50) RETURNING object_key`, region)
	if err != nil {
		return nil, err
	}
	var old []string
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			rows.Close()
			return nil, err
		}
		if key != "" {
			old = append(old, key)
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return old, tx.Commit(ctx)
}

func (p PostgresRepository) Fail(ctx context.Context, region string, version uint64) error {
	_, err := p.Pool.Exec(ctx, `UPDATE public.config_snapshots SET rollout_state='failed',updated_at=now() WHERE scope=$1 AND version=$2 AND rollout_state='building'`, region, version)
	return err
}

func (p PostgresRepository) WarnSite(ctx context.Context, siteID, message string) error {
	if siteID == "" {
		return nil
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = p.Pool.Exec(ctx, `INSERT INTO public.alerts(id,tenant_id,status,details)
SELECT $1,s.tenant_id,'open',jsonb_build_object('kind','snapshot_site_invalid','site_id',s.id::text,'message',$3::text)
FROM public.sites s WHERE s.id=$2 AND NOT EXISTS (
  SELECT 1 FROM public.alerts a WHERE a.tenant_id=s.tenant_id AND a.status='open'
    AND a.details->>'kind'='snapshot_site_invalid' AND a.details->>'site_id'=s.id::text
)`, id, siteID, message)
	return err
}

// DispatchOutbox publishes one locked batch and marks it only after NATS accepts
// each event. A crash after publish can redeliver, which is safe because the
// snapshot worker coalesces events and rebuilds from current committed state.
func (p PostgresRepository) DispatchOutbox(ctx context.Context, publish func([]byte) error) (int, error) {
	if p.Pool == nil || publish == nil {
		return 0, fmt.Errorf("outbox pool and publisher are required")
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT id,payload::text FROM public.config_change_outbox WHERE published_at IS NULL ORDER BY created_at,id LIMIT 100 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return 0, err
	}
	type pending struct {
		id      string
		payload []byte
	}
	var batch []pending
	for rows.Next() {
		var item pending
		if err = rows.Scan(&item.id, &item.payload); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, item := range batch {
		if err = publish(item.payload); err != nil {
			_, updateErr := tx.Exec(ctx, `UPDATE public.config_change_outbox SET attempts=attempts+1,updated_at=now() WHERE id=$1`, item.id)
			if updateErr != nil {
				return 0, fmt.Errorf("publish config outbox event: %w (record attempt: %v)", err, updateErr)
			}
			if commitErr := tx.Commit(ctx); commitErr != nil {
				return 0, fmt.Errorf("publish config outbox event: %w (commit attempt: %v)", err, commitErr)
			}
			return 0, err
		}
		if _, err = tx.Exec(ctx, `UPDATE public.config_change_outbox SET published_at=now(),attempts=attempts+1,updated_at=now() WHERE id=$1`, item.id); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(batch), nil
}

var _ Repository = PostgresRepository{}
