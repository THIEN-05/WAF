package site

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/example/wafplatform/controlplane/internal/entitlement"
	"github.com/example/wafplatform/controlplane/internal/platform/db"
	"github.com/example/wafplatform/controlplane/internal/tenant"
	"github.com/example/wafplatform/pkg/netguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/idna"
)

type Publisher interface {
	Publish(subject string, data []byte) error
}

type Service struct {
	Pool                  *pgxpool.Pool
	Quota                 entitlement.Service
	Events                Publisher
	VerificationCNAMEZone string
	VerificationTimeout   time.Duration
}

type Site struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	Status string    `json:"status"`
}

// Create creates a pending site after RBAC and plan quota checks.
func (s Service) Create(ctx context.Context, tenantID, actor uuid.UUID, name string) (Site, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return Site{}, errors.New("invalid site name")
	}
	id, err := db.NewID()
	if err != nil {
		return Site{}, err
	}
	var event []byte
	err = db.WithUserTenantTx(ctx, s.Pool, actor, tenantID, func(tx pgx.Tx) error {
		var role tenant.Role
		if e := tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2`, tenantID, actor).Scan(&role); e != nil || !tenant.Can(role, tenant.AddSite, tenant.Resource{TenantID: tenantID.String()}) {
			return tenant.ErrForbidden
		}
		// Serialize site creation per tenant so concurrent requests cannot race past the plan quota.
		if _, e := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`, tenantID.String()); e != nil {
			return e
		}
		var current int64
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE tenant_id=$1 AND deleted_at IS NULL`, tenantID).Scan(&current); e != nil {
			return e
		}
		var raw []byte
		if e := tx.QueryRow(ctx, `SELECT p.entitlements FROM subscriptions sub JOIN plans p ON p.id=sub.plan_id WHERE sub.tenant_id=$1 AND sub.status='active' ORDER BY sub.created_at DESC LIMIT 1`, tenantID).Scan(&raw); e != nil {
			return e
		}
		var plan struct {
			Limits map[string]int64 `json:"limits"`
		}
		if e := json.Unmarshal(raw, &plan); e != nil {
			return e
		}
		limit, ok := plan.Limits["sites"]
		if !ok {
			return errors.New("site quota is not configured")
		}
		if limit >= 0 && current >= limit {
			return entitlement.ErrQuotaExceeded
		}
		if _, e := tx.Exec(ctx, `INSERT INTO sites(id,tenant_id,name,status) VALUES($1,$2,$3,'pending_dns')`, id, tenantID, name); e != nil {
			return e
		}
		if e := appendSiteAudit(ctx, tx, tenantID, actor, "site.create", id, map[string]any{"name": name}); e != nil {
			return e
		}
		var e error
		event, e = enqueueConfigChange(ctx, tx, tenantID, id)
		return e
	})
	if err != nil {
		return Site{}, err
	}
	s.publish(event)
	return Site{ID: id, Name: name, Status: "pending_dns"}, nil
}

type DomainProof struct {
	ID         uuid.UUID `json:"id"`
	Hostname   string    `json:"hostname"`
	Token      string    `json:"verification_token"`
	TXTName    string    `json:"txt_name"`
	TXTValue   string    `json:"txt_value"`
	CNAMEName  string    `json:"cname_name,omitempty"`
	CNAMEValue string    `json:"cname_value,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}

var ErrHostnameUnavailable = errors.New("hostname is unavailable")
var ErrSiteNotFound = errors.New("site not found")
var ErrVerificationExpired = errors.New("domain verification expired")

func (s Service) AddDomain(ctx context.Context, tenantID, actor, siteID uuid.UUID, hostname string) (DomainProof, error) {
	var err error
	hostname, err = NormalizeHostname(hostname)
	if err != nil {
		return DomainProof{}, errors.New("invalid hostname")
	}
	id, err := db.NewID()
	if err != nil {
		return DomainProof{}, err
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return DomainProof{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	var expiresAt time.Time
	var event []byte
	err = db.WithUserTenantTx(ctx, s.Pool, actor, tenantID, func(tx pgx.Tx) error {
		var role tenant.Role
		if e := tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2`, tenantID, actor).Scan(&role); e != nil || !tenant.Can(role, tenant.AddSite, tenant.Resource{TenantID: tenantID.String()}) {
			return tenant.ErrForbidden
		}
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sites WHERE id=$1 AND tenant_id=$2 AND deleted_at IS NULL)`, siteID, tenantID).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return ErrSiteNotFound
		}
		if e := tx.QueryRow(ctx, `SELECT now()+interval '24 hours'`).Scan(&expiresAt); e != nil {
			return e
		}
		auditID, e := db.NewID()
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `SELECT public.site_add_domain($1,$2,$3,$4,$5,$6,$7,$8)`, id, tenantID, siteID, hostname, sum[:], expiresAt, actor, auditID)
		if e != nil {
			e = mapDomainInsertError(e)
			if errors.Is(e, ErrHostnameUnavailable) {
				return e
			}
			var pgErr *pgconn.PgError
			if errors.As(e, &pgErr) && pgErr.Code == "P0002" {
				return ErrSiteNotFound
			}
			return e
		}
		event, e = enqueueConfigChange(ctx, tx, tenantID, siteID)
		return e
	})
	if err != nil {
		return DomainProof{}, err
	}
	s.publish(event)
	proof := DomainProof{ID: id, Hostname: hostname, Token: token, TXTName: "_waf-verify." + hostname, TXTValue: token, ExpiresAt: expiresAt}
	if s.VerificationCNAMEZone != "" {
		proof.CNAMEName = hostname
		proof.CNAMEValue = CNAMEProofTarget(sum[:], s.VerificationCNAMEZone)
	}
	return proof, nil
}

// NormalizeHostname maps equivalent DNS names, including U-labels, to one ASCII key.
func NormalizeHostname(hostname string) (string, error) {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if hostname == "" {
		return "", errors.New("invalid hostname")
	}
	ascii, err := idna.Lookup.ToASCII(hostname)
	if err != nil {
		return "", err
	}
	ascii = strings.ToLower(ascii)
	if !validHostname(ascii) {
		return "", errors.New("invalid hostname")
	}
	return ascii, nil
}

func mapDomainInsertError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "domains_hostname_key" {
		return ErrHostnameUnavailable
	}
	return err
}

func (s Service) VerifyDomain(ctx context.Context, tenantID, domainID uuid.UUID, dns DNS) error {
	var hostname string
	var expected []byte
	expired := false
	readErr := db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT hostname,verification_token_hash FROM domains WHERE tenant_id=$1 AND id=$2 AND verification_status='pending_dns' AND verification_expires_at>now()`, tenantID, domainID).Scan(&hostname, &expected)
		if errors.Is(err, pgx.ErrNoRows) {
			tag, expireErr := tx.Exec(ctx, `UPDATE domains SET verification_status='failed',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND verification_status='pending_dns' AND verification_expires_at<=now()`, tenantID, domainID)
			if expireErr != nil {
				return expireErr
			}
			if tag.RowsAffected() > 0 {
				expired = true
				return nil
			}
			return err
		}
		return err
	})
	if readErr != nil {
		return readErr
	}
	if expired {
		return ErrVerificationExpired
	}
	timeout := s.VerificationTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	dnsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := VerifyDNSHash(dnsCtx, dns, hostname, expected, s.VerificationCNAMEZone); err != nil {
		return err
	}
	var payload []byte
	err := db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var siteID uuid.UUID
		if err := tx.QueryRow(ctx, `UPDATE domains SET verification_status='active',verified_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2 AND verification_status='pending_dns' AND verification_expires_at>now() RETURNING site_id`, tenantID, domainID).Scan(&siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE sites SET status='active',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND status='pending_dns'`, tenantID, siteID)
		if err != nil {
			return err
		}
		auditID, e := db.NewID()
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO audit_logs(id,tenant_id,actor_type,action,entity,entity_id,diff) VALUES($1,$2,'system','domain.verify','domain',$3,'{}'::jsonb)`, auditID, tenantID, domainID); e != nil {
			return e
		}
		payload, err = enqueueConfigChange(ctx, tx, tenantID, siteID)
		return err
	})
	if err == nil {
		s.publish(payload)
	}
	return err
}

// VerifyDueDomains runs one bounded worker batch. Its caller supplies the clock for deterministic scheduling tests.
func (s Service) VerifyDueDomains(ctx context.Context, dns DNS, now time.Time, limit int) (int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `WITH due AS (
  SELECT tenant_id,id FROM domains WHERE verification_status='pending_dns' AND next_verification_at<=$1
  ORDER BY next_verification_at FOR UPDATE SKIP LOCKED LIMIT $2
)
UPDATE domains d SET next_verification_at=$1+CASE WHEN d.created_at<=$1-interval '24 hours' THEN interval '15 minutes' ELSE interval '1 minute' END,updated_at=now()
FROM due WHERE d.tenant_id=due.tenant_id AND d.id=due.id
RETURNING d.tenant_id,d.id,d.created_at`, now, limit)
	if err != nil {
		return 0, err
	}
	type due struct {
		tenant, id uuid.UUID
		created    time.Time
	}
	var items []due
	for rows.Next() {
		var item due
		if err = rows.Scan(&item.tenant, &item.id, &item.created); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	verified := 0
	for _, item := range items {
		verifyErr := s.VerifyDomain(ctx, item.tenant, item.id, dns)
		if verifyErr == nil {
			verified++
			continue
		}
		if errors.Is(verifyErr, ErrVerificationExpired) {
			continue
		}
		if ctx.Err() != nil {
			return verified, ctx.Err()
		}
		next := now.Add(VerificationInterval(now.Sub(item.created)))
		if e := db.WithTenantTx(ctx, s.Pool, item.tenant, func(tx pgx.Tx) error {
			_, x := tx.Exec(ctx, `UPDATE domains SET next_verification_at=$3,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND verification_status='pending_dns'`, item.tenant, item.id, next)
			return x
		}); e != nil {
			return verified, e
		}
	}
	return verified, nil
}

func (s Service) AddOrigin(ctx context.Context, tenantID, actor, siteID uuid.UUID, raw string, resolver netguard.Resolver) (uuid.UUID, error) {
	if err := db.WithUserTenantTx(ctx, s.Pool, actor, tenantID, func(tx pgx.Tx) error {
		var role tenant.Role
		if e := tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2`, tenantID, actor).Scan(&role); e != nil || !tenant.Can(role, tenant.AddSite, tenant.Resource{TenantID: tenantID.String()}) {
			return tenant.ErrForbidden
		}
		return nil
	}); err != nil {
		return uuid.Nil, err
	}
	u, err := ValidateOrigin(ctx, raw, resolver)
	if err != nil {
		return uuid.Nil, err
	}
	id, err := db.NewID()
	if err != nil {
		return uuid.Nil, err
	}
	var event []byte
	err = db.WithUserTenantTx(ctx, s.Pool, actor, tenantID, func(tx pgx.Tx) error {
		var role tenant.Role
		if e := tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2`, tenantID, actor).Scan(&role); e != nil || !tenant.Can(role, tenant.AddSite, tenant.Resource{TenantID: tenantID.String()}) {
			return tenant.ErrForbidden
		}
		tag, e := tx.Exec(ctx, `INSERT INTO origins(id,tenant_id,site_id,url) SELECT $1,$2,$3,$4 WHERE EXISTS(SELECT 1 FROM sites WHERE id=$3 AND tenant_id=$2 AND deleted_at IS NULL)`, id, tenantID, siteID, u.String())
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrSiteNotFound
		}
		if e := appendSiteAudit(ctx, tx, tenantID, actor, "origin.add", id, map[string]any{"url": u.String()}); e != nil {
			return e
		}
		event, e = enqueueConfigChange(ctx, tx, tenantID, siteID)
		return e
	})
	if err == nil {
		s.publish(event)
	}
	return id, err
}

func enqueueConfigChange(ctx context.Context, tx pgx.Tx, tenantID, siteID uuid.UUID) ([]byte, error) {
	payload, err := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "site_id": siteID.String()})
	if err != nil {
		return nil, err
	}
	id, err := db.NewID()
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO config_change_outbox(id,tenant_id,site_id,payload) VALUES($1,$2,$3,$4::jsonb)`, id, tenantID, siteID, payload)
	return payload, err
}

func (s Service) publish(payload []byte) {
	if len(payload) > 0 && s.Events != nil {
		_ = s.Events.Publish("config.changed", payload)
	}
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "/:@[] ") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
func appendSiteAudit(ctx context.Context, tx pgx.Tx, tenantID, actor uuid.UUID, action string, id uuid.UUID, diff any) error {
	raw, e := json.Marshal(diff)
	if e != nil {
		return e
	}
	auditID, e := db.NewID()
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff) VALUES($1,$2,'user',$3,$4,'site',$5,$6::jsonb)`, auditID, tenantID, actor, action, id, raw)
	return e
}
