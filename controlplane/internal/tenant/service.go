package tenant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/example/wafplatform/controlplane/internal/platform/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrForbidden = errors.New("forbidden")
var ErrNotFound = errors.New("not found")

type Service struct{ Pool *pgxpool.Pool }

func (s Service) Can(ctx context.Context, userID uuid.UUID, action Action, resource Resource) (bool, error) {
	tenantID, err := uuid.Parse(resource.TenantID)
	if err != nil {
		return false, ErrForbidden
	}
	var role Role
	err = db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var e error
		role, e = roleFor(ctx, tx, tenantID, userID)
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return Can(role, action, resource), nil
}
func (s Service) Invite(ctx context.Context, tenantID, actor uuid.UUID, email string, role Role) (string, error) {
	if role != Admin && role != Viewer {
		return "", ErrForbidden
	}
	email = strings.ToLower(strings.TrimSpace(email))
	address, parseErr := mail.ParseAddress(email)
	if parseErr != nil || address.Address != email {
		return "", ErrForbidden
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	auditID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(token)
	err = db.WithUserTenantTx(ctx, s.Pool, actor, tenantID, func(tx pgx.Tx) error {
		actorRole, e := roleFor(ctx, tx, tenantID, actor)
		if e != nil || !Can(actorRole, ManageMembers, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		_, e = tx.Exec(ctx, `SELECT public.tenant_create_invitation($1,$2,$3,$4,$5,$6,$7,$8)`, id, tenantID, email, role, hash[:], time.Now().Add(7*24*time.Hour-time.Minute), actor, auditID)
		return e
	})
	return base64.RawURLEncoding.EncodeToString(token), err
}
func (s Service) AcceptInvite(ctx context.Context, userID uuid.UUID, token string) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrNotFound
	}
	hash := sha256.Sum256(raw)
	memberID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	auditID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	var accepted bool
	err = db.WithUserTx(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT public.tenant_accept_invitation($1,$2,$3,$4)`, hash[:], userID, memberID, auditID).Scan(&accepted)
	})
	if err != nil {
		return err
	}
	if !accepted {
		return ErrNotFound
	}
	return nil
}

type APIKey struct {
	ID        uuid.UUID
	Plaintext string
}

func (s Service) CreateAPIKey(ctx context.Context, tenantID, actor uuid.UUID, name string, scopes []string, expiresAt *time.Time) (APIKey, error) {
	for _, scope := range scopes {
		if scope != "sites:read" && scope != "rules:write" && scope != "analytics:read" {
			return APIKey{}, ErrForbidden
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return APIKey{}, err
	}
	plain := "waf_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(plain))
	id, err := uuid.NewV7()
	if err != nil {
		return APIKey{}, err
	}
	auditID, err := uuid.NewV7()
	if err != nil {
		return APIKey{}, err
	}
	err = db.WithUserTenantTx(ctx, s.Pool, actor, tenantID, func(tx pgx.Tx) error {
		actorRole, e := roleFor(ctx, tx, tenantID, actor)
		if e != nil || !Can(actorRole, ManageAPIKeys, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		_, e = tx.Exec(ctx, `SELECT public.tenant_create_api_key($1,$2,$3,$4,$5,$6,$7,$8)`, id, tenantID, name, hash[:], scopes, actor, auditID, expiresAt)
		return e
	})
	return APIKey{ID: id, Plaintext: plain}, err
}

type Member struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func (s Service) ListMembers(ctx context.Context, tenantID, actor uuid.UUID) ([]Member, error) {
	var out []Member
	err := db.WithUserTenantTx(ctx, s.Pool, actor, tenantID, func(tx pgx.Tx) error {
		actorRole, e := roleFor(ctx, tx, tenantID, actor)
		if e != nil || !Can(actorRole, ManageMembers, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		rows, e := tx.Query(ctx, `SELECT user_id,email,role,created_at FROM public.tenant_list_members($1)`, tenantID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m Member
			if e = rows.Scan(&m.UserID, &m.Email, &m.Role, &m.CreatedAt); e != nil {
				return e
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}
func (s Service) RemoveMember(ctx context.Context, tenantID, actor, target uuid.UUID) error {
	return db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var actorRole, targetRole Role
		if e := tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, tenantID, actor).Scan(&actorRole); e != nil {
			return ErrForbidden
		}
		if !Can(actorRole, ManageMembers, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		if e := tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, tenantID, target).Scan(&targetRole); e != nil {
			return ErrNotFound
		}
		if targetRole == Owner {
			return ErrForbidden
		}
		if _, e := tx.Exec(ctx, `DELETE FROM memberships WHERE tenant_id=$1 AND user_id=$2`, tenantID, target); e != nil {
			return e
		}
		return appendAudit(ctx, tx, tenantID, actor, "member.remove", "membership", target, map[string]any{"role": targetRole})
	})
}

type APIKeyInfo struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (s Service) ListAPIKeys(ctx context.Context, tenantID, actor uuid.UUID) ([]APIKeyInfo, error) {
	var out []APIKeyInfo
	err := db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		actorRole, e := roleFor(ctx, tx, tenantID, actor)
		if e != nil || !Can(actorRole, ManageAPIKeys, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		rows, e := tx.Query(ctx, `SELECT id,name,scopes,last_used_at,expires_at,revoked_at,created_at FROM api_keys WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var k APIKeyInfo
			if e = rows.Scan(&k.ID, &k.Name, &k.Scopes, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt, &k.CreatedAt); e != nil {
				return e
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}
func (s Service) RevokeAPIKey(ctx context.Context, tenantID, actor, keyID uuid.UUID) error {
	return db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		actorRole, e := roleFor(ctx, tx, tenantID, actor)
		if e != nil || !Can(actorRole, ManageAPIKeys, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		tag, e := tx.Exec(ctx, `UPDATE api_keys SET revoked_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenantID, keyID)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return appendAudit(ctx, tx, tenantID, actor, "api_key.revoke", "api_key", keyID, map[string]any{})
	})
}

func roleFor(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID) (Role, error) {
	var role Role
	err := tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&role)
	return role, err
}

func appendAudit(ctx context.Context, tx pgx.Tx, tenantID, actorID uuid.UUID, action, entity string, entityID uuid.UUID, diff any) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(diff)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff) VALUES($1,$2,'user',$3,$4,$5,$6,$7::jsonb)`, id, tenantID, actorID, action, entity, entityID, raw)
	return err
}
