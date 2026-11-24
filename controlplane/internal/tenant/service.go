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
	hash := sha256.Sum256(token)
	err = db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		actorRole, e := roleFor(ctx, tx, tenantID, actor)
		if e != nil || !Can(actorRole, ManageMembers, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		_, e = tx.Exec(ctx, `INSERT INTO invitations(id,tenant_id,email,role,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, id, tenantID, email, role, hash[:], time.Now().Add(7*24*time.Hour))
		if e != nil {
			return e
		}
		return appendAudit(ctx, tx, tenantID, actor, "member.invitation.create", "invitation", id, map[string]any{"email": email, "role": role})
	})
	return base64.RawURLEncoding.EncodeToString(token), err
}
func (s Service) AcceptInvite(ctx context.Context, userID uuid.UUID, token string) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrNotFound
	}
	hash := sha256.Sum256(raw)
	var tenantID, id uuid.UUID
	var role Role
	var invitedEmail, userEmail string
	if err = s.Pool.QueryRow(ctx, `SELECT email FROM users WHERE id=$1`, userID).Scan(&userEmail); err != nil {
		return ErrNotFound
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = tx.QueryRow(ctx, `SELECT tenant_id,invitation_id,invited_role,invited_email FROM lookup_invitation($1)`, hash[:]).Scan(&tenantID, &id, &role, &invitedEmail)
	if err != nil {
		return ErrNotFound
	}
	if !strings.EqualFold(strings.TrimSpace(userEmail), strings.TrimSpace(invitedEmail)) {
		return ErrForbidden
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantID.String()); err != nil {
		return err
	}
	memberID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(id,tenant_id,user_id,role) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,user_id) DO NOTHING`, memberID, tenantID, userID, role); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM invitations WHERE id=$1`, id); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, tenantID, userID, "member.invitation.accept", "membership", memberID, map[string]any{"role": role}); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
	err = db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		actorRole, e := roleFor(ctx, tx, tenantID, actor)
		if e != nil || !Can(actorRole, ManageAPIKeys, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		_, e = tx.Exec(ctx, `INSERT INTO api_keys(id,tenant_id,name,key_hash,scopes,created_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, tenantID, name, hash[:], scopes, actor, expiresAt)
		if e != nil {
			return e
		}
		return appendAudit(ctx, tx, tenantID, actor, "api_key.create", "api_key", id, map[string]any{"name": name, "scopes": scopes})
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
	err := db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		actorRole, e := roleFor(ctx, tx, tenantID, actor)
		if e != nil || !Can(actorRole, ManageMembers, Resource{TenantID: tenantID.String()}) {
			return ErrForbidden
		}
		rows, e := tx.Query(ctx, `SELECT m.user_id,u.email,m.role,m.created_at FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=$1 ORDER BY m.created_at`, tenantID)
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
