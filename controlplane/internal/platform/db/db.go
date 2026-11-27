package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Pool struct{ *pgxpool.Pool }

func Open(ctx context.Context, databaseURL string) (*Pool, error) {
	return open(ctx, databaseURL, "waf_api", false)
}

// OpenWorker accepts only a non-superuser login granted to the narrowly
// privileged background role. It is not suitable for API traffic.
func OpenWorker(ctx context.Context, databaseURL string) (*Pool, error) {
	return open(ctx, databaseURL, "waf_worker", true)
}

func open(ctx context.Context, databaseURL, role string, allowBypass bool) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database config: %w", err)
	}
	if allowBypass {
		previous := cfg.AfterConnect
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			if previous != nil {
				if err := previous(ctx, conn); err != nil {
					return err
				}
			}
			_, err := conn.Exec(ctx, `SET ROLE waf_worker`)
			return err
		}
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	var sessionSuperuser, superuser, bypass, member bool
	query := `SELECT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=session_user),r.rolsuper,r.rolbypassrls,pg_has_role(session_user,$1,'member') FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`
	if err := p.QueryRow(ctx, query, role).Scan(&sessionSuperuser, &superuser, &bypass, &member); err != nil {
		p.Close()
		return nil, fmt.Errorf("inspect database role: %w", err)
	}
	if sessionSuperuser || superuser || !member || (!allowBypass && bypass) || (allowBypass && !bypass) {
		p.Close()
		if allowBypass {
			return nil, fmt.Errorf("worker database URL must use a non-superuser login granted waf_worker (BYPASSRLS)")
		}
		return nil, fmt.Errorf("DATABASE_URL must use a non-superuser login with the waf_api role (NOBYPASSRLS)")
	}
	return &Pool{Pool: p}, nil
}

func NewID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate UUIDv7: %w", err)
	}
	return id, nil
}

// WithTenantTx pins tenant context to the transaction so RLS protects queries even without tenant WHERE clauses.
func WithTenantTx(ctx context.Context, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('app.tenant_id',$1,true)`, tenantID.String()); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}

// WithUserTx pins a user identity to a transaction for user-scoped RLS policies.
func WithUserTx(ctx context.Context, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, userID uuid.UUID, fn func(pgx.Tx) error) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin user transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('app.user_id',$1,true)`, userID.String()); err != nil {
		return fmt.Errorf("set user context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit user transaction: %w", err)
	}
	return nil
}

// WithUserTenantTx sets both identities when a request is scoped to one user in one tenant.
func WithUserTenantTx(ctx context.Context, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, userID, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	if userID == uuid.Nil || tenantID == uuid.Nil {
		return fmt.Errorf("user and tenant IDs are required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin user tenant transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('app.tenant_id',$1,true), pg_catalog.set_config('app.user_id',$2,true)`, tenantID.String(), userID.String()); err != nil {
		return fmt.Errorf("set user tenant context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit user tenant transaction: %w", err)
	}
	return nil
}
