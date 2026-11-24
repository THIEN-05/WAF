package audit

import (
	"context"
	"fmt"

	"github.com/example/wafplatform/controlplane/internal/platform/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Record struct {
	TenantID       uuid.UUID
	ActorType      string
	ActorID        *uuid.UUID
	Action, Entity string
	EntityID       *uuid.UUID
	IP             string
	UserAgent      string
	Diff           []byte
}
type Sink struct{ Pool *pgxpool.Pool }

func (s Sink) Append(ctx context.Context, r Record) error {
	if r.TenantID == uuid.Nil || r.Action == "" || r.Entity == "" {
		return fmt.Errorf("audit tenant, action and entity are required")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	var ip any
	if r.IP != "" {
		ip = r.IP
	}
	diff := r.Diff
	if len(diff) == 0 {
		diff = []byte(`{}`)
	}
	return db.WithTenantTx(ctx, s.Pool, r.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,ip,user_agent,diff) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`, id, r.TenantID, r.ActorType, r.ActorID, r.Action, r.Entity, r.EntityID, ip, r.UserAgent, diff)
		return e
	})
}
