package entitlement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/example/wafplatform/controlplane/internal/platform/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrQuotaExceeded = errors.New("plan quota exceeded")

type Plan struct {
	Version       int              `json:"version"`
	Limits        map[string]int64 `json:"limits"`
	Features      map[string]any   `json:"features"`
	LogSampleRate float64          `json:"log_sample_rate"`
}
type Service struct{ Pool *pgxpool.Pool }

func Seed(ctx context.Context, pool *pgxpool.Pool) error {
	rows := []struct {
		code         string
		entitlements string
	}{
		{"free", `{"version":1,"limits":{"sites":1,"custom_rules":3,"rate_limit_policies":1,"waf_body_kb":8,"log_retention_days":1},"features":{"waf_managed":"basic","bot":"none","geo_block":false,"asn_block":false,"cache":false,"api_access":false,"siem_export":false},"log_sample_rate":0.01}`},
		{"pro", `{"version":1,"limits":{"sites":5,"custom_rules":20,"rate_limit_policies":5,"waf_body_kb":64,"log_retention_days":7},"features":{"waf_managed":"full","bot":"js_challenge","geo_block":true,"asn_block":false,"cache":true,"api_access":false,"siem_export":false},"log_sample_rate":0.1}`},
		{"business", `{"version":1,"limits":{"sites":-1,"custom_rules":100,"rate_limit_policies":20,"waf_body_kb":128,"log_retention_days":30},"features":{"waf_managed":"full","bot":"captcha","geo_block":true,"asn_block":true,"cache":true,"api_access":true,"siem_export":false},"log_sample_rate":0.5}`},
		{"enterprise", `{"version":1,"limits":{"sites":-1,"custom_rules":-1,"rate_limit_policies":100,"waf_body_kb":256,"log_retention_days":90},"features":{"waf_managed":"full","bot":"custom","geo_block":true,"asn_block":true,"cache":true,"api_access":true,"siem_export":true},"log_sample_rate":1.0}`},
	}
	for _, r := range rows {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, `INSERT INTO plans(id,code,entitlements) VALUES($1,$2,$3::jsonb) ON CONFLICT(code) DO UPDATE SET entitlements=EXCLUDED.entitlements,updated_at=now()`, id, r.code, r.entitlements); err != nil {
			return fmt.Errorf("seed %s plan: %w", r.code, err)
		}
	}
	return nil
}

func (s Service) Get(ctx context.Context, tenantID uuid.UUID) (Plan, error) {
	var raw []byte
	err := db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT p.entitlements FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.tenant_id=$1 AND s.status='active' ORDER BY s.created_at DESC LIMIT 1`, tenantID).Scan(&raw)
	})
	if err != nil {
		return Plan{}, err
	}
	var p Plan
	err = json.Unmarshal(raw, &p)
	return p, err
}
func (s Service) CheckLimit(ctx context.Context, tenantID uuid.UUID, key string, requested int64) error {
	p, err := s.Get(ctx, tenantID)
	if err != nil {
		return err
	}
	limit, ok := p.Limits[key]
	if !ok {
		return fmt.Errorf("unknown quota %q", key)
	}
	if requested < 0 {
		return fmt.Errorf("requested quota delta must not be negative")
	}
	var current int64
	switch key {
	case "sites", "custom_rules", "rate_limit_policies":
		query := ""
		switch key {
		case "sites":
			query = `SELECT count(*) FROM sites WHERE tenant_id=$1 AND deleted_at IS NULL`
		case "custom_rules":
			query = `SELECT count(*) FROM rules WHERE tenant_id=$1 AND deleted_at IS NULL`
		case "rate_limit_policies":
			query = `SELECT count(*) FROM rate_limit_policies WHERE tenant_id=$1`
		}
		err = db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, query, tenantID).Scan(&current)
		})
		if err != nil {
			return err
		}
	case "requests", "bytes_out", "rules_count":
		query := ""
		switch key {
		case "requests":
			query = `SELECT coalesce(sum(requests),0) FROM usage_counters WHERE tenant_id=$1 AND period=date_trunc('month',current_date)::date`
		case "bytes_out":
			query = `SELECT coalesce(sum(bytes_out),0) FROM usage_counters WHERE tenant_id=$1 AND period=date_trunc('month',current_date)::date`
		case "rules_count":
			query = `SELECT coalesce(sum(rules_count),0) FROM usage_counters WHERE tenant_id=$1 AND period=date_trunc('month',current_date)::date`
		}
		err = db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, query, tenantID).Scan(&current)
		})
		if err != nil {
			return err
		}
	}
	if limit >= 0 && (current > limit || requested > limit-current) {
		return ErrQuotaExceeded
	}
	return nil
}

type UsageDelta struct {
	Requests, BytesOut int64
	RulesCount         int64
}

func (s Service) RecordUsage(ctx context.Context, tenantID uuid.UUID, period time.Time, delta UsageDelta) error {
	if delta.Requests < 0 || delta.BytesOut < 0 || delta.RulesCount < 0 {
		return fmt.Errorf("usage deltas must not be negative")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	return db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO usage_counters(id,tenant_id,period,requests,bytes_out,rules_count) VALUES($1,$2,date_trunc('month',$3)::date,$4,$5,$6) ON CONFLICT(tenant_id,period) DO UPDATE SET requests=CASE WHEN usage_counters.requests>9223372036854775807-EXCLUDED.requests THEN 9223372036854775807 ELSE usage_counters.requests+EXCLUDED.requests END,bytes_out=CASE WHEN usage_counters.bytes_out>9223372036854775807-EXCLUDED.bytes_out THEN 9223372036854775807 ELSE usage_counters.bytes_out+EXCLUDED.bytes_out END,rules_count=CASE WHEN usage_counters.rules_count>2147483647-EXCLUDED.rules_count THEN 2147483647 ELSE usage_counters.rules_count+EXCLUDED.rules_count END,updated_at=now()`, id, tenantID, period, delta.Requests, delta.BytesOut, delta.RulesCount)
		return e
	})
}
