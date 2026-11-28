//go:build integration

package integration

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestFleetInfrastructurePrivilegesIntegration(t *testing.T) {
	ctx, admin, redisClient := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, redisClient)
	api := apiRolePool(t, ctx, admin, mustDatabaseURL(t), cleanup)
	worker := workerRolePool(t, ctx, admin, mustDatabaseURL(t), cleanup)
	var apiIsWorker bool
	if err := api.QueryRow(ctx, `SELECT pg_has_role(current_user,'waf_worker','member')`).Scan(&apiIsWorker); err != nil {
		t.Fatal(err)
	}
	if apiIsWorker {
		t.Fatal("waf_api login unexpectedly inherits waf_worker")
	}

	tables := []struct {
		name      string
		insertSQL string
		updateSQL string
	}{
		{"edges", `INSERT INTO public.edges(id,region,provider,status) SELECT '00000000-0000-7000-8000-000000000001','test','integration','offline' WHERE false`, `UPDATE public.edges SET status='offline' WHERE false`},
		{"edge_certificates", `INSERT INTO public.edge_certificates(serial,edge_id,status,not_after) SELECT 'denied','00000000-0000-7000-8000-000000000001','revoked',now() WHERE false`, `UPDATE public.edge_certificates SET revoked_at=NULL WHERE false`},
		{"edge_bootstrap_tokens", `INSERT INTO public.edge_bootstrap_tokens(id,edge_id,token_hash,expires_at) SELECT '00000000-0000-7000-8000-000000000002','00000000-0000-7000-8000-000000000001',decode(repeat('00',32),'hex'),now() WHERE false`, `UPDATE public.edge_bootstrap_tokens SET consumed_at=NULL,expires_at=now()+interval '1 year' WHERE false`},
		{"certificate_issuance_rate_limits", `INSERT INTO public.certificate_issuance_rate_limits(issuer_key,window_started_at,orders_count) SELECT 'denied',now(),0 WHERE false`, `UPDATE public.certificate_issuance_rate_limits SET orders_count=0 WHERE false`},
		{"edge_dns_withdrawal_limits", `INSERT INTO public.edge_dns_withdrawal_limits(region,last_withdrawal_at) SELECT 'denied',now() WHERE false`, `UPDATE public.edge_dns_withdrawal_limits SET last_withdrawal_at=now() WHERE false`},
	}
	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
				var allowed bool
				if err := admin.QueryRow(ctx, `SELECT has_table_privilege('waf_api',$1,$2)`, "public."+table.name, privilege).Scan(&allowed); err != nil {
					t.Fatal(err)
				}
				if allowed {
					t.Errorf("waf_api still has %s on %s", privilege, table.name)
				}
			}
			var apiColumnSelect, apiColumnUpdate bool
			if err := admin.QueryRow(ctx, `SELECT has_any_column_privilege('waf_api',$1,'SELECT'),has_any_column_privilege('waf_api',$1,'UPDATE')`, "public."+table.name).Scan(&apiColumnSelect, &apiColumnUpdate); err != nil {
				t.Fatal(err)
			}
			if apiColumnSelect || apiColumnUpdate {
				t.Errorf("waf_api has column privileges on %s: select=%v update=%v", table.name, apiColumnSelect, apiColumnUpdate)
			}
			for _, privilege := range []string{"SELECT", "INSERT", "UPDATE"} {
				var allowed bool
				if err := admin.QueryRow(ctx, `SELECT has_table_privilege('waf_worker',$1,$2)`, "public."+table.name, privilege).Scan(&allowed); err != nil {
					t.Fatal(err)
				}
				if !allowed {
					t.Errorf("waf_worker lacks required %s on %s", privilege, table.name)
				}
			}
			for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
				var allowed bool
				if err := admin.QueryRow(ctx, `SELECT has_table_privilege('waf_worker',$1,$2)`, "public."+table.name, privilege).Scan(&allowed); err != nil {
					t.Fatal(err)
				}
				if privilege == "DELETE" && allowed {
					t.Errorf("waf_worker has unnecessary DELETE on %s", table.name)
				}
			}

			queries := []string{
				fmt.Sprintf(`SELECT * FROM public.%s LIMIT 0`, table.name),
				table.insertSQL,
				table.updateSQL,
				fmt.Sprintf(`DELETE FROM public.%s WHERE false`, table.name),
			}
			for _, query := range queries {
				if _, err := api.Exec(ctx, query); !isPermissionDenied(err) {
					t.Errorf("waf_api query was not rejected with insufficient_privilege: sql=%q err=%v", query, err)
				}
			}
		})
	}
	if err := worker.Ping(ctx); err != nil {
		t.Fatalf("waf_worker pool is not usable: %v", err)
	}
}

func mustDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("integration DATABASE_URL was not initialized")
	}
	return url
}

func isPermissionDenied(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}
