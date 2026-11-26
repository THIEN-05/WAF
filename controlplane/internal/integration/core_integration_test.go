//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/controlplane/internal/auth"
	"github.com/example/wafplatform/controlplane/internal/entitlement"
	"github.com/example/wafplatform/controlplane/internal/platform/audit"
	"github.com/example/wafplatform/controlplane/internal/platform/db"
	"github.com/example/wafplatform/controlplane/internal/site"
	"github.com/example/wafplatform/controlplane/internal/tenant"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/pressly/goose/v3"
	"github.com/redis/go-redis/v9"
)

func integrationDeps(t *testing.T) (context.Context, *pgxpool.Pool, *redis.Client) {
	t.Helper()
	url, redisAddr := os.Getenv("DATABASE_URL"), os.Getenv("REDIS_ADDR")
	if url == "" || redisAddr == "" {
		if os.Getenv("CP_INTEGRATION_REQUIRED") == "1" {
			t.Fatal("CP integration job requires DATABASE_URL and REDIS_ADDR; refusing to skip")
		}
		t.Skip("integration requires DATABASE_URL and REDIS_ADDR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err = goose.UpContext(ctx, sqlDB, "../../migrations"); err != nil {
		t.Fatalf("goose up: %v", err)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	rc := redis.NewClient(&redis.Options{Addr: redisAddr, Password: os.Getenv("REDIS_PASSWORD")})
	t.Cleanup(func() { _ = rc.Close() })
	if err = rc.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, rc
}

// integrationCleanup removes only rows whose identities were created by this test.
// It deliberately operates on the shared database after assertions finish, so -count
// reruns exercise the same database without relying on it being empty.
type integrationCleanup struct {
	t       *testing.T
	admin   *pgxpool.Pool
	redis   *redis.Client
	emails  []string
	tenants []uuid.UUID
	roles   []cleanupRole
}

type cleanupStatement struct {
	sql  string
	args []any
}
type cleanupRole struct{ name, group string }

func cleanupForTest(t *testing.T, admin *pgxpool.Pool, clients ...*redis.Client) *integrationCleanup {
	t.Helper()
	c := &integrationCleanup{t: t, admin: admin}
	if len(clients) > 0 {
		c.redis = clients[0]
	}
	t.Cleanup(c.run)
	return c
}
func (c *integrationCleanup) email(email string)  { c.emails = append(c.emails, email) }
func (c *integrationCleanup) tenant(id uuid.UUID) { c.tenants = append(c.tenants, id) }
func (c *integrationCleanup) role(name, group string) {
	c.roles = append(c.roles, cleanupRole{name: name, group: group})
}
func (c *integrationCleanup) run() {
	c.runWithRolesAndPool(true, nil)
}

func (c *integrationCleanup) runFixtureRows() {
	c.runWithRolesAndPool(false, nil)
}

func (c *integrationCleanup) runFixtureRowsWithPool(pool *pgxpool.Pool) {
	c.runWithRolesAndPool(false, pool)
}

func (c *integrationCleanup) runWithRolesAndPool(includeRoles bool, execPool *pgxpool.Pool) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var cleanupErrors []error
	if c.redis != nil {
		for _, email := range c.emails {
			digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
			if err := c.redis.Del(ctx, "cp:auth:lock:"+hex.EncodeToString(digest[:])).Err(); err != nil {
				c.t.Errorf("integration Redis fixture cleanup: %v", err)
			}
		}
	}
	users := make([]uuid.UUID, 0, len(c.emails))
	tenants := append([]uuid.UUID(nil), c.tenants...)
	for _, email := range c.emails {
		var userID, tenantID uuid.UUID
		err := c.admin.QueryRow(ctx, `SELECT id,default_tenant_id FROM public.users WHERE email=$1`, email).Scan(&userID, &tenantID)
		if err == nil {
			users = append(users, userID)
			if tenantID != uuid.Nil {
				tenants = append(tenants, tenantID)
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("cleanup lookup by test email %q: %w", email, err))
		}
	}
	if len(users) == 0 && len(tenants) == 0 && len(c.roles) == 0 {
		if len(cleanupErrors) > 0 {
			c.t.Errorf("integration fixture cleanup errors: %v", errors.Join(cleanupErrors...))
		}
		return
	}
	if execPool == nil {
		execPool = c.admin
	}
	tx, err := execPool.Begin(ctx)
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("integration fixture cleanup begin: %w", err))
		c.t.Errorf("integration fixture cleanup errors: %v", errors.Join(cleanupErrors...))
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	roles := c.roles
	if !includeRoles {
		roles = nil
	}
	statements := fixtureCleanupStatements(tenants, users, roles)
	for i, stmt := range statements {
		sp := fmt.Sprintf("fixture_cleanup_%d", i)
		if _, err := tx.Exec(ctx, "SAVEPOINT "+sp); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("cleanup SQL %q savepoint: %w", stmt.sql, err))
			continue
		}
		if _, err := tx.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("cleanup SQL %q: %w", stmt.sql, err))
			if _, rollbackErr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+sp); rollbackErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("cleanup SQL %q rollback: %w", stmt.sql, rollbackErr))
			}
		}
		if _, releaseErr := tx.Exec(ctx, "RELEASE SAVEPOINT "+sp); releaseErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("cleanup SQL %q release: %w", stmt.sql, releaseErr))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("integration fixture cleanup commit: %w", err))
	}
	if len(cleanupErrors) > 0 {
		c.t.Errorf("integration fixture cleanup errors: %v", errors.Join(cleanupErrors...))
	}
}

func fixtureCleanupStatements(tenants, users []uuid.UUID, roles []cleanupRole) []cleanupStatement {
	statements := []cleanupStatement{
		{`DELETE FROM public.config_change_outbox WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.certificates WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.domains WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.origins WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.waf_settings WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.rules WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.rate_limit_policies WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.access_lists WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.bot_settings WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.cache_settings WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.rule_history WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.alert_rules WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.notification_channels WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.alerts WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.usage_counters WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.api_keys WHERE tenant_id=ANY($1::uuid[]) OR created_by=ANY($2::uuid[])`, []any{tenants, users}},
		{`DELETE FROM public.invitations WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.subscriptions WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.invoices WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.memberships WHERE tenant_id=ANY($1::uuid[]) OR user_id=ANY($2::uuid[])`, []any{tenants, users}},
		{`DELETE FROM public.refresh_tokens WHERE user_id=ANY($1::uuid[])`, []any{users}},
		{`DELETE FROM public.email_verification_tokens WHERE user_id=ANY($1::uuid[])`, []any{users}},
		{`DELETE FROM public.password_reset_tokens WHERE user_id=ANY($1::uuid[])`, []any{users}},
		{`DELETE FROM public.totp_recovery_codes WHERE user_id=ANY($1::uuid[])`, []any{users}},
		{`DELETE FROM public.sites WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`UPDATE public.users SET default_tenant_id=NULL WHERE id=ANY($1::uuid[])`, []any{users}},
		{`DELETE FROM public.audit_logs WHERE tenant_id=ANY($1::uuid[]) OR actor_id=ANY($2::uuid[])`, []any{tenants, users}},
		{`DELETE FROM public.organizations WHERE tenant_id=ANY($1::uuid[])`, []any{tenants}},
		{`DELETE FROM public.users WHERE id=ANY($1::uuid[])`, []any{users}},
	}
	for _, role := range roles {
		ident := pgx.Identifier{role.name}.Sanitize()
		group := pgx.Identifier{role.group}.Sanitize()
		statements = append(statements,
			cleanupStatement{`REVOKE ` + group + ` FROM ` + ident, nil},
			cleanupStatement{`DROP ROLE IF EXISTS ` + ident, nil},
		)
	}
	return orderAuditCleanupLastBeforeOrganization(statements)
}

func orderAuditCleanupLastBeforeOrganization(statements []cleanupStatement) []cleanupStatement {
	audit := make([]cleanupStatement, 0, 1)
	ordered := make([]cleanupStatement, 0, len(statements))
	for _, statement := range statements {
		if strings.HasPrefix(statement.sql, "DELETE FROM public.audit_logs ") {
			audit = append(audit, statement)
			continue
		}
		ordered = append(ordered, statement)
	}
	if len(audit) == 0 {
		return ordered
	}
	insertAt := len(ordered)
	for i, statement := range ordered {
		if strings.HasPrefix(statement.sql, "DELETE FROM public.organizations ") {
			insertAt = i
			break
		}
	}
	ordered = append(ordered, make([]cleanupStatement, len(audit))...)
	copy(ordered[insertAt+len(audit):], ordered[insertAt:len(ordered)-len(audit)])
	copy(ordered[insertAt:insertAt+len(audit)], audit)
	return ordered
}

var cleanupTableCoverage = map[string]string{
	"users":                     "delete by tracked user UUID after clearing default_tenant_id",
	"organizations":             "delete by tracked tenant UUID after tenant children and user references",
	"memberships":               "delete by tenant_id or tracked user_id",
	"invitations":               "delete by tenant_id",
	"refresh_tokens":            "delete by user_id",
	"api_keys":                  "delete by tenant_id or created_by",
	"subscriptions":             "delete by tenant_id",
	"invoices":                  "delete by tenant_id",
	"sites":                     "delete by tenant_id after site-owned rows",
	"domains":                   "delete by tenant_id after certificates",
	"origins":                   "delete by tenant_id",
	"waf_settings":              "delete by tenant_id",
	"rules":                     "delete by tenant_id",
	"rate_limit_policies":       "delete by tenant_id",
	"access_lists":              "delete by tenant_id",
	"bot_settings":              "delete by tenant_id",
	"cache_settings":            "delete by tenant_id",
	"certificates":              "delete by tenant_id before domains",
	"rule_history":              "delete by tenant_id",
	"alert_rules":               "delete by tenant_id",
	"notification_channels":     "delete by tenant_id",
	"alerts":                    "delete by tenant_id",
	"audit_logs":                "delete by tenant_id or actor_id",
	"usage_counters":            "delete by tenant_id",
	"email_verification_tokens": "delete by user_id",
	"password_reset_tokens":     "delete by user_id",
	"totp_recovery_codes":       "delete by user_id",
	"config_change_outbox":      "delete by tenant_id before site rows",
}

var cleanupGlobalTableAllowlist = map[string]string{
	"plans":            "shared product catalog; seeded globally and contains no fixture ownership key",
	"config_snapshots": "global signed snapshot inventory; integration fixtures do not create snapshots",
	"edges":            "global edge inventory; integration fixtures do not create edges",
	"webhook_events":   "global provider idempotency inbox; integration fixtures do not process webhooks",
	"goose_db_version": "migration bookkeeping, never test fixture data",
}

func TestIntegrationCleanupSchemaCoverage(t *testing.T) {
	ctx, pool, _ := integrationDeps(t)
	statements := fixtureCleanupStatements(nil, nil, nil)
	auditIndex, organizationIndex := -1, -1
	for i, statement := range statements {
		if strings.HasPrefix(statement.sql, "DELETE FROM public.audit_logs ") {
			auditIndex = i
		}
		if strings.HasPrefix(statement.sql, "DELETE FROM public.organizations ") {
			organizationIndex = i
		}
	}
	if auditIndex < 0 || organizationIndex != auditIndex+1 {
		t.Fatalf("audit deletion must immediately precede organization deletion: audit=%d organization=%d", auditIndex, organizationIndex)
	}
	for table := range cleanupTableCoverage {
		found := false
		for _, statement := range statements {
			if strings.Contains(statement.sql, "public."+table) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("cleanup coverage for table %q has no matching SQL statement", table)
		}
	}
	rows, err := pool.Query(ctx, `SELECT c.relname,
      EXISTS (SELECT 1 FROM information_schema.columns col WHERE col.table_schema='public' AND col.table_name=c.relname AND col.column_name IN ('tenant_id','user_id','actor_id','created_by'))
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var table string
		var fixtureColumns bool
		if err = rows.Scan(&table, &fixtureColumns); err != nil {
			t.Fatal(err)
		}
		seen[table] = true
		if fixtureColumns {
			if _, ok := cleanupTableCoverage[table]; !ok {
				t.Errorf("fixture-owned table %q is not covered by integration cleanup", table)
			}
			continue
		}
		if _, ok := cleanupTableCoverage[table]; ok {
			continue
		}
		if _, ok := cleanupGlobalTableAllowlist[table]; !ok {
			t.Errorf("public table %q has no fixture-cleanup rule or documented global allowlist reason", table)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for table := range cleanupTableCoverage {
		if !seen[table] {
			t.Errorf("cleanup coverage references missing table %q", table)
		}
	}
	for table := range cleanupGlobalTableAllowlist {
		if !seen[table] {
			t.Errorf("global cleanup allowlist references missing table %q", table)
		}
	}
	owned, err := pool.Query(ctx, `SELECT DISTINCT col.table_name FROM information_schema.columns col JOIN information_schema.tables tab USING(table_schema,table_name) WHERE col.table_schema='public' AND tab.table_type='BASE TABLE' AND col.column_name IN ('tenant_id','user_id','actor_id','created_by') ORDER BY col.table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	for owned.Next() {
		var table string
		if err = owned.Scan(&table); err != nil {
			t.Fatal(err)
		}
		if _, ok := cleanupTableCoverage[table]; !ok {
			t.Errorf("new fixture-owned table %q is absent from cleanup coverage", table)
		}
	}
	if err = owned.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationDatabaseIdentity(t *testing.T) {
	ctx, pool, _ := integrationDeps(t)
	var role string
	var superuser bool
	var pgVersion string
	if err := pool.QueryRow(ctx, `SELECT current_user,r.rolsuper,version() FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`).Scan(&role, &superuser, &pgVersion); err != nil {
		t.Fatal(err)
	}
	t.Logf("Postgres integration connection: role=%s rolsuper=%t version=%s", role, superuser, pgVersion)
}

func TestZZIntegrationFixtureResidueBudget(t *testing.T) {
	ctx, admin, rc := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, rc)
	rows, err := admin.Query(ctx, `SELECT email FROM public.users WHERE
      email ~ '^(integration-[0-9a-f-]+|security-[ab]-[0-9a-f-]+|bind-[ab](-not-used)?-[0-9a-f-]+|flow-[0-9a-f-]+|rotate-[0-9a-f-]+|site-race-[ab]-[0-9a-f-]+|cleanup-[0-9a-f-]+)@example[.]test$'
      OR email ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@example[.]test$'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var email string
		if err = rows.Scan(&email); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		cleanup.email(email)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	cleanup.runFixtureRows()
	counts := make(map[string]int64)
	for _, table := range []string{"users", "organizations", "sites", "domains", "audit_logs"} {
		var count int64
		if err = admin.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{"public", table}.Sanitize()).Scan(&count); err != nil {
			t.Fatalf("count residue in %s: %v", table, err)
		}
		counts[table] = count
	}
	t.Logf("integration DB residue after fixture purge: users=%d organizations=%d sites=%d domains=%d audit_logs=%d", counts["users"], counts["organizations"], counts["sites"], counts["domains"], counts["audit_logs"])
	for table, count := range counts {
		if count > 5 {
			t.Errorf("integration database residue too high in %s: %d rows (limit 5)", table, count)
		}
	}
}

func TestAuditCleanupPlannerDefersAuditAfterNewTriggerTable(t *testing.T) {
	statements := []cleanupStatement{
		{`DELETE FROM public.audit_logs WHERE tenant_id=ANY($1::uuid[])`, []any{nil}},
		{`DELETE FROM public.future_auth_rows WHERE tenant_id=ANY($1::uuid[])`, []any{nil}},
		{`DELETE FROM public.organizations WHERE tenant_id=ANY($1::uuid[])`, []any{nil}},
	}
	ordered := orderAuditCleanupLastBeforeOrganization(statements)
	if !strings.Contains(ordered[0].sql, "future_auth_rows") || !strings.Contains(ordered[1].sql, "audit_logs") || !strings.Contains(ordered[2].sql, "organizations") {
		t.Fatalf("future trigger table must be deleted before its generated audit and tenant: %#v", ordered)
	}
}

func TestIntegrationCleanupRemovesFixtureRows(t *testing.T) {
	ctx, admin, rc := integrationDeps(t)
	for _, mode := range []string{"superuser", "non_superuser_bypassrls"} {
		t.Run(mode, func(t *testing.T) {
			cleanup := cleanupForTest(t, admin, rc)
			app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
			cleanupPool := admin
			if mode == "non_superuser_bypassrls" {
				cleanupPool = nonSuperuserBypassPool(t, ctx, admin, os.Getenv("DATABASE_URL"))
			}
			userID, tenantID := seedCleanupFixture(t, ctx, admin, rc, app, cleanup)
			cleanup.runFixtureRowsWithPool(cleanupPool)
			cleanup.runFixtureRowsWithPool(cleanupPool)
			assertNoFixtureRows(t, ctx, admin, userID, tenantID)
		})
	}
}

func seedCleanupFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool, rc *redis.Client, app *pgxpool.Pool, cleanup *integrationCleanup) (uuid.UUID, uuid.UUID) {
	t.Helper()
	mailer := &captureMailer{messages: make(chan capturedMail, 8)}
	authSvc := newAuthService(t, app, rc, mailer)
	email := "cleanup-" + uuid.NewString() + "@example.test"
	cleanup.email(email)
	if err := authSvc.Register(ctx, email, "a correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := authSvc.VerifyEmail(ctx, receivedToken(t, mailer, "Verification token: ")); err != nil {
		t.Fatal(err)
	}
	var userID, tenantID uuid.UUID
	if err := admin.QueryRow(ctx, `SELECT id,default_tenant_id FROM public.users WHERE email=$1`, email).Scan(&userID, &tenantID); err != nil {
		t.Fatal(err)
	}
	verificationHash := sha256.Sum256([]byte(uuid.NewString()))
	if _, err := admin.Exec(ctx, `INSERT INTO public.email_verification_tokens(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, uuid.New(), userID, verificationHash[:], time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("seed pending email-verification token for cleanup: %v", err)
	}
	session, err := authSvc.Login(ctx, email, "a correct horse battery staple", "integration-cleanup", "192.0.2.90", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = authSvc.RequestPasswordReset(ctx, email); err != nil {
		t.Fatal(err)
	}
	if _, _, err = authSvc.CreateTOTP(ctx, userID); err != nil {
		t.Fatal(err)
	}
	sites := site.Service{Pool: app}
	createdSite, err := sites.Create(ctx, tenantID, userID, "cleanup-site-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sites.AddDomain(ctx, tenantID, userID, createdSite.ID, "cleanup-"+strings.ReplaceAll(uuid.NewString(), "-", "")+".example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sites.AddOrigin(ctx, tenantID, userID, createdSite.ID, "https://origin.example", siteFakeDNS{ips: []net.IP{net.ParseIP("203.0.113.21")}}); err != nil {
		t.Fatal(err)
	}
	if _, err = (tenant.Service{Pool: app}).CreateAPIKey(ctx, tenantID, userID, "cleanup-key", []string{"sites:read"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = (tenant.Service{Pool: app}).Invite(ctx, tenantID, userID, "invite-"+uuid.NewString()+"@example.test", tenant.Viewer); err != nil {
		t.Fatal(err)
	}
	if session.RefreshToken == "" || proof.ID == uuid.Nil {
		t.Fatal("fixture setup did not create auth/site/domain data")
	}
	for _, check := range []struct {
		table, column string
		id            uuid.UUID
		want          int
	}{
		{"users", "id", userID, 1}, {"organizations", "tenant_id", tenantID, 1},
		{"sites", "tenant_id", tenantID, 1}, {"domains", "tenant_id", tenantID, 1},
		{"origins", "tenant_id", tenantID, 1}, {"config_change_outbox", "tenant_id", tenantID, 3},
		{"refresh_tokens", "user_id", userID, 1}, {"password_reset_tokens", "user_id", userID, 1},
		{"email_verification_tokens", "user_id", userID, 1},
		{"totp_recovery_codes", "user_id", userID, 10}, {"api_keys", "tenant_id", tenantID, 1},
		{"invitations", "tenant_id", tenantID, 1}, {"audit_logs", "tenant_id", tenantID, 1},
	} {
		var count int
		query := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s=$1`, pgx.Identifier{"public", check.table}.Sanitize(), pgx.Identifier{check.column}.Sanitize())
		if err := admin.QueryRow(ctx, query, check.id).Scan(&count); err != nil {
			t.Fatalf("count fixture rows in %s: %v", check.table, err)
		}
		if count < check.want {
			t.Fatalf("fixture seeded %s rows=%d, want at least %d", check.table, count, check.want)
		}
	}
	var recoveryInsertEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_logs WHERE tenant_id=$1 AND action='auth.totp_recovery_codes.insert'`, tenantID).Scan(&recoveryInsertEvents); err != nil {
		t.Fatal(err)
	}
	if recoveryInsertEvents != 10 {
		t.Fatalf("recovery-code insert trigger generated %d audit rows, want 10", recoveryInsertEvents)
	}
	return userID, tenantID
}

func assertNoFixtureRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID, tenantID uuid.UUID) {
	t.Helper()
	var users, orgs, sites, domains int
	for _, check := range []struct {
		query string
		id    uuid.UUID
		dst   *int
	}{
		{`SELECT count(*) FROM public.users WHERE id=$1`, userID, &users},
		{`SELECT count(*) FROM public.organizations WHERE tenant_id=$1`, tenantID, &orgs},
		{`SELECT count(*) FROM public.sites WHERE tenant_id=$1`, tenantID, &sites},
		{`SELECT count(*) FROM public.domains WHERE tenant_id=$1`, tenantID, &domains},
	} {
		if err := pool.QueryRow(ctx, check.query, check.id).Scan(check.dst); err != nil {
			t.Fatal(err)
		}
	}
	if users+orgs+sites+domains != 0 {
		t.Fatalf("fixture rows remain: users=%d organizations=%d sites=%d domains=%d", users, orgs, sites, domains)
	}
	rows, err := pool.Query(ctx, `SELECT col.table_name,array_agg(col.column_name ORDER BY col.column_name) FROM information_schema.columns col JOIN information_schema.tables tab USING(table_schema,table_name) WHERE col.table_schema='public' AND tab.table_type='BASE TABLE' AND col.column_name IN ('tenant_id','user_id','actor_id','created_by') GROUP BY col.table_name ORDER BY col.table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table string
		var columns []string
		if err = rows.Scan(&table, &columns); err != nil {
			t.Fatal(err)
		}
		conditions := make([]string, 0, len(columns))
		args := make([]any, 0, len(columns))
		for _, column := range columns {
			arg := userID
			if column == "tenant_id" {
				arg = tenantID
			}
			conditions = append(conditions, pgx.Identifier{column}.Sanitize()+"=$"+fmt.Sprint(len(args)+1))
			args = append(args, arg)
		}
		query := "SELECT count(*) FROM " + pgx.Identifier{"public", table}.Sanitize() + " WHERE " + strings.Join(conditions, " OR ")
		var count int
		if err = pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
			t.Errorf("inspect fixture rows in %s: %v", table, err)
			continue
		}
		if count != 0 {
			t.Errorf("fixture cleanup left %d matching rows in %s", count, table)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func apiRolePool(t *testing.T, ctx context.Context, admin *pgxpool.Pool, url string, cleanup *integrationCleanup) *pgxpool.Pool {
	t.Helper()
	roleName := "waf_test_api_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test-api-role-password'`, roleName)); err != nil {
		t.Fatalf("create api login: %v", err)
	}
	cleanup.role(roleName, "waf_api")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`GRANT waf_api TO %s`, roleName)); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = roleName
	cfg.ConnConfig.Password = "test-api-role-password"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if err = p.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	var bypass, member bool
	if err = p.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls,pg_has_role(current_user,'waf_api','member') FROM pg_roles r WHERE r.rolname=current_user`).Scan(&bypass, &member); err != nil {
		t.Fatal(err)
	}
	if bypass || !member {
		t.Fatalf("application login policy invalid: bypass=%v member=%v", bypass, member)
	}
	return p
}

func workerRolePool(t *testing.T, ctx context.Context, admin *pgxpool.Pool, url string, cleanup *integrationCleanup) *pgxpool.Pool {
	t.Helper()
	roleName := "waf_test_worker_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test-worker-role-password'`, roleName)); err != nil {
		t.Fatalf("create worker login: %v", err)
	}
	cleanup.role(roleName, "waf_worker")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`GRANT waf_worker TO %s`, roleName)); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.ConnConfig.Password = roleName, "test-worker-role-password"
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, e := conn.Exec(ctx, `SET ROLE waf_worker`)
		return e
	}
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if err = p.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	var bypass, member bool
	if err = p.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls,pg_has_role(current_user,'waf_worker','member') FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`).Scan(&bypass, &member); err != nil {
		t.Fatal(err)
	}
	if !bypass || !member {
		t.Fatalf("worker login must be a BYPASSRLS member: bypass=%v member=%v", bypass, member)
	}
	return p
}

func nonSuperuserBypassPool(t *testing.T, ctx context.Context, admin *pgxpool.Pool, url string) *pgxpool.Pool {
	t.Helper()
	roleName := "waf_test_cleanup_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ident := pgx.Identifier{roleName}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE ROLE `+ident+` LOGIN BYPASSRLS PASSWORD 'test-cleanup-role-password'`); err != nil {
		t.Fatalf("create cleanup login: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, `DROP OWNED BY `+ident); err != nil {
			t.Errorf("drop owned by cleanup login %s: %v", roleName, err)
		}
		if _, err := admin.Exec(cleanupCtx, `DROP ROLE IF EXISTS `+ident); err != nil {
			t.Errorf("drop cleanup login %s: %v", roleName, err)
		}
	})
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+ident); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO `+ident); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.ConnConfig.Password = roleName, "test-cleanup-role-password"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if err = p.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	var superuser, bypass bool
	if err = p.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&superuser, &bypass); err != nil {
		t.Fatal(err)
	}
	if superuser || !bypass {
		t.Fatalf("cleanup role must be non-superuser BYPASSRLS: rolsuper=%v rolbypassrls=%v", superuser, bypass)
	}
	return p
}

func TestPostgresRLSAndAuthRedisIntegration(t *testing.T) {
	ctx, pool, rc := integrationDeps(t)
	cleanup := cleanupForTest(t, pool, rc)
	appPool := apiRolePool(t, ctx, pool, os.Getenv("DATABASE_URL"), cleanup)
	var apiBypass, workerBypass bool
	if err := pool.QueryRow(ctx, `SELECT (SELECT rolbypassrls FROM pg_roles WHERE rolname='waf_api'),(SELECT rolbypassrls FROM pg_roles WHERE rolname='waf_worker')`).Scan(&apiBypass, &workerBypass); err != nil {
		t.Fatal(err)
	}
	if apiBypass || !workerBypass {
		t.Fatalf("database role policy invalid: api bypass=%v worker bypass=%v", apiBypass, workerBypass)
	}
	var auditInsert, auditSelect, auditUpdate, auditDelete bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('waf_api','audit_logs','INSERT'),has_table_privilege('waf_api','audit_logs','SELECT'),has_table_privilege('waf_api','audit_logs','UPDATE'),has_table_privilege('waf_api','audit_logs','DELETE')`).Scan(&auditInsert, &auditSelect, &auditUpdate, &auditDelete); err != nil {
		t.Fatal(err)
	}
	if !auditInsert || auditSelect || auditUpdate || auditDelete {
		t.Fatalf("audit_logs grants invalid: insert=%v select=%v update=%v delete=%v", auditInsert, auditSelect, auditUpdate, auditDelete)
	}
	if err := entitlement.Seed(ctx, pool); err != nil {
		t.Fatal(err)
	}
	planID := uuid.MustParse("01900000-0000-7000-8000-000000000001")
	makeTenant := func() uuid.UUID {
		t.Helper()
		tenantID, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		ownerID, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,password_hash,status) VALUES($1,$2,'test','active')`, ownerID, tenantID.String()+"@example.test"); err != nil {
			t.Fatal(err)
		}
		orgName := "test-" + uuid.NewString()
		if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,tenant_id,name,owner_user_id,plan_id) VALUES($1,$1,$2,$3,$4)`, tenantID, orgName, ownerID, planID); err != nil {
			t.Fatal(err)
		}
		cleanup.tenant(tenantID)
		cleanup.email(tenantID.String() + "@example.test")
		siteID, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `INSERT INTO sites(id,tenant_id,name,status) VALUES($1,$2,$3,'active')`, siteID, tenantID, "private-"+uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		return tenantID
	}
	tenantA, tenantB := makeTenant(), makeTenant()
	var noTenant int64
	if err := appPool.QueryRow(ctx, `SELECT count(*) FROM sites`).Scan(&noTenant); err != nil {
		t.Fatal(err)
	}
	if noTenant != 0 {
		t.Fatalf("API login without tenant context saw %d sites", noTenant)
	}
	for _, tenantID := range []uuid.UUID{tenantA, tenantB} {
		err := db.WithTenantTx(ctx, appPool, tenantID, func(tx pgx.Tx) error {
			var n int64
			if e := tx.QueryRow(ctx, `SELECT count(*) FROM sites`).Scan(&n); e != nil {
				return e
			}
			if n != 1 {
				return fmt.Errorf("tenant %s sees %d sites without WHERE", tenantID, n)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.WithTenantTx(ctx, appPool, tenantA, func(tx pgx.Tx) error {
		var hidden int64
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE tenant_id=$1`, tenantB).Scan(&hidden); e != nil {
			return e
		}
		if hidden != 0 {
			return fmt.Errorf("cross-tenant site visibility: %d", hidden)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertVisible := func(tenantID uuid.UUID, want int64) {
		t.Helper()
		conn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE waf_api`); err != nil {
			t.Fatalf("set api role: %v", err)
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantID.String()); err != nil {
			t.Fatal(err)
		}
		var n int64
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM sites`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Fatalf("tenant %s sees %d rows without WHERE, want %d", tenantID, n, want)
		}
	}
	assertVisible(tenantA, 1)
	assertVisible(tenantB, 1)
	if err := (audit.Sink{Pool: pool}).Append(ctx, audit.Record{TenantID: tenantA, ActorType: "user", Action: "integration.test", Entity: "site", Diff: []byte(`{"ok":true}`)}); err != nil {
		t.Fatalf("append audit record: %v", err)
	}
	connAudit, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auditTx, err := connAudit.Begin(ctx)
	if err != nil {
		connAudit.Release()
		t.Fatal(err)
	}
	if _, err = auditTx.Exec(ctx, `SET LOCAL ROLE waf_api`); err != nil {
		t.Fatal(err)
	}
	if _, err = auditTx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantA.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = auditTx.Exec(ctx, `UPDATE audit_logs SET action='tampered' WHERE tenant_id=$1`, tenantA); err == nil {
		t.Fatal("API role updated append-only audit log")
	}
	_ = auditTx.Rollback(ctx)
	connAudit.Release()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		conn.Release()
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE waf_api`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantA.String()); err != nil {
		t.Fatal(err)
	}
	var hidden int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE tenant_id=$1`, tenantB).Scan(&hidden); err != nil {
		t.Fatal(err)
	}
	if hidden != 0 {
		t.Fatalf("cross-tenant site IDOR exposed %d rows", hidden)
	}
	_ = tx.Rollback(ctx)
	conn.Release()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.Service{Pool: appPool, Redis: rc, JWTPrivate: private, JWTKeyID: "integration", TOTPEncryptionKey: make([]byte, 32)}
	email := "integration-" + uuid.NewString() + "@example.test"
	cleanup.email(email)
	if addr := os.Getenv("MAILHOG_ADDR"); addr != "" {
		svc.Mailer = auth.SMTPMailer{Addr: addr, From: "noreply@example.test"}
	}
	if err = svc.Register(ctx, email, "correct horse battery staple"); err != nil {
		t.Fatalf("register: %v", err)
	}
	var userID uuid.UUID
	if err = pool.QueryRow(ctx, `SELECT id FROM users WHERE lower(email)=lower($1)`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if apiURL := os.Getenv("MAILHOG_API_URL"); apiURL != "" {
		type mail struct {
			To []struct {
				Mailbox string `json:"Mailbox"`
				Domain  string `json:"Domain"`
			} `json:"To"`
			Content struct {
				Body string `json:"Body"`
			} `json:"Content"`
		}
		var messages struct {
			Items []mail `json:"items"`
		}
		deadline := time.Now().Add(5 * time.Second)
		var body string
		for time.Now().Before(deadline) && body == "" {
			resp, e := http.Get(apiURL)
			if e == nil {
				_ = json.NewDecoder(resp.Body).Decode(&messages)
				_ = resp.Body.Close()
				for i := len(messages.Items) - 1; i >= 0; i-- {
					for _, to := range messages.Items[i].To {
						if strings.EqualFold(to.Mailbox+"@"+to.Domain, email) {
							body = messages.Items[i].Content.Body
							break
						}
					}
					if body != "" {
						break
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if body == "" {
			t.Fatalf("Mailhog did not receive verification email for %s", email)
		}
		marker := "Verification token: "
		at := strings.Index(body, marker)
		if at < 0 {
			t.Fatal("verification message has no token")
		}
		if err = svc.VerifyEmail(ctx, strings.TrimSpace(body[at+len(marker):])); err != nil {
			t.Fatalf("verify email: %v", err)
		}
	}
	if _, err = pool.Exec(ctx, `UPDATE users SET status='active',email_verified_at=coalesce(email_verified_at,now()) WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	secret, _, err := svc.CreateTOTP(ctx, userID)
	if err != nil {
		t.Fatalf("create TOTP: %v", err)
	}
	fixed := time.Now().UTC().Truncate(30 * time.Second)
	svc.Clock = func() time.Time { return fixed }
	for _, delta := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, e := totp.GenerateCodeCustom(secret, fixed.Add(delta), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if e != nil {
			t.Fatal(e)
		}
		if !svc.VerifyTOTP(ctx, userID, code) {
			t.Fatalf("TOTP skew %s rejected", delta)
		}
	}
	badCode, e := totp.GenerateCodeCustom(secret, fixed.Add(60*time.Second), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if e != nil {
		t.Fatal(e)
	}
	if svc.VerifyTOTP(ctx, userID, badCode) {
		t.Fatal("TOTP accepted beyond one-step skew")
	}
	// A newly configured secret gives the enable flow an unused current-step code.
	secret, _, err = svc.CreateTOTP(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	currentCode, e := totp.GenerateCodeCustom(secret, fixed, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if e != nil {
		t.Fatal(e)
	}
	if !svc.EnableTOTP(ctx, userID, currentCode) {
		t.Fatal("TOTP could not be enabled")
	}
	if svc.VerifyTOTP(ctx, userID, currentCode) {
		t.Fatal("TOTP replay accepted")
	}
	missingEmail := "absent-" + uuid.NewString() + "@example.test"
	cleanup.email(missingEmail)
	for i := 0; i < 11; i++ {
		_, loginErr := svc.Login(ctx, missingEmail, "bad", "integration", "127.0.0.1", "", "")
		if loginErr == nil {
			t.Fatal("unknown account login succeeded")
		}
	}
	nextCode, e := totp.GenerateCodeCustom(secret, fixed.Add(30*time.Second), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if e != nil {
		t.Fatal(e)
	}
	first, err := svc.Login(ctx, email, "correct horse battery staple", "integration", "127.0.0.1", nextCode, "")
	if err != nil {
		t.Fatalf("valid login: %v", err)
	}
	if _, err = svc.Login(ctx, email, "correct horse battery staple", "integration", "127.0.0.1", nextCode, ""); err == nil {
		t.Fatal("TOTP code replay logged in again")
	}
	rotated, err := svc.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token did not rotate")
	}
	if _, err = svc.Refresh(ctx, first.RefreshToken); err == nil {
		t.Fatal("reuse of old refresh token accepted")
	}
	var active int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE family_id=(SELECT family_id FROM refresh_tokens WHERE token_hash=$1) AND revoked_at IS NULL`, hashForTest(rotated.RefreshToken)).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("refresh reuse did not revoke token family; active=%d", active)
	}
}

func hashForTest(token string) []byte { sum := sha256.Sum256([]byte(token)); return sum[:] }

type capturedMail struct{ To, Subject, Body string }
type captureMailer struct{ messages chan capturedMail }

func (m *captureMailer) Send(_ context.Context, to, subject, body string) error {
	m.messages <- capturedMail{To: to, Subject: subject, Body: body}
	return nil
}

func newAuthService(t *testing.T, pool *pgxpool.Pool, rc *redis.Client, mailer auth.Mailer) auth.Service {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return auth.Service{Pool: pool, Redis: rc, Mailer: mailer, JWTPrivate: private, JWTKeyID: "integration", TOTPEncryptionKey: make([]byte, 32)}
}

func receivedToken(t *testing.T, m *captureMailer, marker string) string {
	t.Helper()
	select {
	case message := <-m.messages:
		at := strings.Index(message.Body, marker)
		if at < 0 {
			t.Fatalf("mail %q did not contain token marker", message.Subject)
		}
		return strings.TrimSpace(message.Body[at+len(marker):])
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for test mail")
		return ""
	}
}

func TestAuthCredentialIsolationAndDefinerHardening(t *testing.T) {
	ctx, admin, rc := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, rc)
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	mail := &captureMailer{messages: make(chan capturedMail, 16)}
	svc := newAuthService(t, app, rc, mail)
	emailA, emailB := "security-a-"+uuid.NewString()+"@example.test", "security-b-"+uuid.NewString()+"@example.test"
	cleanup.email(emailA)
	cleanup.email(emailB)
	if err := svc.Register(ctx, emailA, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	verifyA := receivedToken(t, mail, "Verification token: ")
	if err := svc.VerifyEmail(ctx, verifyA); err != nil {
		t.Fatal(err)
	}
	if err := svc.Register(ctx, emailB, "another correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	verifyB := receivedToken(t, mail, "Verification token: ")
	if err := svc.VerifyEmail(ctx, verifyB); err != nil {
		t.Fatal(err)
	}
	var userA, userB uuid.UUID
	if err := admin.QueryRow(ctx, `SELECT id FROM public.users WHERE email=$1`, emailA).Scan(&userA); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT id FROM public.users WHERE email=$1`, emailB).Scan(&userB); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateTOTP(ctx, userB); err != nil {
		t.Fatal(err)
	}
	sessionA, err := svc.Login(ctx, emailA, "correct horse battery staple", "test", "192.0.2.20", "", "")
	if err != nil {
		t.Fatal(err)
	}
	sessionB, err := svc.Login(ctx, emailB, "another correct horse battery staple", "test", "192.0.2.21", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var sessionBID uuid.UUID
	if err = admin.QueryRow(ctx, `SELECT id FROM public.refresh_tokens WHERE token_hash=$1`, hashForTest(sessionB.RefreshToken)).Scan(&sessionBID); err != nil {
		t.Fatal(err)
	}
	issuedKey, err := (tenant.Service{Pool: app}).CreateAPIKey(ctx, sessionA.TenantID, userA, "integration", []string{"sites:read"}, nil)
	if err != nil {
		t.Fatalf("API key creation via restricted role: %v", err)
	}
	keyHash := hashForTest(issuedKey.Plaintext)
	var storedKeyHash []byte
	if err = admin.QueryRow(ctx, `SELECT key_hash FROM public.api_keys WHERE id=$1`, issuedKey.ID).Scan(&storedKeyHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyHash, storedKeyHash) {
		t.Fatal("API key plaintext was not stored as its SHA-256 hash")
	}
	if err = svc.RequestPasswordReset(ctx, emailB); err != nil {
		t.Fatal(err)
	}
	resetToken := receivedToken(t, mail, "If an account exists, use this reset token: ")
	for _, login := range []auth.Tokens{sessionA, sessionB} {
		var count int
		if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.refresh_tokens WHERE token_hash=$1`, hashForTest(login.RefreshToken)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("refresh test fixture count=%d, want 1", count)
		}
	}

	t.Run("user_scope_and_sensitive_table_denials", func(t *testing.T) {
		var noUserContext int
		if e := app.QueryRow(ctx, `SELECT count(id) FROM public.users`).Scan(&noUserContext); e != nil {
			t.Fatalf("missing app.user_id should not error: %v", e)
		}
		if noUserContext != 0 {
			t.Fatalf("missing app.user_id exposed %d users", noUserContext)
		}
		for _, query := range []string{
			`SELECT password_hash FROM public.users WHERE id=$1`,
			`SELECT totp_secret_enc FROM public.users WHERE id=$1`,
			`SELECT token_hash FROM public.refresh_tokens WHERE user_id=$1`,
			`SELECT token_hash FROM public.email_verification_tokens WHERE user_id=$1`,
			`SELECT token_hash FROM public.password_reset_tokens WHERE user_id=$1`,
			`SELECT code_hash FROM public.totp_recovery_codes WHERE user_id=$1`,
			`SELECT key_hash FROM public.api_keys WHERE tenant_id=$1`,
			`SELECT token_hash FROM public.invitations WHERE tenant_id=$1`,
			`SELECT verification_token_hash FROM public.domains WHERE tenant_id=$1`,
		} {
			if _, e := app.Exec(ctx, query, userB); e == nil {
				t.Errorf("sensitive query was permitted: %s", query)
			}
		}
		var visible int
		if e := db.WithUserTx(ctx, app, userA, func(tx pgx.Tx) error {
			if e := tx.QueryRow(ctx, `SELECT count(id) FROM public.users`).Scan(&visible); e != nil {
				return e
			}
			var rows int
			if e := tx.QueryRow(ctx, `SELECT count(*) FROM public.refresh_tokens`).Scan(&rows); e != nil {
				return e
			}
			if rows != 1 {
				return fmt.Errorf("user A sees %d sessions, want 1", rows)
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		if visible != 1 {
			t.Fatalf("user A sees %d users without WHERE, want 1", visible)
		}
		var changed int64
		if e := db.WithUserTx(ctx, app, userA, func(tx pgx.Tx) error {
			tag, e := tx.Exec(ctx, `UPDATE public.refresh_tokens SET revoked_at=now() WHERE id=$1`, sessionBID)
			if e != nil {
				return e
			}
			changed = tag.RowsAffected()
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		if changed != 0 {
			t.Fatalf("user A updated %d of user B's sessions", changed)
		}
		if _, e := app.Exec(ctx, `DELETE FROM public.refresh_tokens WHERE user_id=$1`, userB); e == nil {
			t.Fatal("API deleted another user's session")
		}
		if _, e := app.Exec(ctx, `UPDATE public.password_reset_tokens SET used_at=now() WHERE user_id=$1`, userB); e == nil {
			t.Fatal("API updated another user's reset token")
		}
		if _, e := app.Exec(ctx, `DELETE FROM public.password_reset_tokens WHERE user_id=$1`, userB); e == nil {
			t.Fatal("API deleted another user's reset token")
		}
		if _, e := app.Exec(ctx, `UPDATE public.email_verification_tokens SET used_at=now() WHERE user_id=$1`, userB); e == nil {
			t.Fatal("API updated another user's verification token")
		}
	})

	t.Run("function_owner_search_path_and_column_privileges", func(t *testing.T) {
		var unsafe int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.prosecdef AND (r.rolname<>'waf_worker' OR r.rolsuper OR NOT r.rolbypassrls OR NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(p.proconfig) AS cfg(setting) WHERE cfg.setting LIKE 'search_path=pg_catalog, public%'))`).Scan(&unsafe); err != nil {
			t.Fatal(err)
		}
		if unsafe != 0 {
			t.Fatalf("%d public SECURITY DEFINER functions have unsafe owner/search_path", unsafe)
		}
		for _, col := range [][2]string{{"users", "password_hash"}, {"users", "totp_secret_enc"}, {"users", "totp_last_step"}, {"refresh_tokens", "token_hash"}, {"email_verification_tokens", "token_hash"}, {"password_reset_tokens", "token_hash"}, {"totp_recovery_codes", "code_hash"}, {"api_keys", "key_hash"}, {"invitations", "token_hash"}, {"domains", "verification_token_hash"}} {
			var selectOK, insertOK, updateOK bool
			if err := admin.QueryRow(ctx, `SELECT has_column_privilege('waf_api','public.'||$1,$2,'SELECT'),has_column_privilege('waf_api','public.'||$1,$2,'INSERT'),has_column_privilege('waf_api','public.'||$1,$2,'UPDATE')`, col[0], col[1]).Scan(&selectOK, &insertOK, &updateOK); err != nil {
				t.Fatal(err)
			}
			if selectOK || insertOK || updateOK {
				t.Errorf("waf_api has sensitive column privileges on %s.%s: select=%v insert=%v update=%v", col[0], col[1], selectOK, insertOK, updateOK)
			}
		}
		conn, err := app.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		if _, err = conn.Exec(ctx, `CREATE TEMP TABLE users(id uuid,email text,password_hash text,status text,default_tenant_id uuid,totp_secret_enc bytea,totp_enabled_at timestamptz)`); err != nil {
			t.Fatal(err)
		}
		if _, err = conn.Exec(ctx, `INSERT INTO pg_temp.users(email,password_hash) VALUES($1,'attacker')`, emailB); err != nil {
			t.Fatal(err)
		}
		var actual uuid.UUID
		if err = conn.QueryRow(ctx, `SELECT user_id FROM public.auth_login_material($1)`, emailB).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != userB {
			t.Fatal("SECURITY DEFINER login lookup resolved a shadow table")
		}
		// The caller does not learn whether reset target exists from the function result or HTTP service.
		if err = svc.ResetPassword(ctx, resetToken, "a new secure password phrase"); err != nil {
			t.Fatal(err)
		}
		var auditEvents int
		if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_logs WHERE tenant_id=$1 AND action LIKE 'auth.%'`, sessionB.TenantID).Scan(&auditEvents); err != nil {
			t.Fatal(err)
		}
		if auditEvents == 0 {
			t.Fatal("credential mutations did not emit audit events")
		}
	})
	t.Run("invitation_token_and_narrow_member_directory", func(t *testing.T) {
		tenantService := tenant.Service{Pool: app}
		invitation, e := tenantService.Invite(ctx, sessionA.TenantID, userA, emailB, tenant.Viewer)
		if e != nil {
			t.Fatalf("create invitation through API role: %v", e)
		}
		rawInvitation, e := base64.RawURLEncoding.DecodeString(invitation)
		if e != nil {
			t.Fatal(e)
		}
		invitationHash := sha256.Sum256(rawInvitation)
		var stored []byte
		if e = admin.QueryRow(ctx, `SELECT token_hash FROM public.invitations WHERE token_hash=$1`, invitationHash[:]).Scan(&stored); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(invitationHash[:], stored) {
			t.Fatal("invitation token stored without hashing")
		}
		if _, e = app.Exec(ctx, `SELECT token_hash FROM public.invitations WHERE token_hash=$1`, invitationHash[:]); e == nil {
			t.Fatal("waf_api read invitation token hash")
		}
		if e = tenantService.AcceptInvite(ctx, userB, invitation); e != nil {
			t.Fatalf("accept invitation through API role: %v", e)
		}
		if _, e = tenantService.CreateAPIKey(ctx, sessionA.TenantID, userB, "viewer-forbidden", []string{"sites:read"}, nil); e == nil {
			t.Fatal("viewer unexpectedly created API key")
		}
		if _, e = tenantService.Invite(ctx, sessionA.TenantID, userB, emailA, tenant.Viewer); e == nil {
			t.Fatal("viewer unexpectedly created invitation")
		}
		if _, e = tenantService.CreateAPIKey(ctx, sessionA.TenantID, userA, "bad-scope", []string{"users:admin"}, nil); e == nil {
			t.Fatal("scope outside explicit allowlist was accepted")
		}
		if _, e = admin.Exec(ctx, `UPDATE public.memberships SET role='admin' WHERE tenant_id=$1 AND user_id=$2`, sessionA.TenantID, userB); e != nil {
			t.Fatal(e)
		}
		if _, e = tenantService.Invite(ctx, sessionA.TenantID, userB, emailA, tenant.Owner); e == nil {
			t.Fatal("admin unexpectedly invited owner role")
		}
		members, e := tenantService.ListMembers(ctx, sessionA.TenantID, userA)
		if e != nil {
			t.Fatal(e)
		}
		if len(members) != 2 {
			t.Fatalf("narrow member directory returned %d rows, want 2", len(members))
		}
	})
}

func TestRefreshCreationRequiresBoundIdentityAndDefinerInventory(t *testing.T) {
	ctx, admin, rc := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, rc)
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	mail := &captureMailer{messages: make(chan capturedMail, 8)}
	svc := newAuthService(t, app, rc, mail)
	registerAndVerify := func(email, password string) uuid.UUID {
		t.Helper()
		cleanup.email(email)
		if err := svc.Register(ctx, email, password); err != nil {
			t.Fatal(err)
		}
		if err := svc.VerifyEmail(ctx, receivedToken(t, mail, "Verification token: ")); err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		if err := admin.QueryRow(ctx, `SELECT id FROM public.users WHERE email=$1`, email).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	userA := registerAndVerify("bind-a-"+uuid.NewString()+"@example.test", "a correct horse battery staple")
	userB := registerAndVerify("bind-b-"+uuid.NewString()+"@example.test", "another correct horse battery staple")
	var tenantA, tenantB uuid.UUID
	if err := admin.QueryRow(ctx, `SELECT default_tenant_id FROM public.users WHERE id=$1`, userA).Scan(&tenantA); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT default_tenant_id FROM public.users WHERE id=$1`, userB).Scan(&tenantB); err != nil {
		t.Fatal(err)
	}
	t.Run("identity_arguments_require_matching_session_or_return_empty", func(t *testing.T) {
		var totpConfigured bool
		if err := db.WithUserTx(ctx, app, userA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT public.auth_configure_totp($1,$2,'[]'::jsonb)`, userB, []byte("not-used")).Scan(&totpConfigured)
		}); err != nil {
			t.Fatal(err)
		}
		if totpConfigured {
			t.Fatal("auth_configure_totp accepted user B from user A context")
		}
		if err := app.QueryRow(ctx, `SELECT public.auth_configure_totp($1,$2,'[]'::jsonb)`, userB, []byte("not-used")).Scan(&totpConfigured); err != nil || totpConfigured {
			t.Fatalf("auth_configure_totp without context configured=%v err=%v", totpConfigured, err)
		}
		var visible int
		if err := db.WithUserTenantTx(ctx, app, userA, tenantA, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.tenant_list_members($1)`, tenantB).Scan(&visible); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SAVEPOINT expect_denial`); err != nil {
				return err
			}
			_, keyErr := tx.Exec(ctx, `SELECT public.tenant_create_api_key($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), tenantB, "cross", []byte("hash"), []string{"sites:read"}, userB, uuid.New(), time.Now().Add(time.Hour))
			if keyErr == nil {
				return fmt.Errorf("tenant_create_api_key accepted tenant B from tenant A context")
			}
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT expect_denial`); err != nil {
				return err
			}
			_, inviteErr := tx.Exec(ctx, `SELECT public.tenant_create_invitation($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), tenantB, "invite-"+uuid.NewString()+"@example.test", "viewer", []byte("hash"), time.Now().Add(time.Hour), userB, uuid.New())
			if inviteErr == nil {
				return fmt.Errorf("tenant_create_invitation accepted tenant B from tenant A context")
			}
			if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT expect_denial`); err != nil {
				return err
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if visible != 0 {
			t.Fatalf("tenant_list_members exposed %d rows across tenant context", visible)
		}
		if _, err := app.Exec(ctx, `SELECT public.tenant_create_api_key($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), tenantB, "no-context", []byte("hash"), []string{"sites:read"}, userB, uuid.New(), time.Now().Add(time.Hour)); err == nil {
			t.Fatal("tenant_create_api_key accepted missing session context")
		}
	})

	before := func() int {
		var n int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.refresh_tokens WHERE user_id=$1`, userB).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	initial := before()
	callCreate := func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT public.auth_create_refresh($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), userB, uuid.New(), hashForTest("forged-refresh"), "test", "192.0.2.99", time.Now().Add(time.Hour))
		return err
	}
	if err := db.WithUserTx(ctx, app, userA, callCreate); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("cross-user refresh creation err=%v, want forbidden", err)
	}
	noContextTx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	noContextErr := callCreate(noContextTx)
	_ = noContextTx.Rollback(ctx)
	if noContextErr == nil || !strings.Contains(noContextErr.Error(), "forbidden") {
		t.Fatalf("refresh creation without app.user_id err=%v, want forbidden", noContextErr)
	}
	if got := before(); got != initial {
		t.Fatalf("rejected call changed user B refresh rows: before=%d after=%d", initial, got)
	}

	missingLoginEmail := "bind-a-not-used-" + uuid.NewString() + "@example.test"
	cleanup.email(missingLoginEmail)
	login, err := svc.Login(ctx, missingLoginEmail, "wrong password", "", "", "", "")
	if err == nil || login.RefreshToken != "" {
		t.Fatal("invalid login unexpectedly created a session")
	}
	// A successful login proves the application now binds the verified identity before
	// invoking auth_create_refresh; the migration audit records the personal tenant.
	var emailA string
	if err = admin.QueryRow(ctx, `SELECT email FROM public.users WHERE id=$1`, userA).Scan(&emailA); err != nil {
		t.Fatal(err)
	}
	login, err = svc.Login(ctx, emailA, "a correct horse battery staple", "test", "192.0.2.11", "", "")
	if err != nil {
		t.Fatalf("valid login with identity-bound session failed: %v", err)
	}
	var auditCount int
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_logs WHERE actor_id=$1 AND action='auth.session.create'`, userA).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("session creation audit count=%d err=%v, want 1", auditCount, err)
	}

	// Every definer function must be explicitly reviewed here; the description records
	// where the identity comes from and what the function may return or mutate.
	allow := map[string]string{
		"lookup_invitation":               "token hash possession; locked invitation metadata only",
		"auth_register_user":              "new UUIDs supplied by registration; inserts one personal tenant only",
		"auth_login_material":             "email lookup; minimal password/TOTP material, equal-cost dummy hash in Go when absent",
		"auth_consume_email_verification": "verification token hash possession; consumes one token",
		"auth_create_refresh":             "app.user_id must equal p_user_id and active user row; creates own session + audit",
		"auth_rotate_refresh":             "refresh token hash possession; atomically rotates/revokes family",
		"auth_logout_refresh":             "refresh token hash possession; revokes matching session",
		"auth_password_reset_request":     "email-triggered generic reset; stores token only for matching account",
		"auth_complete_password_reset":    "reset token hash possession; changes password and revokes sessions",
		"auth_configure_totp":             "app.user_id must equal p_user_id; sets own encrypted secret and code hashes",
		"auth_totp_secret":                "app.user_id; returns own encrypted TOTP material only",
		"auth_consume_totp_step":          "app.user_id; consumes own current step",
		"auth_enable_totp":                "app.user_id; enables own configured TOTP",
		"auth_consume_recovery_code":      "app.user_id + recovery hash; consumes own code",
		"audit_auth_mutation":             "trigger-only; derives subject from changed row and emits secret-free audit",
		"tenant_create_api_key":           "session tenant/user + owner/admin membership; allowlisted scopes only",
		"tenant_create_invitation":        "session tenant/user + owner/admin membership; cannot invite owner",
		"tenant_accept_invitation":        "app.user_id + matching user email + invitation hash; inserts own membership",
		"tenant_list_members":             "app.user_id membership in app.tenant_id; narrow member metadata",
		"site_add_domain":                 "app.user_id and app.tenant_id plus owner/admin membership; writes token digest and audit",
	}
	rows, err := admin.Query(ctx, `SELECT p.proname::text,
      EXISTS (SELECT 1 FROM pg_catalog.unnest(p.proconfig) c WHERE c LIKE 'search_path=pg_catalog, public%'),
      r.rolname, r.rolsuper,
      (SELECT count(*) FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
       WHERE a.grantee NOT IN (p.proowner,(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='waf_api'))),
      EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
       WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    JOIN pg_catalog.pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.prosecdef`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var signature, owner string
		var fixedPath, superuser, publicExec bool
		var unexpectedGrants int
		if err = rows.Scan(&signature, &fixedPath, &owner, &superuser, &unexpectedGrants, &publicExec); err != nil {
			t.Fatal(err)
		}
		if _, ok := allow[signature]; !ok {
			t.Errorf("unreviewed SECURITY DEFINER function %s", signature)
		}
		seen[signature] = true
		if !fixedPath || owner != "waf_worker" || superuser || unexpectedGrants != 0 {
			t.Errorf("unsafe SECURITY DEFINER %s: search_path=%v owner=%s superuser=%v unexpected_grants=%d", signature, fixedPath, owner, superuser, unexpectedGrants)
		}
		if publicExec {
			t.Errorf("PUBLIC can EXECUTE %s", signature)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for signature, reason := range allow {
		if !seen[signature] {
			t.Errorf("allowlisted SECURITY DEFINER missing %s: %s", signature, reason)
		}
	}
}

func TestPublicTableRLSAllowlist(t *testing.T) {
	ctx, pool, _ := integrationDeps(t)
	_ = cleanupForTest(t, pool)
	allow := map[string]string{
		"plans":            "globally readable product catalog; contains no tenant data",
		"config_snapshots": "control-plane signed snapshot metadata, restricted by deployment grants",
		"edges":            "fleet-wide control-plane inventory, restricted by deployment grants",
		"webhook_events":   "provider idempotency inbox, restricted by deployment grants",
		"goose_db_version": "migration bookkeeping, not application tenant data",
	}
	rows, err := pool.Query(ctx, `SELECT c.relname,c.relrowsecurity FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		var hasRLS bool
		if err = rows.Scan(&name, &hasRLS); err != nil {
			t.Fatal(err)
		}
		seen[name] = true
		if !hasRLS {
			if _, ok := allow[name]; !ok {
				t.Errorf("public table %q has RLS disabled and is not allowlisted", name)
			}
		}
		if hasRLS {
			if _, ok := allow[name]; ok {
				t.Errorf("allowlisted table %q unexpectedly has RLS enabled; review allowlist", name)
			}
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for name, reason := range allow {
		if !seen[name] {
			t.Errorf("allowlisted table %q is missing: %s", name, reason)
		}
	}
	var rls, forced bool
	if err = pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class WHERE oid='public.config_change_outbox'::regclass`).Scan(&rls, &forced); err != nil {
		t.Fatal(err)
	}
	if !rls || !forced {
		t.Fatalf("config_change_outbox requires ENABLE and FORCE RLS; enabled=%v forced=%v", rls, forced)
	}
	var usingExpr, checkExpr string
	if err = pool.QueryRow(ctx, `SELECT coalesce(qual,''),coalesce(with_check,'') FROM pg_catalog.pg_policies WHERE schemaname='public' AND tablename='config_change_outbox' AND policyname='tenant_isolation'`).Scan(&usingExpr, &checkExpr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(usingExpr, "app.tenant_id") || !strings.Contains(checkExpr, "app.tenant_id") {
		t.Fatalf("outbox RLS policy is not tenant scoped: USING=%q WITH CHECK=%q", usingExpr, checkExpr)
	}
	var apiInsert, apiSelect, apiUpdate, apiDelete, workerRead, workerUpdate, workerPayloadUpdate, workerInsert, workerDelete bool
	if err = pool.QueryRow(ctx, `SELECT has_column_privilege('waf_api','public.config_change_outbox','payload','INSERT'),has_column_privilege('waf_api','public.config_change_outbox','payload','SELECT'),has_column_privilege('waf_api','public.config_change_outbox','payload','UPDATE'),has_table_privilege('waf_api','public.config_change_outbox','DELETE'),has_column_privilege('waf_worker','public.config_change_outbox','payload','SELECT'),has_column_privilege('waf_worker','public.config_change_outbox','published_at','UPDATE'),has_column_privilege('waf_worker','public.config_change_outbox','payload','UPDATE'),has_column_privilege('waf_worker','public.config_change_outbox','payload','INSERT'),has_table_privilege('waf_worker','public.config_change_outbox','DELETE')`).Scan(&apiInsert, &apiSelect, &apiUpdate, &apiDelete, &workerRead, &workerUpdate, &workerPayloadUpdate, &workerInsert, &workerDelete); err != nil {
		t.Fatal(err)
	}
	if !apiInsert || apiSelect || apiUpdate || apiDelete || !workerRead || !workerUpdate || workerPayloadUpdate || !workerInsert || workerDelete {
		t.Fatalf("unexpected outbox grants: API insert/select/update/delete=%v/%v/%v/%v worker payload-read/published-update/payload-update/insert/delete=%v/%v/%v/%v/%v", apiInsert, apiSelect, apiUpdate, apiDelete, workerRead, workerUpdate, workerPayloadUpdate, workerInsert, workerDelete)
	}
}

func TestAuthFlowsAndConcurrentRefreshRotation(t *testing.T) {
	ctx, admin, rc := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, rc)
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	mail := &captureMailer{messages: make(chan capturedMail, 16)}
	svc := newAuthService(t, app, rc, mail)
	email := "flow-" + uuid.NewString() + "@example.test"
	cleanup.email(email)
	t.Run("registration_verification_generic_login_reset_logout", func(t *testing.T) {
		if err := svc.Register(ctx, email, "correct horse battery staple"); err != nil {
			t.Fatal(err)
		}
		verifyToken := receivedToken(t, mail, "Verification token: ")
		if err := svc.VerifyEmail(ctx, verifyToken); err != nil {
			t.Fatal(err)
		}
		if err := svc.VerifyEmail(ctx, verifyToken); err == nil {
			t.Fatal("verification token was reusable")
		}
		unknownLoginEmail := "absent-" + uuid.NewString() + "@example.test"
		cleanup.email(unknownLoginEmail)
		missingErr := func() error {
			_, e := svc.Login(ctx, unknownLoginEmail, "wrong password", "", "", "", "")
			return e
		}()
		wrongErr := func() error { _, e := svc.Login(ctx, email, "wrong password", "", "", "", ""); return e }()
		if missingErr != auth.ErrCredentials || wrongErr != auth.ErrCredentials {
			t.Fatalf("login errors expose account state: missing=%v wrong=%v", missingErr, wrongErr)
		}
		login, err := svc.Login(ctx, email, "correct horse battery staple", "test", "192.0.2.42", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if err = svc.Logout(ctx, login.RefreshToken); err != nil {
			t.Fatal(err)
		}
		if _, err = svc.Refresh(ctx, login.RefreshToken); err == nil {
			t.Fatal("logged-out refresh token remained valid")
		}
		if err = svc.RequestPasswordReset(ctx, email); err != nil {
			t.Fatal(err)
		}
		reset := receivedToken(t, mail, "If an account exists, use this reset token: ")
		if err = svc.RequestPasswordReset(ctx, "absent-"+uuid.NewString()+"@example.test"); err != nil {
			t.Fatal(err)
		}
		unknownResetMail := receivedToken(t, mail, "If an account exists, use this reset token: ")
		if unknownResetMail == reset {
			t.Fatal("reset token was reused across requests")
		}
		if err = svc.ResetPassword(ctx, reset, "new correct horse battery staple"); err != nil {
			t.Fatal(err)
		}
		if err = svc.ResetPassword(ctx, reset, "another new secure password"); err == nil {
			t.Fatal("password reset token was reusable")
		}
		if _, err = svc.Login(ctx, email, "correct horse battery staple", "", "", "", ""); err == nil {
			t.Fatal("old password remained valid")
		}
		if _, err = svc.Login(ctx, email, "new correct horse battery staple", "", "", "", ""); err != nil {
			t.Fatalf("new password failed: %v", err)
		}
	})
	t.Run("only_one_concurrent_refresh_wins", func(t *testing.T) {
		freshEmail := "rotate-" + uuid.NewString() + "@example.test"
		cleanup.email(freshEmail)
		if err := svc.Register(ctx, freshEmail, "correct horse battery staple"); err != nil {
			t.Fatal(err)
		}
		if err := svc.VerifyEmail(ctx, receivedToken(t, mail, "Verification token: ")); err != nil {
			t.Fatal(err)
		}
		login, err := svc.Login(ctx, freshEmail, "correct horse battery staple", "", "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		const requests = 2
		start := make(chan struct{})
		results := make(chan error, requests)
		var wg sync.WaitGroup
		for i := 0; i < requests; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; _, e := svc.Refresh(ctx, login.RefreshToken); results <- e }()
		}
		close(start)
		wg.Wait()
		close(results)
		ok := 0
		for e := range results {
			if e == nil {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("same refresh token had %d successful rotations, want exactly 1", ok)
		}
	})
}

type siteFakeDNS struct {
	records []string
	cname   string
	ips     []net.IP
}

func (d siteFakeDNS) LookupTXT(context.Context, string) ([]string, error)        { return d.records, nil }
func (d siteFakeDNS) LookupCNAME(context.Context, string) (string, error)        { return d.cname, nil }
func (d siteFakeDNS) LookupIP(context.Context, string, string) ([]net.IP, error) { return d.ips, nil }

func TestSiteQuotaHostnameOwnershipAndStateIntegration(t *testing.T) {
	ctx, admin, redisClient := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, redisClient)
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	worker := workerRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	mailer := &captureMailer{messages: make(chan capturedMail, 16)}
	authSvc := newAuthService(t, app, redisClient, mailer)
	register := func(label string) (uuid.UUID, uuid.UUID) {
		t.Helper()
		email := label + "-" + uuid.NewString() + "@example.test"
		cleanup.email(email)
		if err := authSvc.Register(ctx, email, "a correct horse battery staple"); err != nil {
			t.Fatal(err)
		}
		if err := authSvc.VerifyEmail(ctx, receivedToken(t, mailer, "Verification token: ")); err != nil {
			t.Fatal(err)
		}
		var userID, tenantID uuid.UUID
		if err := admin.QueryRow(ctx, `SELECT id,default_tenant_id FROM public.users WHERE email=$1`, email).Scan(&userID, &tenantID); err != nil {
			t.Fatal(err)
		}
		return userID, tenantID
	}
	userA, tenantA := register("site-race-a")
	userB, tenantB := register("site-race-b")
	cleanup.tenant(tenantA)
	cleanup.tenant(tenantB)
	siteNameSuffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	raceSiteName := "race-site-" + siteNameSuffix
	tenantBSiteName := "tenant-b-site-" + siteNameSuffix
	service := site.Service{Pool: app}
	t.Run("free_site_quota_serializes_concurrent_creates", func(t *testing.T) {
		start := make(chan struct{})
		type result struct {
			site site.Site
			err  error
		}
		results := make(chan result, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				s, e := service.Create(ctx, tenantA, userA, raceSiteName)
				results <- result{s, e}
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		success, quota := 0, 0
		for r := range results {
			if r.err == nil {
				success++
			} else if errors.Is(r.err, entitlement.ErrQuotaExceeded) {
				quota++
			} else {
				t.Errorf("unexpected concurrent site creation result: %v", r.err)
			}
		}
		if success != 1 || quota != 1 {
			t.Fatalf("site create successes=%d quota rejects=%d; want one each", success, quota)
		}
	})
	siteA, err := service.Create(ctx, tenantB, userB, tenantBSiteName)
	if err != nil {
		t.Fatal(err)
	}
	var siteAID uuid.UUID
	if err = admin.QueryRow(ctx, `SELECT id FROM public.sites WHERE tenant_id=$1 AND name=$2`, tenantA, raceSiteName).Scan(&siteAID); err != nil {
		t.Fatal(err)
	}
	for _, siteID := range []uuid.UUID{siteAID, siteA.ID} {
		var status string
		if err := admin.QueryRow(ctx, `SELECT status FROM public.sites WHERE id=$1`, siteID).Scan(&status); err != nil || status != "pending_dns" {
			t.Fatalf("new site %s status=%q err=%v, want pending_dns", siteID, status, err)
		}
	}
	if _, err := service.AddOrigin(ctx, tenantA, userA, siteAID, "https://origin.example", siteFakeDNS{ips: []net.IP{net.ParseIP("203.0.113.21")}}); err != nil {
		t.Fatalf("add origin before verification: %v", err)
	}
	var originSiteStatus string
	if err := admin.QueryRow(ctx, `SELECT status FROM public.sites WHERE id=$1`, siteAID).Scan(&originSiteStatus); err != nil || originSiteStatus != "pending_dns" {
		t.Fatalf("adding an origin changed pending site status to %q: %v", originSiteStatus, err)
	}
	t.Run("same_hostname_race_and_non_disclosing_conflict", func(t *testing.T) {
		suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
		unicodeHost := "BÜCHER-" + suffix + ".EXAMPLE.TEST."
		canonicalHost, err := site.NormalizeHostname(unicodeHost)
		if err != nil {
			t.Fatal(err)
		}
		punycodeHost, err := site.NormalizeHostname(canonicalHost)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		type result struct {
			proof  site.DomainProof
			siteID uuid.UUID
			err    error
		}
		results := make(chan result, 2)
		var wg sync.WaitGroup
		for i, input := range []struct{ tenant, user, sid uuid.UUID }{{tenantA, userA, siteAID}, {tenantB, userB, siteA.ID}} {
			wg.Add(1)
			go func(v struct{ tenant, user, sid uuid.UUID }, hostname string) {
				defer wg.Done()
				<-start
				p, e := service.AddDomain(ctx, v.tenant, v.user, v.sid, hostname)
				results <- result{proof: p, siteID: v.sid, err: e}
			}(input, []string{unicodeHost, punycodeHost}[i])
		}
		close(start)
		wg.Wait()
		close(results)
		var winner site.DomainProof
		var winnerSiteID uuid.UUID
		var loserSiteID uuid.UUID
		var conflictErr error
		success, conflict := 0, 0
		for r := range results {
			if r.err == nil {
				success++
				winner = r.proof
				winnerSiteID = r.siteID
			} else if errors.Is(r.err, site.ErrHostnameUnavailable) {
				conflict++
				conflictErr = r.err
				loserSiteID = r.siteID
			} else {
				t.Errorf("unexpected domain result: %v", r.err)
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatalf("domain creates successes=%d conflicts=%d; want one each", success, conflict)
		}
		if winner.Hostname != canonicalHost || conflictErr == nil || strings.Contains(conflictErr.Error(), tenantA.String()) || strings.Contains(conflictErr.Error(), tenantB.String()) {
			t.Fatalf("hostname normalization/conflict disclosure mismatch: winner=%q err=%v", winner.Hostname, conflictErr)
		}
		if winnerSiteID == uuid.Nil || loserSiteID == uuid.Nil || winnerSiteID == loserSiteID {
			t.Fatalf("hostname race did not preserve winner/loser site identity: winner=%s loser=%s", winnerSiteID, loserSiteID)
		}
		if strings.Contains(winner.Hostname, tenantA.String()) || strings.Contains(winner.Hostname, tenantB.String()) {
			t.Fatal("hostname conflict response exposed tenant identity")
		}
		for _, expected := range []struct {
			siteID uuid.UUID
			status string
		}{{winnerSiteID, "pending_dns"}, {loserSiteID, "pending_dns"}} {
			var status string
			if err := admin.QueryRow(ctx, `SELECT status FROM public.sites WHERE id=$1`, expected.siteID).Scan(&status); err != nil || status != expected.status {
				t.Fatalf("site %s status after domain creation=%q err=%v, want %s", expected.siteID, status, err, expected.status)
			}
		}
		if _, err := service.AddDomain(ctx, tenantA, userA, siteA.ID, "cross-tenant-"+suffix+".example.test"); !errors.Is(err, site.ErrSiteNotFound) {
			t.Fatalf("cross-tenant site reference err=%v, want not found", err)
		}
		if _, err := service.AddOrigin(ctx, tenantA, userA, siteA.ID, "https://origin.example", siteFakeDNS{ips: []net.IP{net.ParseIP("203.0.113.21")}}); !errors.Is(err, site.ErrSiteNotFound) {
			t.Fatalf("cross-tenant origin reference err=%v, want not found", err)
		}
		hash := sha256.Sum256([]byte(winner.Token))
		var stored []byte
		if err := admin.QueryRow(ctx, `SELECT verification_token_hash FROM public.domains WHERE id=$1`, winner.ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hash[:], stored) {
			t.Fatal("domain verification token was not stored as SHA-256")
		}
		if _, err := app.Exec(ctx, `SELECT verification_token_hash FROM public.domains WHERE id=$1`, winner.ID); err == nil {
			t.Fatal("waf_api read domain verification token hash")
		}
		workerService := site.Service{Pool: worker, VerificationCNAMEZone: "verify.example.net"}
		if _, err := admin.Exec(ctx, `UPDATE public.domains SET next_verification_at=now()-interval '1 second' WHERE id=$1`, winner.ID); err != nil {
			t.Fatal(err)
		}
		badDNS := siteFakeDNS{records: []string{"not-the-token"}}
		if count, err := workerService.VerifyDueDomains(ctx, badDNS, time.Now(), 10); err != nil || count != 0 {
			t.Fatalf("invalid DNS proof batch count=%d err=%v", count, err)
		}
		if _, err := admin.Exec(ctx, `UPDATE public.domains SET next_verification_at=now()-interval '1 second' WHERE id=$1`, winner.ID); err != nil {
			t.Fatal(err)
		}
		dns := siteFakeDNS{records: []string{"not-the-token", winner.Token}}
		if count, err := workerService.VerifyDueDomains(ctx, dns, time.Now(), 10); err != nil || count != 1 {
			t.Fatalf("valid DNS proof batch count=%d err=%v", count, err)
		}
		var verified bool
		if err := admin.QueryRow(ctx, `SELECT verification_status='active' FROM public.domains WHERE id=$1`, winner.ID).Scan(&verified); err != nil || !verified {
			t.Fatalf("domain verification status active=%v err=%v", verified, err)
		}
		var winnerStatus, loserStatus string
		if err := admin.QueryRow(ctx, `SELECT status FROM public.sites WHERE id=$1`, winnerSiteID).Scan(&winnerStatus); err != nil || winnerStatus != "active" {
			t.Fatalf("verified domain owner site %s status=%q err=%v, want active", winnerSiteID, winnerStatus, err)
		}
		if err := admin.QueryRow(ctx, `SELECT status FROM public.sites WHERE id=$1`, loserSiteID).Scan(&loserStatus); err != nil || loserStatus != "pending_dns" {
			t.Fatalf("site %s without verified domain status=%q err=%v, want pending_dns", loserSiteID, loserStatus, err)
		}
		expiredProof, err := service.AddDomain(ctx, tenantA, userA, siteAID, "expired-"+suffix+".example.test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, `UPDATE public.domains SET verification_expires_at=now()-interval '1 second' WHERE id=$1`, expiredProof.ID); err != nil {
			t.Fatal(err)
		}
		var expiredSiteStatusBefore string
		if err = admin.QueryRow(ctx, `SELECT status FROM public.sites WHERE id=$1`, siteAID).Scan(&expiredSiteStatusBefore); err != nil {
			t.Fatal(err)
		}
		if err = workerService.VerifyDomain(ctx, tenantA, expiredProof.ID, siteFakeDNS{records: []string{expiredProof.Token}}); !errors.Is(err, site.ErrVerificationExpired) {
			t.Fatalf("expired proof result=%v, want ErrVerificationExpired", err)
		}
		var expiredStatus string
		if err = admin.QueryRow(ctx, `SELECT verification_status FROM public.domains WHERE id=$1`, expiredProof.ID).Scan(&expiredStatus); err != nil || expiredStatus != "failed" {
			t.Fatalf("expired domain status=%q err=%v", expiredStatus, err)
		}
		var expiredSiteStatusAfter string
		if err = admin.QueryRow(ctx, `SELECT status FROM public.sites WHERE id=$1`, siteAID).Scan(&expiredSiteStatusAfter); err != nil || expiredSiteStatusAfter != expiredSiteStatusBefore {
			t.Fatalf("expired domain changed site status from %q to %q err=%v", expiredSiteStatusBefore, expiredSiteStatusAfter, err)
		}
	})
	t.Run("site_status_machine_rejects_invalid_transitions", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE public.sites SET status='suspended' WHERE id=$1`, siteA.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE public.sites SET status='active' WHERE id=$1`, siteA.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE public.sites SET status='deleted' WHERE id=$1`, siteA.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE public.sites SET status='active' WHERE id=$1`, siteA.ID); err == nil {
			t.Fatal("deleted site transitioned back to active")
		}
	})
}
