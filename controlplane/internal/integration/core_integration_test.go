//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/example/wafplatform/controlplane/internal/auth"
	"github.com/example/wafplatform/controlplane/internal/entitlement"
	"github.com/example/wafplatform/controlplane/internal/platform/audit"
	"github.com/example/wafplatform/controlplane/internal/platform/db"
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

func apiRolePool(t *testing.T, ctx context.Context, admin *pgxpool.Pool, url string) *pgxpool.Pool {
	t.Helper()
	roleName := "waf_test_api_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'test-api-role-password'`, roleName)); err != nil {
		t.Fatalf("create api login: %v", err)
	}
	if _, err := admin.Exec(ctx, fmt.Sprintf(`GRANT waf_api TO %s`, roleName)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), fmt.Sprintf(`REVOKE waf_api FROM %s`, roleName))
		_, _ = admin.Exec(context.Background(), fmt.Sprintf(`DROP ROLE IF EXISTS %s`, roleName))
	})
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

func TestPostgresRLSAndAuthRedisIntegration(t *testing.T) {
	ctx, pool, rc := integrationDeps(t)
	appPool := apiRolePool(t, ctx, pool, os.Getenv("DATABASE_URL"))
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
		if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,tenant_id,name,owner_user_id,plan_id) VALUES($1,$1,'test',$2,$3)`, tenantID, ownerID, planID); err != nil {
			t.Fatal(err)
		}
		siteID, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `INSERT INTO sites(id,tenant_id,name,status) VALUES($1,$2,'private','active')`, siteID, tenantID); err != nil {
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
			Content struct {
				Body string `json:"Body"`
			} `json:"Content"`
		}
		var messages struct {
			Items []mail `json:"items"`
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			resp, e := http.Get(apiURL)
			if e == nil {
				_ = json.NewDecoder(resp.Body).Decode(&messages)
				_ = resp.Body.Close()
				if len(messages.Items) > 0 {
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if len(messages.Items) == 0 {
			t.Fatal("Mailhog did not receive verification email")
		}
		body := messages.Items[len(messages.Items)-1].Content.Body
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
	fixed := time.Unix(1_800_000_000, 0)
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
	currentCode, e := totp.GenerateCodeCustom(secret, fixed, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if e != nil {
		t.Fatal(e)
	}
	if !svc.EnableTOTP(ctx, userID, currentCode) {
		t.Fatal("TOTP could not be enabled")
	}
	missingEmail := "absent-" + uuid.NewString() + "@example.test"
	for i := 0; i < 11; i++ {
		_, loginErr := svc.Login(ctx, missingEmail, "bad", "integration", "127.0.0.1", "", "")
		if loginErr == nil {
			t.Fatal("unknown account login succeeded")
		}
	}
	first, err := svc.Login(ctx, email, "correct horse battery staple", "integration", "127.0.0.1", currentCode, "")
	if err != nil {
		t.Fatalf("valid login: %v", err)
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
