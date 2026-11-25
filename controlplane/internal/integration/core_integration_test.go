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
	"encoding/json"
	"fmt"
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
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"))
	mail := &captureMailer{messages: make(chan capturedMail, 16)}
	svc := newAuthService(t, app, rc, mail)
	emailA, emailB := "security-a-"+uuid.NewString()+"@example.test", "security-b-"+uuid.NewString()+"@example.test"
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
		members, e := tenantService.ListMembers(ctx, sessionA.TenantID, userA)
		if e != nil {
			t.Fatal(e)
		}
		if len(members) != 2 {
			t.Fatalf("narrow member directory returned %d rows, want 2", len(members))
		}
	})
}

func TestPublicTableRLSAllowlist(t *testing.T) {
	ctx, pool, _ := integrationDeps(t)
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
}

func TestAuthFlowsAndConcurrentRefreshRotation(t *testing.T) {
	ctx, admin, rc := integrationDeps(t)
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"))
	mail := &captureMailer{messages: make(chan capturedMail, 16)}
	svc := newAuthService(t, app, rc, mail)
	email := "flow-" + uuid.NewString() + "@example.test"
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
		missingErr := func() error {
			_, e := svc.Login(ctx, "absent-"+uuid.NewString()+"@example.test", "wrong password", "", "", "", "")
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
