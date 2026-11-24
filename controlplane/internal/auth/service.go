package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/example/wafplatform/controlplane/internal/platform/db"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"
)

var ErrCredentials = errors.New("invalid credentials")
var ErrToken = errors.New("invalid token")
var ErrLocked = errors.New("account temporarily locked")

type Mailer interface {
	Send(context.Context, string, string, string) error
}
type SMTPMailer struct{ Addr, From string }

func (m SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parsed, err := mail.ParseAddress(to)
	if err != nil || parsed.Address != to || strings.ContainsAny(to, "\r\n") {
		return fmt.Errorf("invalid recipient address")
	}
	msg := []byte("From: " + m.From + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body)
	return smtp.SendMail(m.Addr, nil, m.From, []string{to}, msg)
}

type Service struct {
	Pool              *pgxpool.Pool
	Redis             redis.UniversalClient
	Mailer            Mailer
	JWTPrivate        ed25519.PrivateKey
	JWTKeyID          string
	TOTPEncryptionKey []byte
	Clock             func() time.Time
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	UserID       uuid.UUID
	TenantID     uuid.UUID
	Role         string
}

type Session struct {
	ID        uuid.UUID  `json:"id"`
	UserAgent string     `json:"user_agent"`
	IP        string     `json:"ip"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (s Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}
func (s Service) Register(ctx context.Context, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	parsed, parseErr := mail.ParseAddress(email)
	if parseErr != nil || parsed.Address != email || len(password) < 10 {
		return ErrCredentials
	}
	hash := hashPassword(password)
	userID, e := uuid.NewV7()
	if e != nil {
		return e
	}
	tenantID, e := uuid.NewV7()
	if e != nil {
		return e
	}
	memberID, e := uuid.NewV7()
	if e != nil {
		return e
	}
	subID, e := uuid.NewV7()
	if e != nil {
		return e
	}
	token, e := randomToken(32)
	if e != nil {
		return e
	}
	tokenID, e := uuid.NewV7()
	if e != nil {
		return e
	}
	tokenHash := sha256.Sum256([]byte(token))
	var planID uuid.UUID
	err := db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO users(id,email,password_hash,status) VALUES($1,$2,$3,'pending')`, userID, email, hash); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT id FROM plans WHERE code='free'`).Scan(&planID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO organizations(id,tenant_id,name,owner_user_id,plan_id) VALUES($1,$1,$2,$3,$4)`, tenantID, "Personal", userID, planID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET default_tenant_id=$1,updated_at=now() WHERE id=$2`, tenantID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(id,tenant_id,user_id,role) VALUES($1,$2,$3,'owner')`, memberID, tenantID, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO subscriptions(id,tenant_id,plan_id,status,provider) VALUES($1,$2,$3,'active','free')`, subID, tenantID, planID); err != nil {
			return err
		}
		auditID, auditErr := uuid.NewV7()
		if auditErr != nil {
			return auditErr
		}
		if _, auditErr = tx.Exec(ctx, `INSERT INTO audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff) VALUES($1,$2,'user',$3,'organization.create','organization',$2,'{}'::jsonb)`, auditID, tenantID, userID); auditErr != nil {
			return auditErr
		}
		_, err := tx.Exec(ctx, `INSERT INTO email_verification_tokens(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, tokenID, userID, tokenHash[:], s.now().Add(24*time.Hour))
		return err
	})
	if err != nil {
		return err
	}
	if s.Mailer != nil {
		if err := s.Mailer.Send(ctx, email, "Verify your email", "Verification token: "+token); err != nil {
			return fmt.Errorf("send verification email: %w", err)
		}
	}
	return nil
}

func (s Service) VerifyEmail(ctx context.Context, token string) error {
	h := sha256.Sum256([]byte(token))
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id, userID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id,user_id FROM email_verification_tokens WHERE token_hash=$1 AND expires_at>now() AND used_at IS NULL FOR UPDATE`, h[:]).Scan(&id, &userID); err != nil {
		return ErrToken
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET email_verified_at=now(),status='active',updated_at=now() WHERE id=$1`, userID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE email_verification_tokens SET used_at=now(),updated_at=now() WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s Service) Login(ctx context.Context, email, password, ua, ip, totpCode, recoveryCode string) (Tokens, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	keyHash := sha256.Sum256([]byte(email))
	lockKey := "cp:auth:lock:" + hex.EncodeToString(keyHash[:])
	if s.Redis != nil {
		v, err := s.Redis.Eval(ctx, `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return n`, []string{lockKey}, (15 * time.Minute).Milliseconds()).Int64()
		if err != nil {
			return Tokens{}, ErrLocked
		}
		if v > 10 {
			return Tokens{}, ErrCredentials
		}
	}
	var userID, tenantID uuid.UUID
	var stored, role, status string
	err := s.Pool.QueryRow(ctx, `SELECT id,password_hash,status,default_tenant_id FROM users WHERE lower(email)=lower($1)`, email).Scan(&userID, &stored, &status, &tenantID)
	if err != nil || status != "active" || !verifyPassword(stored, password) {
		return Tokens{}, ErrCredentials
	}
	err = db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&role)
	})
	if err != nil {
		return Tokens{}, ErrCredentials
	}
	var encrypted []byte
	var totpEnabled *time.Time
	if err = s.Pool.QueryRow(ctx, `SELECT totp_secret_enc,totp_enabled_at FROM users WHERE id=$1`, userID).Scan(&encrypted, &totpEnabled); err != nil {
		return Tokens{}, ErrCredentials
	}
	if totpEnabled != nil {
		secret, e := s.decryptTOTP(encrypted)
		valid := false
		if e == nil && totpCode != "" {
			valid, _ = totp.ValidateCustom(totpCode, string(secret), s.now(), totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		}
		if !valid && recoveryCode != "" {
			valid = s.ConsumeRecoveryCode(ctx, userID, recoveryCode)
		}
		if !valid {
			return Tokens{}, ErrCredentials
		}
	}
	if s.Redis != nil {
		_ = s.Redis.Del(ctx, lockKey).Err()
	}
	family, err := uuid.NewV7()
	if err != nil {
		return Tokens{}, err
	}
	refresh, err := randomToken(48)
	if err != nil {
		return Tokens{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Tokens{}, err
	}
	hash := sha256.Sum256([]byte(refresh))
	var parsedIP any
	if ip != "" {
		parsedIP = ip
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO refresh_tokens(id,user_id,family_id,token_hash,user_agent,ip,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, userID, family, hash[:], ua, parsedIP, s.now().Add(30*24*time.Hour))
	if err != nil {
		return Tokens{}, err
	}
	access, err := s.issueAccess(userID, tenantID, role)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, RefreshToken: refresh, ExpiresIn: 900, UserID: userID, TenantID: tenantID, Role: role}, nil
}

func (s Service) Refresh(ctx context.Context, old string) (Tokens, error) {
	oldHash := sha256.Sum256([]byte(old))
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Tokens{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id, userID, family, tenantID uuid.UUID
	var role string
	var revoked *time.Time
	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT default_tenant_id FROM users WHERE id=(SELECT user_id FROM refresh_tokens WHERE token_hash=$1)`, oldHash[:]).Scan(&tenantID)
	if err != nil {
		return Tokens{}, ErrToken
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantID.String()); err != nil {
		return Tokens{}, err
	}
	err = tx.QueryRow(ctx, `SELECT rt.id,rt.user_id,rt.family_id,rt.revoked_at,rt.expires_at,m.tenant_id,m.role FROM refresh_tokens rt JOIN memberships m ON m.user_id=rt.user_id AND m.tenant_id=$2 WHERE rt.token_hash=$1 FOR UPDATE OF rt`, oldHash[:], tenantID).Scan(&id, &userID, &family, &revoked, &expires, &tenantID, &role)
	if err != nil {
		return Tokens{}, ErrToken
	}
	if revoked != nil {
		_, _ = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now(),updated_at=now() WHERE family_id=$1 AND revoked_at IS NULL`, family)
		_ = tx.Commit(ctx)
		return Tokens{}, ErrToken
	}
	if !expires.After(s.now()) {
		return Tokens{}, ErrToken
	}
	if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now(),updated_at=now() WHERE id=$1`, id); err != nil {
		return Tokens{}, err
	}
	newToken, err := randomToken(48)
	if err != nil {
		return Tokens{}, err
	}
	newID, err := uuid.NewV7()
	if err != nil {
		return Tokens{}, err
	}
	newHash := sha256.Sum256([]byte(newToken))
	if _, err = tx.Exec(ctx, `INSERT INTO refresh_tokens(id,user_id,family_id,token_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, newID, userID, family, newHash[:], s.now().Add(30*24*time.Hour)); err != nil {
		return Tokens{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Tokens{}, err
	}
	access, err := s.issueAccess(userID, tenantID, role)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, RefreshToken: newToken, ExpiresIn: 900, UserID: userID, TenantID: tenantID, Role: role}, nil
}

func (s Service) Logout(ctx context.Context, token string) error {
	h := sha256.Sum256([]byte(token))
	_, err := s.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now(),updated_at=now() WHERE token_hash=$1 AND revoked_at IS NULL`, h[:])
	return err
}
func (s Service) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now(),updated_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, sessionID, userID)
	return err
}
func (s Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,user_agent,coalesce(ip::text,''),expires_at,revoked_at,created_at FROM refresh_tokens WHERE user_id=$1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var item Session
		if err = rows.Scan(&item.ID, &item.UserAgent, &item.IP, &item.ExpiresAt, &item.RevokedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s Service) RequestPasswordReset(ctx context.Context, email string) error {
	var uid uuid.UUID
	var storedEmail string
	err := s.Pool.QueryRow(ctx, `SELECT id,email FROM users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).Scan(&uid, &storedEmail)
	if err != nil {
		return nil
	}
	token, e := randomToken(32)
	if e != nil {
		return e
	}
	id, e := uuid.NewV7()
	if e != nil {
		return e
	}
	h := sha256.Sum256([]byte(token))
	if _, e = s.Pool.Exec(ctx, `INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, id, uid, h[:], s.now().Add(time.Hour)); e != nil {
		return e
	}
	if s.Mailer != nil {
		_ = s.Mailer.Send(ctx, storedEmail, "Reset your password", "Password reset token: "+token)
	}
	return nil
}
func (s Service) ResetPassword(ctx context.Context, token, password string) error {
	if len(password) < 10 {
		return ErrCredentials
	}
	h := sha256.Sum256([]byte(token))
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var uid uuid.UUID
	var id uuid.UUID
	e = tx.QueryRow(ctx, `SELECT id,user_id FROM password_reset_tokens WHERE token_hash=$1 AND expires_at>now() AND used_at IS NULL FOR UPDATE`, h[:]).Scan(&id, &uid)
	if e != nil {
		return ErrToken
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET password_hash=$1,updated_at=now() WHERE id=$2`, hashPassword(password), uid); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE password_reset_tokens SET used_at=now(),updated_at=now() WHERE id=$1`, id); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now(),updated_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, uid); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s Service) CreateTOTP(ctx context.Context, userID uuid.UUID) (string, [10]string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", [10]string{}, err
	}
	plain := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	enc, err := s.encryptTOTP([]byte(plain))
	if err != nil {
		return "", [10]string{}, err
	}
	var recovery [10]string
	hashes := make([][32]byte, len(recovery))
	ids := make([]uuid.UUID, len(recovery))
	for i := range recovery {
		v, e := generateRecoveryCode()
		if e != nil {
			return "", recovery, e
		}
		recovery[i] = v
		hashes[i] = sha256.Sum256([]byte(v))
		ids[i], e = uuid.NewV7()
		if e != nil {
			return "", recovery, e
		}
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", recovery, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `UPDATE users SET totp_secret_enc=$1,totp_enabled_at=NULL,updated_at=now() WHERE id=$2`, enc, userID); err != nil {
		return "", recovery, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM totp_recovery_codes WHERE user_id=$1`, userID); err != nil {
		return "", recovery, err
	}
	for i := range ids {
		if _, err = tx.Exec(ctx, `INSERT INTO totp_recovery_codes(id,user_id,code_hash) VALUES($1,$2,$3)`, ids[i], userID, hashes[i][:]); err != nil {
			return "", recovery, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return "", recovery, err
	}
	return plain, recovery, nil
}
func (s Service) EnableTOTP(ctx context.Context, userID uuid.UUID, code string) bool {
	if !s.VerifyTOTP(ctx, userID, code) {
		return false
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE users SET totp_enabled_at=now(),updated_at=now() WHERE id=$1 AND totp_secret_enc IS NOT NULL`, userID)
	return err == nil && tag.RowsAffected() == 1
}
func (s Service) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) bool {
	var enc []byte
	if err := s.Pool.QueryRow(ctx, `SELECT totp_secret_enc FROM users WHERE id=$1`, userID).Scan(&enc); err != nil {
		return false
	}
	secret, err := s.decryptTOTP(enc)
	if err != nil {
		return false
	}
	valid, _ := totp.ValidateCustom(code, string(secret), s.now(), totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	return valid
}
func (s Service) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, code string) bool {
	h := sha256.Sum256([]byte(strings.ToUpper(code)))
	tag, e := s.Pool.Exec(ctx, `UPDATE totp_recovery_codes SET used_at=now(),updated_at=now() WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL`, userID, h[:])
	return e == nil && tag.RowsAffected() == 1
}

func (s Service) issueAccess(user, tenant uuid.UUID, role string) (string, error) {
	if len(s.JWTPrivate) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("Ed25519 signing key is not configured")
	}
	now := s.now()
	claims := jwt.MapClaims{"sub": user.String(), "tenant_id": tenant.String(), "role": role, "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix()}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if s.JWTKeyID != "" {
		t.Header["kid"] = s.JWTKeyID
	}
	return t.SignedString(s.JWTPrivate)
}
func hashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	sum := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
}
func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var saltB, sumB string
	var m, t, p int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m < 8192 || m > 262144 || t < 1 || t > 10 || p < 1 || p > 8 {
		return false
	}
	saltB, sumB = parts[4], parts[5]
	salt, e := base64.RawStdEncoding.DecodeString(saltB)
	if e != nil {
		return false
	}
	expected, e := base64.RawStdEncoding.DecodeString(sumB)
	if e != nil || len(expected) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(t), uint32(m), uint8(p), 32)
	return subtle.ConstantTimeCompare(got, expected) == 1
}
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func generateRecoveryCode() (string, error) {
	token, err := randomToken(9)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(token), nil
}
func (s Service) encryptTOTP(plain []byte) ([]byte, error) {
	if len(s.TOTPEncryptionKey) < 32 {
		return nil, fmt.Errorf("TOTP encryption key must be at least 32 bytes")
	}
	key := sha256.Sum256(s.TOTPEncryptionKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plain, nil)...), nil
}
func (s Service) decryptTOTP(enc []byte) ([]byte, error) {
	if len(s.TOTPEncryptionKey) < 32 {
		return nil, ErrToken
	}
	key := sha256.Sum256(s.TOTPEncryptionKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(enc) < aead.NonceSize() {
		return nil, ErrToken
	}
	plain, err := aead.Open(nil, enc[:aead.NonceSize()], enc[aead.NonceSize():], nil)
	if err != nil {
		return nil, ErrToken
	}
	return plain, nil
}
