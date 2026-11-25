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
	"encoding/json"
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

type authMailDelivery struct {
	mailer            Mailer
	to, subject, body string
}

var authMailQueue = make(chan authMailDelivery, 256)

func init() {
	go func() {
		for job := range authMailQueue {
			_ = job.mailer.Send(context.Background(), job.to, job.subject, job.body)
		}
	}()
}

func enqueueAuthMail(m Mailer, to, subject, body string) bool {
	if m == nil {
		return true
	}
	select {
	case authMailQueue <- authMailDelivery{mailer: m, to: to, subject: subject, body: body}:
		return true
	default:
		return false
	}
}

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

func padAuthResponse(started time.Time) {
	if remaining := 100*time.Millisecond - time.Since(started); remaining > 0 {
		time.Sleep(remaining)
	}
}

func (s Service) Register(ctx context.Context, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	parsed, parseErr := mail.ParseAddress(email)
	if parseErr != nil || parsed.Address != email || len(password) < 10 {
		return ErrCredentials
	}
	started := time.Now()
	defer padAuthResponse(started)
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
	auditID, e := uuid.NewV7()
	if e != nil {
		return e
	}
	tokenHash := sha256.Sum256([]byte(token))
	_, err := s.Pool.Exec(ctx, `SELECT public.auth_register_user($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, userID, email, hash, tenantID, memberID, subID, tokenID, auditID, tokenHash[:], s.now().Add(24*time.Hour))
	if err != nil {
		return err
	}
	if !enqueueAuthMail(s.Mailer, email, "Verify your email", "Verification token: "+token) {
		return fmt.Errorf("authentication mail queue full")
	}
	return nil
}

func (s Service) VerifyEmail(ctx context.Context, token string) error {
	h := sha256.Sum256([]byte(token))
	var consumed bool
	if err := s.Pool.QueryRow(ctx, `SELECT public.auth_consume_email_verification($1)`, h[:]).Scan(&consumed); err != nil {
		return err
	}
	if !consumed {
		return ErrToken
	}
	return nil
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
	var stored, status string
	var encrypted []byte
	var totpEnabled *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT user_id,password_hash,status,default_tenant_id,totp_secret_enc,totp_enabled_at FROM public.auth_login_material($1)`, email).Scan(&userID, &stored, &status, &tenantID, &encrypted, &totpEnabled)
	if err != nil {
		_ = verifyPassword(dummyPasswordHash, password)
		return Tokens{}, ErrCredentials
	}
	passwordValid := verifyPassword(stored, password)
	if status != "active" || !passwordValid {
		return Tokens{}, ErrCredentials
	}
	var role string
	err = db.WithTenantTx(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&role)
	})
	if err != nil {
		return Tokens{}, ErrCredentials
	}
	if totpEnabled != nil {
		valid := totpCode != "" && s.consumeTOTPCode(ctx, userID, encrypted, totpCode)
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
	_, err = s.Pool.Exec(ctx, `SELECT public.auth_create_refresh($1,$2,$3,$4,$5,$6,$7)`, id, userID, family, hash[:], ua, parsedIP, s.now().Add(30*24*time.Hour))
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
	newToken, err := randomToken(48)
	if err != nil {
		return Tokens{}, err
	}
	newID, err := uuid.NewV7()
	if err != nil {
		return Tokens{}, err
	}
	newHash := sha256.Sum256([]byte(newToken))
	var outcome, role string
	var userID, tenantID uuid.UUID
	err = s.Pool.QueryRow(ctx, `SELECT outcome,user_id,tenant_id,role FROM public.auth_rotate_refresh($1,$2,$3,$4)`, oldHash[:], newID, newHash[:], s.now().Add(30*24*time.Hour)).Scan(&outcome, &userID, &tenantID, &role)
	if err != nil {
		return Tokens{}, err
	}
	if outcome != "ok" {
		return Tokens{}, ErrToken
	}
	access, err := s.issueAccess(userID, tenantID, role)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, RefreshToken: newToken, ExpiresIn: 900, UserID: userID, TenantID: tenantID, Role: role}, nil
}

func (s Service) Logout(ctx context.Context, token string) error {
	h := sha256.Sum256([]byte(token))
	_, err := s.Pool.Exec(ctx, `SELECT public.auth_logout_refresh($1)`, h[:])
	return err
}
func (s Service) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	return db.WithUserTx(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=pg_catalog.now(),updated_at=pg_catalog.now() WHERE id=$1 AND revoked_at IS NULL`, sessionID)
		return err
	})
}
func (s Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	out := []Session{}
	err := db.WithUserTx(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,user_agent,coalesce(ip::text,''),expires_at,revoked_at,created_at FROM refresh_tokens ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item Session
			if err = rows.Scan(&item.ID, &item.UserAgent, &item.IP, &item.ExpiresAt, &item.RevokedAt, &item.CreatedAt); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

func (s Service) RequestPasswordReset(ctx context.Context, email string) error {
	started := time.Now()
	// Do the same password-hash work for present and absent accounts; the endpoint also
	// returns one generic response and mail delivery is detached from request latency.
	_ = verifyPassword(dummyPasswordHash, "password-reset-timing-pad")
	token, e := randomToken(32)
	if e != nil {
		return e
	}
	id, e := uuid.NewV7()
	if e != nil {
		return e
	}
	h := sha256.Sum256([]byte(token))
	_, e = s.Pool.Exec(ctx, `SELECT public.auth_password_reset_request($1,$2,$3,$4)`, strings.TrimSpace(email), id, h[:], s.now().Add(time.Hour))
	if e != nil {
		return e
	}
	// The same message goes to the supplied address whether or not an account exists.
	_ = enqueueAuthMail(s.Mailer, strings.TrimSpace(email), "Reset your password", "If an account exists, use this reset token: "+token)
	padAuthResponse(started)
	return nil
}
func (s Service) ResetPassword(ctx context.Context, token, password string) error {
	if len(password) < 10 {
		return ErrCredentials
	}
	h := sha256.Sum256([]byte(token))
	var consumed bool
	if e := s.Pool.QueryRow(ctx, `SELECT public.auth_complete_password_reset($1,$2)`, h[:], hashPassword(password)).Scan(&consumed); e != nil {
		return e
	}
	if !consumed {
		return ErrToken
	}
	return nil
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
	codeRows := make([]struct {
		ID   uuid.UUID `json:"id"`
		Hash []byte    `json:"hash"`
	}, len(ids))
	for i := range ids {
		codeRows[i] = struct {
			ID   uuid.UUID `json:"id"`
			Hash []byte    `json:"hash"`
		}{ID: ids[i], Hash: hashes[i][:]}
	}
	codeJSON, err := json.Marshal(codeRows)
	if err != nil {
		return "", recovery, err
	}
	err = db.WithUserTx(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		var configured bool
		if e := tx.QueryRow(ctx, `SELECT public.auth_configure_totp($1,$2,$3::jsonb)`, userID, enc, string(codeJSON)).Scan(&configured); e != nil {
			return e
		}
		if !configured {
			return ErrToken
		}
		return nil
	})
	if err != nil {
		return "", recovery, err
	}
	return plain, recovery, nil
}
func (s Service) EnableTOTP(ctx context.Context, userID uuid.UUID, code string) bool {
	if !s.VerifyTOTP(ctx, userID, code) {
		return false
	}
	var enabled bool
	err := db.WithUserTx(ctx, s.Pool, userID, func(tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT public.auth_enable_totp()`).Scan(&enabled) })
	return err == nil && enabled
}
func (s Service) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) bool {
	var enc []byte
	err := db.WithUserTx(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT secret FROM public.auth_totp_secret()`).Scan(&enc)
	})
	return err == nil && s.consumeTOTPCode(ctx, userID, enc, code)
}
func (s Service) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, code string) bool {
	h := sha256.Sum256([]byte(strings.ToUpper(code)))
	var consumed bool
	e := db.WithUserTx(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT public.auth_consume_recovery_code($1)`, h[:]).Scan(&consumed)
	})
	return e == nil && consumed
}

func (s Service) consumeTOTPCode(ctx context.Context, userID uuid.UUID, encrypted []byte, code string) bool {
	secret, err := s.decryptTOTP(encrypted)
	if err != nil || code == "" {
		return false
	}
	step, ok := matchingTOTPStep(string(secret), code, s.now())
	if !ok {
		return false
	}
	var consumed bool
	err = db.WithUserTx(ctx, s.Pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT public.auth_consume_totp_step($1)`, step).Scan(&consumed)
	})
	return err == nil && consumed
}

func matchingTOTPStep(secret, code string, now time.Time) (int64, bool) {
	current := now.Unix() / 30
	matched := int64(-1)
	for _, candidate := range []int64{current, current - 1, current + 1} {
		if candidate < 0 {
			continue
		}
		generated, err := totp.GenerateCodeCustom(secret, time.Unix(candidate*30, 0), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && subtle.ConstantTimeCompare([]byte(generated), []byte(code)) == 1 && matched < 0 {
			matched = candidate
		}
	}
	return matched, matched >= 0
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

var dummyPasswordHash = func() string {
	salt := make([]byte, 16)
	sum := argon2.IDKey([]byte("never-a-real-password"), salt, 2, 19*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
}()

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
