package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/example/wafplatform/controlplane/internal/analytics"
	"github.com/example/wafplatform/controlplane/internal/auth"
	"github.com/example/wafplatform/controlplane/internal/entitlement"
	"github.com/example/wafplatform/controlplane/internal/platform/config"
	"github.com/example/wafplatform/controlplane/internal/platform/db"
	"github.com/example/wafplatform/controlplane/internal/platform/logger"
	"github.com/example/wafplatform/controlplane/internal/platform/middleware"
	"github.com/example/wafplatform/controlplane/internal/platform/problem"
	"github.com/example/wafplatform/controlplane/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	cfg          config.Config
	pool         *db.Pool
	redis        *redis.Client
	auth         auth.Service
	log          *slog.Logger
	private      ed25519.PrivateKey
	tenant       tenant.Service
	entitlements entitlement.Service
	analytics    analytics.AnalyticsService
}

func New(cfg config.Config, pool *db.Pool, rc *redis.Client, log *slog.Logger) (*Server, error) {
	privateRaw, err := base64.RawStdEncoding.DecodeString(cfg.JWTPrivateKey)
	if err != nil {
		return nil, errors.New("JWT_ED25519_PRIVATE_KEY must be base64 encoded")
	}
	if len(privateRaw) == ed25519.SeedSize {
		privateRaw = ed25519.NewKeyFromSeed(privateRaw)
	}
	if len(privateRaw) != ed25519.PrivateKeySize {
		return nil, errors.New("JWT_ED25519_PRIVATE_KEY must contain an Ed25519 private key")
	}
	totpKey, err := base64.RawStdEncoding.DecodeString(cfg.TOTPKey)
	if err != nil || len(totpKey) < 32 {
		return nil, errors.New("TOTP_ENCRYPTION_KEY must be base64 encoded and contain at least 32 bytes")
	}
	s := &Server{cfg: cfg, pool: pool, redis: rc, log: log, private: ed25519.PrivateKey(privateRaw), auth: auth.Service{Pool: pool.Pool, Redis: rc, Mailer: auth.SMTPMailer{Addr: cfg.SMTPAddr, From: cfg.SMTPFrom}, JWTPrivate: ed25519.PrivateKey(privateRaw), JWTKeyID: "cp-1", TOTPEncryptionKey: totpKey}, tenant: tenant.Service{Pool: pool.Pool}, entitlements: entitlement.Service{Pool: pool.Pool}, analytics: analytics.AnalyticsService{Pool: pool.Pool, Cache: rc, ClickHouse: analytics.ClickHouseHTTP{Endpoint: apiEnv("CLICKHOUSE_URL", "http://127.0.0.1:8123"), Database: apiEnv("CLICKHOUSE_DATABASE", "waf"), Username: os.Getenv("CLICKHOUSE_USER"), Password: os.Getenv("CLICKHOUSE_PASSWORD")}}}
	return s, nil
}
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(func(next http.Handler) http.Handler { return middleware.Recover(s.log, next) })
	r.Use(func(next http.Handler) http.Handler { return middleware.AccessLog(s.log, next) })
	r.Use(func(next http.Handler) http.Handler { return middleware.CORS(s.cfg.AllowedOrigins, next) })
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.pool.Ping(r.Context()); err != nil {
			problem.Write(w, r, http.StatusServiceUnavailable, "not_ready", "Not ready", "A required service is unavailable")
			return
		}
		if err := s.redis.Ping(r.Context()).Err(); err != nil {
			problem.Write(w, r, http.StatusServiceUnavailable, "not_ready", "Not ready", "A required service is unavailable")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	r.Route("/v1", func(v chi.Router) {
		v.Use(func(next http.Handler) http.Handler {
			return middleware.RedisRateLimit(s.redis, 120, time.Minute, next)
		})
		v.Use(middleware.CSRF)
		v.Post("/auth/register", s.register)
		v.Post("/auth/verify-email", s.verifyEmail)
		v.Post("/auth/login", s.login)
		v.Post("/auth/refresh", s.refresh)
		v.Post("/auth/logout", s.logout)
		v.Post("/auth/password-reset", s.resetRequest)
		v.Post("/auth/password-reset/confirm", s.resetConfirm)
		v.With(s.requireAuth).Get("/auth/sessions", s.sessions)
		v.With(s.requireAuth).Delete("/auth/sessions/{session_id}", s.revokeSession)
		v.With(s.requireAuth).Post("/auth/totp/setup", s.totpSetup)
		v.With(s.requireAuth).Post("/auth/totp/enable", s.totpEnable)
		v.With(s.requireAuth).Post("/tenants/{tenant_id}/invitations", s.invite)
		v.With(s.requireAuth).Post("/invitations/accept", s.acceptInvite)
		v.With(s.requireAuth).Get("/tenants/{tenant_id}/members", s.listMembers)
		v.With(s.requireAuth).Delete("/tenants/{tenant_id}/members/{user_id}", s.removeMember)
		v.With(s.requireAuth).Post("/tenants/{tenant_id}/api-keys", s.createAPIKey)
		v.With(s.requireAuth).Get("/tenants/{tenant_id}/api-keys", s.listAPIKeys)
		v.With(s.requireAuth).Delete("/tenants/{tenant_id}/api-keys/{key_id}", s.revokeAPIKey)
		v.With(s.requireAuth).Get("/tenants/{tenant_id}/entitlements", s.getEntitlements)
		v.With(s.requireAuth).Post("/tenants/{tenant_id}/sites", s.createSite)
		v.With(s.requireAuth).Post("/tenants/{tenant_id}/sites/{site_id}/domains", s.addDomain)
		v.With(s.requireAuth).Post("/tenants/{tenant_id}/sites/{site_id}/origins", s.addOrigin)
		v.With(s.requireAuth).Get("/sites/{site_id}/analytics/{view:overview|timeseries|top}", s.siteAnalytics)
	})
	return r
}

type credentials = Credentials

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "Request body is invalid")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		problem.Write(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "Request body must contain one JSON value")
		return false
	}
	return true
}
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !decode(w, r, &in) {
		return
	}
	if err := s.auth.Register(r.Context(), string(in.Email), in.Password); err != nil {
		s.log.Warn("registration rejected", "request_id", logger.RequestID(r.Context()))
		problem.Write(w, r, http.StatusAccepted, "registration_pending", "Registration submitted", "If the address can be registered, verification instructions will be sent")
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending_verification"})
}
func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.auth.VerifyEmail(r.Context(), in.Token); err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_token", "Invalid token", "The verification token is invalid or expired")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !decode(w, r, &in) {
		return
	}
	totpCode, recoveryCode := "", ""
	if in.TotpCode != nil {
		totpCode = *in.TotpCode
	}
	if in.RecoveryCode != nil {
		recoveryCode = *in.RecoveryCode
	}
	tokens, err := s.auth.Login(r.Context(), string(in.Email), in.Password, r.UserAgent(), clientIP(r), totpCode, recoveryCode)
	if err != nil {
		problem.Write(w, r, http.StatusUnauthorized, "invalid_credentials", "Sign in failed", "Email or password is invalid")
		return
	}
	csrfToken := s.setSessionCookies(w, tokens.RefreshToken)
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tokens.AccessToken, "token_type": "Bearer", "expires_in": tokens.ExpiresIn, "tenant_id": tokens.TenantID, "role": tokens.Role, "csrf_token": csrfToken})
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		problem.Write(w, r, http.StatusUnauthorized, "invalid_session", "Session expired", "Sign in again")
		return
	}
	tokens, err := s.auth.Refresh(r.Context(), c.Value)
	if err != nil {
		s.clearCookies(w)
		problem.Write(w, r, http.StatusUnauthorized, "invalid_session", "Session expired", "Sign in again")
		return
	}
	csrfToken := s.setSessionCookies(w, tokens.RefreshToken)
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tokens.AccessToken, "token_type": "Bearer", "expires_in": tokens.ExpiresIn, "tenant_id": tokens.TenantID, "role": tokens.Role, "csrf_token": csrfToken})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("refresh_token"); e == nil {
		_ = s.auth.Logout(r.Context(), c.Value)
	}
	s.clearCookies(w)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) resetRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return
	}
	_ = s.auth.RequestPasswordReset(r.Context(), in.Email)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "if_account_exists_instructions_sent"})
}
func (s *Server) resetConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.auth.ResetPassword(r.Context(), in.Token, in.Password); err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_reset", "Reset rejected", "The reset token is invalid or expired")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) setSessionCookies(w http.ResponseWriter, refresh string) string {
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: refresh, Path: "/v1/auth", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 60 * 60})
	var b [32]byte
	_, _ = rand.Read(b[:])
	token := base64.RawURLEncoding.EncodeToString(b[:])
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 60 * 60})
	return token
}
func (s *Server) clearCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Path: "/v1/auth", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type principal struct {
	userID, tenantID uuid.UUID
	role             string
}
type principalKey struct{}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if raw == "" {
			problem.Write(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", "A valid access token is required")
			return
		}
		token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodEdDSA {
				return nil, errors.New("unexpected signing algorithm")
			}
			return s.private.Public().(ed25519.PublicKey), nil
		})
		if err != nil || !token.Valid {
			problem.Write(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", "A valid access token is required")
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			problem.Write(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", "A valid access token is required")
			return
		}
		userID, e1 := uuid.Parse(fmt.Sprint(claims["sub"]))
		tenantID, e2 := uuid.Parse(fmt.Sprint(claims["tenant_id"]))
		role, _ := claims["role"].(string)
		if e1 != nil || e2 != nil || role == "" {
			problem.Write(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", "A valid access token is required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal{userID: userID, tenantID: tenantID, role: role})))
	})
}
func getPrincipal(r *http.Request) principal {
	p, _ := r.Context().Value(principalKey{}).(principal)
	return p
}
func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := getPrincipal(r)
	items, err := s.auth.ListSessions(r.Context(), p.userID)
	if err != nil {
		problem.Write(w, r, http.StatusInternalServerError, "internal_error", "Unable to load sessions", "Try again later")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": items})
}
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	id, err := uuid.Parse(chi.URLParam(r, "session_id"))
	if err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_session", "Invalid session", "Session identifier is invalid")
		return
	}
	if err = s.auth.RevokeSession(r.Context(), p.userID, id); err != nil {
		problem.Write(w, r, http.StatusInternalServerError, "internal_error", "Unable to revoke session", "Try again later")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := getPrincipal(r)
	secret, codes, err := s.auth.CreateTOTP(r.Context(), p.userID)
	if err != nil {
		problem.Write(w, r, http.StatusInternalServerError, "totp_setup_failed", "Unable to set up 2FA", "Try again later")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"secret": secret, "recovery_codes": codes})
}
func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.auth.EnableTOTP(r.Context(), p.userID, in.Code) {
		problem.Write(w, r, http.StatusBadRequest, "invalid_code", "Invalid code", "The authenticator code was not accepted")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) invite(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tid, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_tenant", "Invalid tenant", "Tenant identifier is invalid")
		return
	}
	var in struct {
		Email string      `json:"email"`
		Role  tenant.Role `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	token, err := s.tenant.Invite(r.Context(), tid, p.userID, in.Email, in.Role)
	if err != nil {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Request denied", "You cannot invite a member to this organization")
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"invitation_token": token})
}
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tid, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_tenant", "Invalid tenant", "Tenant identifier is invalid")
		return
	}
	var in struct {
		Name      string     `json:"name"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !decode(w, r, &in) {
		return
	}
	key, err := s.tenant.CreateAPIKey(r.Context(), tid, p.userID, in.Name, in.Scopes, in.ExpiresAt)
	if err != nil {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Request denied", "You cannot create this API key")
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": key.ID.String(), "key": key.Plaintext})
}
func (s *Server) getEntitlements(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tid, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_tenant", "Invalid tenant", "Tenant identifier is invalid")
		return
	}
	ok, err := s.tenant.Can(r.Context(), p.userID, tenant.ViewSites, tenant.Resource{TenantID: tid.String(), Kind: "entitlement"})
	if err != nil || !ok {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Request denied", "You cannot access this organization")
		return
	}
	plan, err := s.entitlements.Get(r.Context(), tid)
	if err != nil {
		problem.Write(w, r, http.StatusNotFound, "plan_not_found", "Plan unavailable", "No active subscription is available")
		return
	}
	_ = json.NewEncoder(w).Encode(plan)
}
func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.tenant.AcceptInvite(r.Context(), p.userID, in.Token); err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_invitation", "Invitation rejected", "The invitation is invalid, expired, or addressed to another email")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tid, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_tenant", "Invalid tenant", "Tenant identifier is invalid")
		return
	}
	items, err := s.tenant.ListMembers(r.Context(), tid, p.userID)
	if err != nil {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Request denied", "You cannot list this organization’s members")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"members": items})
}
func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tid, e1 := uuid.Parse(chi.URLParam(r, "tenant_id"))
	uid, e2 := uuid.Parse(chi.URLParam(r, "user_id"))
	if e1 != nil || e2 != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_resource", "Invalid resource", "Identifier is invalid")
		return
	}
	if err := s.tenant.RemoveMember(r.Context(), tid, p.userID, uid); err != nil {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Request denied", "You cannot remove this member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tid, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_tenant", "Invalid tenant", "Tenant identifier is invalid")
		return
	}
	items, err := s.tenant.ListAPIKeys(r.Context(), tid, p.userID)
	if err != nil {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Request denied", "You cannot list API keys for this organization")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": items})
}
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tid, e1 := uuid.Parse(chi.URLParam(r, "tenant_id"))
	id, e2 := uuid.Parse(chi.URLParam(r, "key_id"))
	if e1 != nil || e2 != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_resource", "Invalid resource", "Identifier is invalid")
		return
	}
	if err := s.tenant.RevokeAPIKey(r.Context(), tid, p.userID, id); err != nil {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Request denied", "You cannot revoke this API key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
