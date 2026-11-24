package middleware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/example/wafplatform/controlplane/internal/platform/logger"
	"github.com/example/wafplatform/controlplane/internal/platform/problem"
	"github.com/redis/go-redis/v9"
)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b [16]byte
		_, _ = rand.Read(b[:])
		id := hex.EncodeToString(b[:])
		trace := ""
		parts := strings.Split(r.Header.Get("traceparent"), "-")
		if len(parts) == 4 && len(parts[1]) == 32 {
			trace = parts[1]
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(logger.WithRequestIDs(r.Context(), id, trace)))
	})
}
func Recover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Error("handler panic", "request_id", logger.RequestID(r.Context()), "panic_type", fmt.Sprintf("%T", v))
				problem.Write(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func CORS(origins []string, next http.Handler) http.Handler {
	allowed := map[string]struct{}{}
	for _, o := range origins {
		allowed[o] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if _, ok := allowed[origin]; ok && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unsafe(r.Method) && r.URL.Path != "/v1/auth/login" && r.URL.Path != "/v1/auth/register" {
			if _, err := r.Cookie("refresh_token"); err == nil {
				c, e := r.Cookie("csrf_token")
				if e != nil || c.Value == "" || r.Header.Get("X-CSRF-Token") != c.Value {
					problem.Write(w, r, http.StatusForbidden, "csrf_failed", "Request rejected", "CSRF token is missing or invalid")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
func RedisRateLimit(client redis.UniversalClient, limit int64, window time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if client == nil {
			problem.Write(w, r, http.StatusServiceUnavailable, "rate_limiter_unavailable", "Service unavailable", "Try again later")
			return
		}
		ip := remoteIP(r)
		digest := sha256.Sum256([]byte(ip))
		key := "cp:api:rate:" + hex.EncodeToString(digest[:])
		n, err := client.Eval(r.Context(), `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return n`, []string{key}, window.Milliseconds()).Int64()
		if err != nil {
			problem.Write(w, r, http.StatusServiceUnavailable, "rate_limiter_unavailable", "Service unavailable", "Try again later")
			return
		}
		if n > limit {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(window.Seconds()), 10))
			problem.Write(w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests", "Wait before retrying")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func unsafe(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

func AccessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		cw := &capture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(cw, r)
		log.Info("http request", "request_id", logger.RequestID(r.Context()), "trace_id", logger.TraceID(r.Context()), "method", r.Method, "path", r.URL.Path, "status", cw.status, "duration_ms", time.Since(started).Milliseconds())
	})
}

type capture struct {
	http.ResponseWriter
	status int
}

func (c *capture) WriteHeader(status int)      { c.status = status; c.ResponseWriter.WriteHeader(status) }
func (c *capture) Write(p []byte) (int, error) { return c.ResponseWriter.Write(p) }
func (c *capture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
