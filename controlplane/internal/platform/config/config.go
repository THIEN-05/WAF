package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	APIAddr, DatabaseURL, RedisAddr, RedisPassword, NATSURL string
	SMTPAddr, SMTPFrom, JWTPrivateKey, TOTPKey              string
	Environment                                             string
	APITLSCertFile, APITLSKeyFile                           string
	AllowedOrigins                                          []string
	RedisDB                                                 int
}

func Load() (Config, error) {
	c := Config{
		APIAddr: env("API_ADDR", ":8081"), DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisAddr: env("REDIS_ADDR", "127.0.0.1:6379"), RedisPassword: os.Getenv("REDIS_PASSWORD"),
		NATSURL: env("NATS_URL", "nats://127.0.0.1:4222"), SMTPAddr: env("SMTP_ADDR", "127.0.0.1:1025"),
		SMTPFrom: env("SMTP_FROM", "no-reply@localhost"), JWTPrivateKey: os.Getenv("JWT_ED25519_PRIVATE_KEY"),
		TOTPKey:        os.Getenv("TOTP_ENCRYPTION_KEY"),
		Environment:    env("APP_ENV", "development"),
		APITLSCertFile: os.Getenv("API_TLS_CERT_FILE"), APITLSKeyFile: os.Getenv("API_TLS_KEY_FILE"),
	}
	if raw := os.Getenv("REDIS_DB"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return Config{}, fmt.Errorf("REDIS_DB must be a non-negative integer")
		}
		c.RedisDB = n
	}
	if raw := os.Getenv("CORS_ALLOWED_ORIGINS"); raw != "" {
		for _, origin := range split(raw) {
			origin = strings.TrimSpace(origin)
			if origin != "" {
				c.AllowedOrigins = append(c.AllowedOrigins, origin)
			}
		}
	}
	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	return c, nil
}

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
func split(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
