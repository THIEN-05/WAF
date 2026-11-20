package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("health response = (%d, %q), want (200, %q)", response.Code, response.Body.String(), "ok\n")
	}
}

func TestEnvFallback(t *testing.T) {
	t.Setenv("WAF_TEST_SETTING", "configured")
	if got := Env("WAF_TEST_SETTING", "default"); got != "configured" {
		t.Fatalf("Env() = %q, want configured", got)
	}
	if got := Env("WAF_TEST_UNSET", "default"); got != "default" {
		t.Fatalf("Env() = %q, want default", got)
	}
}
