package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicAPIDoesNotExposeEdgeRegistration(t *testing.T) {
	server := &Server{log: slog.New(slog.NewTextHandler(httptest.NewRecorder(), nil))}
	request := httptest.NewRequest(http.MethodPost, "/internal/edges/register", nil)
	response := httptest.NewRecorder()
	server.Router().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("public API edge registration status=%d body=%s; expected route to be absent", response.Code, response.Body.String())
	}
}
