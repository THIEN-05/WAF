package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEdgeRegistrationRejectsPlainHTTP(t *testing.T) {
	server := &Server{}
	request := httptest.NewRequest("POST", "/internal/edges/register", strings.NewReader(`{"token":"bootstrap-token-placeholder-value","csr":"pem"}`))
	response := httptest.NewRecorder()
	server.registerEdge(response, request)
	if response.Code != http.StatusUpgradeRequired {
		t.Fatalf("plain HTTP registration status=%d body=%s", response.Code, response.Body.String())
	}
}
