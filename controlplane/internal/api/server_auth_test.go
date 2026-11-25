package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestRequireAuthRejectsJWTAlgorithmConfusion(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{private: privateKey}
	protected := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	claims := jwt.MapClaims{"sub": uuid.NewString(), "tenant_id": uuid.NewString(), "role": "owner", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}

	valid, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	validRequest := httptest.NewRequest(http.MethodGet, "/protected", nil)
	validRequest.Header.Set("Authorization", "Bearer "+valid)
	validResponse := httptest.NewRecorder()
	protected.ServeHTTP(validResponse, validRequest)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("valid EdDSA token status=%d", validResponse.Code)
	}

	confused, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+confused)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("HS256 token signed with public key accepted: status=%d", response.Code)
	}
}
