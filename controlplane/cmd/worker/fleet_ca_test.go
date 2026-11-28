package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/example/wafplatform/controlplane/internal/platform/secret"
	"github.com/google/uuid"
)

func TestDevelopmentEdgeCAUsesSecretStoreAndReturnsOnlyCertificate(t *testing.T) {
	store := secret.NewMemory()
	authority, caPEM, err := loadEdgeAuthority(context.Background(), nil, "", "development", store)
	if err != nil {
		t.Fatal(err)
	}
	storedKey, err := store.Get(context.Background(), "edge-ca/private-key")
	if err != nil || len(storedKey) == 0 {
		t.Fatalf("CA key did not pass through SecretStore: bytes=%d err=%v", len(storedKey), err)
	}
	if len(caPEM) == 0 || bytes.Contains(caPEM, storedKey) {
		t.Fatal("CA private key leaked into registration CA certificate")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = authority.IssueCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), uuid.New(), time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("CA loaded back from SecretStore cannot sign: %v", err)
	}
}

func TestConfiguredEdgeCAKeyRequiresPrivateExternalFile(t *testing.T) {
	root := repositoryRoot()
	if root == "" {
		t.Fatal("could not locate repository root for CA path test")
	}
	if _, err := readPrivateCAKeyFile(filepath.Join(root, "go.mod")); err == nil {
		t.Fatal("repository file accepted as internal CA private key")
	}

	path := filepath.Join(t.TempDir(), "edge-ca-key.pem")
	if err := os.WriteFile(path, []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateCAKeyFile(path); err != nil {
		t.Fatalf("private external key file rejected: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readPrivateCAKeyFile(path); err == nil {
			t.Fatal("group/world-readable CA key file accepted")
		}
	}
}
