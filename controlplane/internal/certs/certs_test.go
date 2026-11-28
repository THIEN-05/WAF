package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRetryBackoffAndExpiryWarningThreshold(t *testing.T) {
	for attempt, want := range []time.Duration{time.Minute, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute} {
		if got := retryDelay(attempt); got != want {
			t.Errorf("attempt %d backoff=%s want %s", attempt, got, want)
		}
	}
	if got := retryDelay(99); got != 24*time.Hour {
		t.Fatalf("backoff cap=%s", got)
	}
	now := time.Now().UTC()
	if !Status(uuid.New(), now.Add(29*24*time.Hour), now).RenewalDue {
		t.Fatal("renewal did not become due within 30 days")
	}
	if Status(uuid.New(), now.Add(31*24*time.Hour), now).RenewalDue {
		t.Fatal("renewal became due too early")
	}
}

func TestPostgresRetryTimestampNeverRoundsBackoffDown(t *testing.T) {
	base := time.Date(2026, 11, 28, 4, 19, 9, 628318700, time.UTC)
	want := base.Add(time.Minute)
	got := postgresTimestampCeil(want)
	if got.Before(want) {
		t.Fatalf("database timestamp rounded retry earlier: got=%s want_at_least=%s", got, want)
	}
	if got.After(want.Add(time.Microsecond)) {
		t.Fatalf("database timestamp rounding exceeded one microsecond: got=%s want_at_most=%s", got, want.Add(time.Microsecond))
	}
	if got != got.Truncate(time.Microsecond) {
		t.Fatalf("retry timestamp is not PostgreSQL microsecond precision: %s", got)
	}
}

func TestManagerDeduplicatesOrderAndRateLimits(t *testing.T) {
	now := time.Now()
	m := Manager{Now: func() time.Time { return now }, MaxOrdersPerMinute: 1}
	id := uuid.New()
	if !m.claim(id) {
		t.Fatal("first order claim rejected")
	}
	if m.claim(id) {
		t.Fatal("duplicate in-flight domain order accepted")
	}
	m.release(id)
	if m.claim(uuid.New()) {
		t.Fatal("issuer rate limit exceeded")
	}
	now = now.Add(time.Minute)
	if !m.claim(uuid.New()) {
		t.Fatal("rate limit did not reset")
	}
}

func TestValidateCustomerCertificateChainKeyAndExpiry(t *testing.T) {
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: bigInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: bigInt(2), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err = ValidateCustomerUpload(certPEM, keyPEM, roots, "example.test", now); err != nil {
		t.Fatalf("valid upload rejected: %v", err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, _ := x509.MarshalPKCS8PrivateKey(wrongKey)
	if _, err = ValidateCustomerUpload(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongDER}), roots, "example.test", now); err == nil {
		t.Fatal("mismatched private key accepted")
	}
	if _, err = ValidateCustomerUpload(certPEM, keyPEM, roots, "example.test", now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired certificate accepted")
	}
	if _, err = ValidateCustomerUpload(certPEM, keyPEM, x509.NewCertPool(), "example.test", now); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if _, err = ValidateCustomerUpload(certPEM, keyPEM, roots, "other.test", now); err == nil {
		t.Fatal("certificate for another domain accepted")
	}
}

func bigInt(v int64) *big.Int { return big.NewInt(v) }
