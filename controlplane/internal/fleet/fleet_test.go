package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEdgeStateTransitions(t *testing.T) {
	valid := []struct{ from, to State }{{Registering, Ready}, {Ready, Degraded}, {Degraded, Ready}, {Ready, Draining}, {Draining, Offline}, {Offline, Decommissioned}}
	for _, pair := range valid {
		if !CanTransition(pair.from, pair.to) {
			t.Errorf("transition %s -> %s rejected", pair.from, pair.to)
		}
	}
	invalid := []struct{ from, to State }{{Registering, Offline}, {Decommissioned, Ready}, {Draining, Ready}, {Ready, Registering}, {Offline, Registering}}
	for _, pair := range invalid {
		if CanTransition(pair.from, pair.to) {
			t.Errorf("transition %s -> %s accepted", pair.from, pair.to)
		}
	}
}

func TestPlanDNSHysteresisAndSafety(t *testing.T) {
	a, b, c, d := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	plan := PlanDNS([]DNSCandidate{{ID: a, HealthyStreak: 2}, {ID: b, HealthyStreak: 3}, {ID: c, Present: true, UnhealthyStreak: 3}, {ID: d, Present: true}}, 3, 1)
	if len(plan) != 2 || !plan[0].Add || plan[0].EdgeID != b || plan[1].Add || plan[1].EdgeID != c {
		t.Fatalf("unexpected DNS plan: %+v", plan)
	}
	last := PlanDNS([]DNSCandidate{{ID: a, Present: true, UnhealthyStreak: 99}}, 1, 10)
	if len(last) != 0 {
		t.Fatalf("planned withdrawal of final edge: %+v", last)
	}
	limited := PlanDNS([]DNSCandidate{{ID: a, Present: true, UnhealthyStreak: 3}, {ID: b, Present: true, UnhealthyStreak: 3}, {ID: c, Present: true}}, 1, 1)
	if len(limited) != 1 {
		t.Fatalf("withdrawal cap ignored: %+v", limited)
	}
}

func TestAuthorityIssuesBoundClientCertificateAndRejectsExpiry(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ca, caPEM, err := NewDevelopmentAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored-by-issuer"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	id := uuid.New()
	certPEM, serial, notAfter, err := ca.IssueCSR(csrPEM, id, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(caPEM) == 0 || serial == "" || !notAfter.Equal(now.Add(time.Hour)) || !ca.VerifyEdgeCertificate(cert, id, now) {
		t.Fatal("issued certificate did not satisfy edge identity contract")
	}
	if ca.VerifyEdgeCertificate(cert, id, now.Add(2*time.Hour)) {
		t.Fatal("expired edge certificate accepted")
	}
	if ca.VerifyEdgeCertificate(cert, uuid.New(), now) {
		t.Fatal("certificate accepted for different edge")
	}
}
