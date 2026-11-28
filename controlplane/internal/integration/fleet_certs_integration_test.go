//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/wafplatform/controlplane/internal/certs"
	"github.com/example/wafplatform/controlplane/internal/fleet"
	"github.com/example/wafplatform/controlplane/internal/platform/secret"
	"github.com/example/wafplatform/controlplane/internal/site"
	"github.com/google/uuid"
)

func TestFleetEnrollmentHeartbeatDNSAndCertificateRevocationIntegration(t *testing.T) {
	ctx, admin, redisClient := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, redisClient)
	worker := workerRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	now := time.Now().UTC()
	ca, caPEM, err := fleet.NewDevelopmentAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	service := fleet.Service{Pool: worker, CA: ca, Now: func() time.Time { return clock }, CertificateLifetime: 24 * time.Hour}
	workerFleet := fleet.Service{Pool: worker, CA: ca, Now: func() time.Time { return clock }, CertificateLifetime: 24 * time.Hour}
	region := "it-fleet-" + uuid.NewString()
	cleanup.region(region)
	register := func(lifetime time.Duration) (fleet.Bootstrap, fleet.Registration) {
		t.Helper()
		bootstrap, e := service.CreateBootstrapToken(ctx, region, "integration")
		if e != nil {
			t.Fatal(e)
		}
		cleanup.edge(bootstrap.EdgeID)
		var storedHash []byte
		if e = admin.QueryRow(ctx, `SELECT token_hash FROM public.edge_bootstrap_tokens WHERE edge_id=$1`, bootstrap.EdgeID).Scan(&storedHash); e != nil {
			t.Fatal(e)
		}
		expectedHash := sha256.Sum256([]byte(bootstrap.Token))
		if !bytes.Equal(storedHash, expectedHash[:]) {
			t.Fatal("bootstrap token was not stored as its SHA-256 digest")
		}
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		csrDER, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted-request-name"}}, key)
		if e != nil {
			t.Fatal(e)
		}
		csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
		workerFleet.CertificateLifetime = lifetime
		registration, e := workerFleet.Register(ctx, bootstrap.Token, csr, caPEM)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = workerFleet.Register(ctx, bootstrap.Token, csr, caPEM); !errors.Is(e, fleet.ErrBootstrapRejected) {
			t.Fatalf("reused bootstrap token accepted: %v", e)
		}
		block, _ := pem.Decode([]byte(registration.Certificate))
		certificate, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			t.Fatal(e)
		}
		if !ca.VerifyEdgeCertificate(certificate, bootstrap.EdgeID, clock) {
			t.Fatal("issued mTLS certificate failed identity verification")
		}
		return bootstrap, registration
	}
	first, cert1 := register(24 * time.Hour)
	second, cert2 := register(24 * time.Hour)
	good := fleet.Heartbeat{SnapshotVersion: 1, CPUPercent: 12.5, MemoryBytes: 1024, RPS: 10, ErrorRate: .01, P99Millis: 50}
	for i := 0; i < 3; i++ {
		if err = service.Heartbeat(ctx, first.EdgeID, cert1.Serial, good); err != nil {
			t.Fatalf("first edge heartbeat %d: %v", i, err)
		}
		if err = service.Heartbeat(ctx, second.EdgeID, cert2.Serial, good); err != nil {
			t.Fatalf("second edge heartbeat %d: %v", i, err)
		}
	}
	var firstState, secondState string
	if err = admin.QueryRow(ctx, `SELECT status FROM public.edges WHERE id=$1`, first.EdgeID).Scan(&firstState); err != nil {
		t.Fatal(err)
	}
	if err = admin.QueryRow(ctx, `SELECT status FROM public.edges WHERE id=$1`, second.EdgeID).Scan(&secondState); err != nil {
		t.Fatal(err)
	}
	if firstState != "ready" || secondState != "ready" {
		t.Fatalf("heartbeat states first=%s second=%s", firstState, secondState)
	}
	dns := &fleet.FakeDNS{}
	if err = service.SweepHealth(ctx, map[string]fleet.DNSProvider{"integration": dns}, time.Minute, 3, 1); err != nil {
		t.Fatal(err)
	}
	if !dns.Records[first.Region][first.EdgeID] || !dns.Records[second.Region][second.EdgeID] {
		t.Fatalf("DNS did not add edges after healthy streak: %+v", dns.Records)
	}
	if _, err = admin.Exec(ctx, `UPDATE public.edges SET last_heartbeat_at=$2 WHERE id=$1`, first.EdgeID, clock.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err = service.SweepHealth(ctx, map[string]fleet.DNSProvider{"integration": dns}, time.Minute, 3, 1); err != nil {
			t.Fatal(err)
		}
	}
	if dns.Records[first.Region][first.EdgeID] || !dns.Records[second.Region][second.EdgeID] {
		t.Fatalf("stale edge DNS withdrawal unsafe or incomplete: %+v", dns.Records)
	}
	if err = service.Decommission(ctx, first.EdgeID); err != nil {
		t.Fatalf("decommission after DNS withdrawal: %v", err)
	}
	if service.CertificateActive(ctx, first.EdgeID, cert1.Serial) {
		t.Fatal("decommissioned edge certificate remains active")
	}
	if err = service.RevokeCompromised(ctx, second.EdgeID, dns); err != nil {
		t.Fatal(err)
	}
	if service.CertificateActive(ctx, second.EdgeID, cert2.Serial) {
		t.Fatal("compromised edge certificate remains active")
	}
	if dns.Records[second.Region][second.EdgeID] {
		t.Fatal("compromised edge DNS record remains")
	}
	_, expired := register(time.Second)
	clock = clock.Add(2 * time.Second)
	if service.CertificateActive(ctx, expired.EdgeID, expired.Serial) {
		t.Fatal("expired edge certificate remains active")
	}
	if err = service.Heartbeat(ctx, expired.EdgeID, expired.Serial, good); !errors.Is(err, fleet.ErrEdgeCertificateRejected) {
		t.Fatalf("expired certificate heartbeat error=%v", err)
	}
	expiredBootstrap, err := service.CreateBootstrapToken(ctx, region, "integration")
	if err != nil {
		t.Fatal(err)
	}
	cleanup.edge(expiredBootstrap.EdgeID)
	_, renewalKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	renewalCSRDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, renewalKey)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour + time.Second)
	if _, err = workerFleet.Register(ctx, expiredBootstrap.Token, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: renewalCSRDER}), caPEM); !errors.Is(err, fleet.ErrBootstrapRejected) {
		t.Fatalf("expired bootstrap token error=%v", err)
	}
	if err = good.Validate(); err != nil {
		t.Fatal(err)
	}
	if err = (fleet.Heartbeat{CPUPercent: 101}).Validate(); err == nil {
		t.Fatal("invalid heartbeat metrics accepted")
	}
	cleanup.runFixtureRows()
	var fleetResidue int
	if err = admin.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM public.edges WHERE id=ANY($1::uuid[]))+
      (SELECT count(*) FROM public.edge_bootstrap_tokens WHERE edge_id=ANY($1::uuid[]))+
      (SELECT count(*) FROM public.edge_certificates WHERE edge_id=ANY($1::uuid[]))+
      (SELECT count(*) FROM public.edge_dns_withdrawal_limits WHERE region=ANY($2::text[]))`, cleanup.edges, cleanup.regions).Scan(&fleetResidue); err != nil || fleetResidue != 0 {
		t.Fatalf("fleet fixture cleanup left %d rows: %v", fleetResidue, err)
	}
}

func TestCertificateRenewalBackoffAndSecretStoreIntegration(t *testing.T) {
	ctx, admin, redisClient := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, redisClient)
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	worker := workerRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	userID, tenantID := registerSiteIntegrationUser(t, ctx, admin, app, redisClient, cleanup, "cert-renew")
	sites := site.Service{Pool: app}
	created, err := sites.Create(ctx, tenantID, userID, "cert-renew-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sites.AddDomain(ctx, tenantID, userID, created.ID, testHostname("renew"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `INSERT INTO public.certificates(id,tenant_id,domain_id,status,not_after,secret_ref,issuer) VALUES($1,$2,$3,'active',$4,'old-ref','fake')`, certID, tenantID, proof.ID, now.Add(20*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	issuer := &certs.FakeIssuer{Now: func() time.Time { return now }}
	secrets := secret.NewMemory()
	issuerKey := "integration-" + uuid.NewString()
	cleanup.issuer(issuerKey)
	manager := certs.Manager{Pool: worker, Issuer: issuer, Secrets: secrets, Now: func() time.Time { return now }, RateLimitKey: issuerKey}
	count, err := manager.RenewDue(ctx, 10)
	if err != nil || count != 1 {
		t.Fatalf("renewal count=%d err=%v", count, err)
	}
	var status, secretRef string
	var notAfter time.Time
	if err = admin.QueryRow(ctx, `SELECT status,secret_ref,not_after FROM public.certificates WHERE id=$1`, certID).Scan(&status, &secretRef, &notAfter); err != nil {
		t.Fatal(err)
	}
	if status != "active" || secretRef == "old-ref" || !notAfter.After(now.Add(80*24*time.Hour)) {
		t.Fatalf("renewed certificate status=%s ref=%q not_after=%s", status, secretRef, notAfter)
	}
	material, err := secrets.Get(ctx, secretRef)
	if err != nil || len(material) == 0 {
		t.Fatalf("renewed key bundle not held by SecretStore: bytes=%d err=%v", len(material), err)
	}
	privateMaterial, err := secrets.Get(ctx, secretRef+"/private-key")
	if err != nil || len(privateMaterial) == 0 {
		t.Fatalf("renewed private key not held by SecretStore: bytes=%d err=%v", len(privateMaterial), err)
	}
	var storedKey string
	if err = admin.QueryRow(ctx, `SELECT secret_ref FROM public.certificates WHERE id=$1`, certID).Scan(&storedKey); err != nil || strings.Contains(storedKey, string(privateMaterial)) {
		t.Fatal("private key material was stored in database")
	}
	concurrentID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `INSERT INTO public.certificates(id,tenant_id,domain_id,status,not_after,secret_ref,issuer) VALUES($1,$2,$3,'active',$4,'concurrent-old-ref','fake')`, concurrentID, tenantID, proof.ID, now.Add(20*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	blocking := &integrationBlockingIssuer{started: make(chan struct{}), release: make(chan struct{}), issued: certs.Issued{CertificatePEM: []byte("certificate"), PrivateKeyPEM: []byte("private"), NotAfter: now.Add(90 * 24 * time.Hour), Issuer: "blocking-fake"}}
	managerA := certs.Manager{Pool: worker, Issuer: blocking, Secrets: secret.NewMemory(), Now: func() time.Time { return now }, RateLimitKey: issuerKey}
	secondIssuer := &certs.FakeIssuer{Now: func() time.Time { return now }}
	managerB := certs.Manager{Pool: worker, Issuer: secondIssuer, Secrets: secret.NewMemory(), Now: func() time.Time { return now }, RateLimitKey: issuerKey}
	done := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		n, e := managerA.RenewDue(ctx, 10)
		done <- struct {
			count int
			err   error
		}{n, e}
	}()
	select {
	case <-blocking.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first renewal did not reach fake issuer")
	}
	if count, renewErr := managerB.RenewDue(ctx, 10); renewErr != nil || count != 0 {
		t.Fatalf("second worker duplicated renewal: count=%d err=%v", count, renewErr)
	}
	close(blocking.release)
	result := <-done
	if result.err != nil || result.count != 1 {
		t.Fatalf("first worker renewal count=%d err=%v", result.count, result.err)
	}
	if blocking.calls.Load() != 1 || secondIssuer.Calls != 0 {
		t.Fatalf("duplicate issuer calls: first=%d second=%d", blocking.calls.Load(), secondIssuer.Calls)
	}

	failedID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `INSERT INTO public.certificates(id,tenant_id,domain_id,status,not_after,secret_ref,issuer) VALUES($1,$2,$3,'active',$4,'failed-old-ref','fake')`, failedID, tenantID, proof.ID, now.Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	issuer.Fail = errors.New("simulated issuer outage")
	if count, err = manager.RenewDue(ctx, 10); err != nil || count != 0 {
		t.Fatalf("failed renewal count=%d err=%v", count, err)
	}
	var attempts int
	var next time.Time
	if err = admin.QueryRow(ctx, `SELECT renewal_attempts,next_attempt_at FROM public.certificates WHERE id=$1`, failedID).Scan(&attempts, &next); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || next.Before(now.Add(time.Minute)) || next.After(now.Add(time.Minute+time.Millisecond)) {
		t.Fatalf("retry schedule attempts=%d next=%s", attempts, next)
	}
	var warningCount int
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.alerts WHERE tenant_id=$1 AND details->>'kind'='certificate_renewal_failed' AND details->>'certificate_id'=$2`, tenantID, failedID.String()).Scan(&warningCount); err != nil || warningCount != 1 {
		t.Fatalf("renewal warning count=%d err=%v", warningCount, err)
	}
	if count, err = manager.RenewDue(ctx, 10); err != nil || count != 0 {
		t.Fatalf("renewal ran before backoff: count=%d err=%v", count, err)
	}
	if issuer.Calls != 2 {
		t.Fatalf("duplicate or premature issuer calls: %d, want 2", issuer.Calls)
	}
	cleanup.runFixtureRows()
	var renewalResidue int
	if err = admin.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM public.certificates WHERE tenant_id=$1)+
      (SELECT count(*) FROM public.certificate_issuance_rate_limits WHERE issuer_key=ANY($2::text[]))`, cleanup.tenants[0], cleanup.issuers).Scan(&renewalResidue); err != nil || renewalResidue != 0 {
		t.Fatalf("certificate renewal fixture cleanup left %d rows: %v", renewalResidue, err)
	}
}

type integrationBlockingIssuer struct {
	started, release chan struct{}
	calls            atomic.Int32
	issued           certs.Issued
}

func (i *integrationBlockingIssuer) Issue(ctx context.Context, _ certs.Order) (certs.Issued, error) {
	if i.calls.Add(1) == 1 {
		close(i.started)
	}
	select {
	case <-ctx.Done():
		return certs.Issued{}, ctx.Err()
	case <-i.release:
		return i.issued, nil
	}
}
func (*integrationBlockingIssuer) Revoke(context.Context, string) error { return nil }
