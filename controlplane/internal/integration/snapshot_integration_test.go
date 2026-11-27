//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	platformnats "github.com/example/wafplatform/controlplane/internal/platform/nats"
	"github.com/example/wafplatform/controlplane/internal/platform/secret"
	"github.com/example/wafplatform/controlplane/internal/site"
	"github.com/example/wafplatform/controlplane/internal/snapshot"
	"github.com/example/wafplatform/pkg/wafcore"
	"github.com/google/uuid"
)

func TestSnapshotOutboxNATSSigningAndMTLSEndpointIntegration(t *testing.T) {
	ctx, admin, redisClient := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, redisClient)
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	worker := workerRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:4222"
	}
	nc, err := platformnats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect real NATS service: %v", err)
	}
	t.Cleanup(nc.Close)

	userID, tenantID := registerSiteIntegrationUser(t, ctx, admin, app, redisClient, cleanup, "snapshot")
	// Exercise Pro entitlements: the challenge key reference must be retained,
	// and over-quota rules/policies must be trimmed to the Pro limits.
	tag, err := admin.Exec(ctx, `UPDATE public.subscriptions SET plan_id=(SELECT id FROM public.plans WHERE code='pro') WHERE tenant_id=$1 AND status='active'`, tenantID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("set snapshot fixture plan to Pro: rows=%d err=%v", tag.RowsAffected(), err)
	}
	service := site.Service{Pool: app}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	created, err := service.Create(ctx, tenantID, userID, "snapshot-"+suffix)
	if err != nil {
		t.Fatal(err)
	}
	proof := addTestDomain(t, service, ctx, tenantID, userID, created.ID, "snapshot")
	if _, err = service.AddOrigin(ctx, tenantID, userID, created.ID, "https://origin.example", siteFakeDNS{ips: []net.IP{net.ParseIP("203.0.113.21")}}); err != nil {
		t.Fatal(err)
	}
	workerSite := site.Service{Pool: worker, VerificationCNAMEZone: "verify.example.net"}
	if _, err = admin.Exec(ctx, `UPDATE public.domains SET next_verification_at=now()-interval '1 second' WHERE id=$1`, proof.ID); err != nil {
		t.Fatal(err)
	}
	if count, verifyErr := workerSite.VerifyDueDomains(ctx, siteFakeDNS{records: []string{proof.Token}}, time.Now(), 10); verifyErr != nil || count != 1 {
		t.Fatalf("verify integration domain count=%d err=%v", count, verifyErr)
	}
	// Seed over-quota config and secret references. The literal secret values
	// exist only in the test SecretStore; snapshot fields contain references.
	for i := 0; i < 22; i++ {
		if _, err = admin.Exec(ctx, `INSERT INTO public.rules(id,tenant_id,site_id,priority,expression,action,mode) VALUES($1,$2,$3,$4,'true == true','log','enforce')`, uuid.New(), tenantID, created.ID, i); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 6; i++ {
		if _, err = admin.Exec(ctx, `INSERT INTO public.rate_limit_policies(id,tenant_id,site_id,match_expr,key_expr,request_limit,window_seconds,action) VALUES($1,$2,$3,'true == true','ip',10,60,'block')`, uuid.New(), tenantID, created.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = admin.Exec(ctx, `INSERT INTO public.bot_settings(id,tenant_id,site_id,settings) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(site_id) DO UPDATE SET settings=EXCLUDED.settings`, uuid.New(), tenantID, created.ID, `{"mode":"monitor","challenge_hmac_key_id":"hmac-kid-reference","origin_credential_ids":["origin-credential-reference"],"additional_secrets":{"tls":"tls-reference"}}`); err != nil {
		t.Fatal(err)
	}

	changed := make(chan []byte, 256)
	unsubscribe, err := nc.Subscribe("config.changed", func(data []byte) {
		select {
		case changed <- append([]byte(nil), data...):
		default:
		}
	})
	if err != nil {
		t.Fatalf("subscribe config.changed: %v", err)
	}
	t.Cleanup(func() { _ = unsubscribe() })
	repository := snapshot.PostgresRepository{Pool: worker}
	if count, dispatchErr := repository.DispatchOutbox(ctx, func(data []byte) error {
		if publishErr := nc.Publish("config.changed", data); publishErr != nil {
			return publishErr
		}
		return nc.Flush()
	}); dispatchErr != nil || count == 0 {
		t.Fatalf("dispatch config outbox count=%d err=%v", count, dispatchErr)
	}
	deadline := time.After(3 * time.Second)
	found := false
	for !found {
		select {
		case payload := <-changed:
			var event struct {
				SiteID string `json:"site_id"`
			}
			if json.Unmarshal(payload, &event) == nil && event.SiteID == created.ID.String() {
				found = true
			}
		case <-deadline:
			t.Fatal("NATS did not deliver the site's config.changed outbox event")
		}
	}

	region := "it-" + suffix
	if _, err = admin.Exec(ctx, `DELETE FROM public.config_snapshots WHERE scope=$1`, region); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DELETE FROM public.config_snapshots WHERE scope=$1`, region)
	})
	objects := snapshot.FileObjects{Root: t.TempDir()}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := secret.NewMemory()
	rawSecrets := [][]byte{[]byte("raw-hmac-secret-never-serialized"), []byte("raw-origin-password-never-serialized"), []byte("raw-tls-private-key-never-serialized")}
	for i, value := range rawSecrets {
		if err = store.Put(ctx, []string{"raw/hmac", "raw/origin", "raw/tls"}[i], value); err != nil {
			t.Fatal(err)
		}
	}
	keyID := "integration-signing-kid"
	if err = store.Put(ctx, "snapshot-signing/"+keyID, privateKey); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	var fixtureWarnings []string
	builder := &snapshot.Builder{Repository: repository, Objects: objects, Signer: snapshot.SecretSigner{Store: store, KeyID: keyID}, PublicKeys: map[string]ed25519.PublicKey{keyID: publicKey}, OnWarning: func(w snapshot.Warning) {
		if w.SiteID == created.ID.String() {
			fixtureWarnings = append(fixtureWarnings, w.Message)
		}
		if w.SiteID != "" {
			if warnErr := repository.WarnSite(ctx, w.SiteID, w.Message); warnErr != nil {
				t.Errorf("persist site snapshot warning: %v", warnErr)
			}
		}
	}}
	record, err := builder.Build(ctx, region)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtureWarnings) != 0 {
		t.Fatalf("valid fixture site was rejected from snapshot: %v", fixtureWarnings)
	}
	var storedCount int
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.config_snapshots WHERE scope=$1 AND version=$2 AND rollout_state='active'`, region, record.Version).Scan(&storedCount); err != nil || storedCount != 1 {
		t.Fatalf("config_snapshots active rows=%d err=%v", storedCount, err)
	}
	signed, err := objects.Get(ctx, record.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range rawSecrets {
		if bytes.Contains(signed, raw) {
			t.Fatal("snapshot contains a raw secret value")
		}
	}
	if bytes.Contains(signed, privateKey) || !bytes.Contains(signed, []byte(keyID)) {
		t.Fatal("signed snapshot leaked signing private key or omitted kid")
	}
	verified, err := wafcore.VerifySnapshot(signed, builder.PublicKeys)
	if err != nil {
		t.Fatalf("snapshot signature verification: %v", err)
	}
	var included *wafcore.Site
	for i := range verified.Sites {
		if verified.Sites[i].ID == created.ID.String() {
			included = &verified.Sites[i]
		}
	}
	if included == nil || len(included.Rules) != 20 || len(included.RateLimits) != 5 {
		t.Fatalf("snapshot entitlement trim site=%+v", included)
	}
	for _, rule := range included.Rules {
		if rule.Mode != "" {
			t.Fatalf("database enforce mode must map to wafcore default enforcement, rule=%+v", rule)
		}
	}
	if !strings.Contains(included.Secrets.ChallengeHMACKeyID, "reference") || len(included.Secrets.OriginCredentialIDs) != 1 || included.Secrets.OriginCredentialIDs[0] != "origin-credential-reference" {
		t.Fatalf("snapshot secret fields should be references only: %+v", included.Secrets)
	}

	updated := make(chan []byte, 4)
	unsubUpdated, err := nc.Subscribe("config.updated", func(data []byte) { updated <- append([]byte(nil), data...) })
	if err != nil {
		t.Fatalf("subscribe config.updated: %v", err)
	}
	t.Cleanup(func() { _ = unsubUpdated() })
	if err = snapshot.NotifyUpdated(nc, region, record); err != nil {
		t.Fatalf("publish config.updated: %v", err)
	}
	select {
	case payload := <-updated:
		var event struct {
			Region   string `json:"region"`
			Version  uint64 `json:"version"`
			Checksum string `json:"checksum_sha256"`
		}
		if err = json.Unmarshal(payload, &event); err != nil || event.Region != region || event.Version != record.Version || event.Checksum != record.Checksum {
			t.Fatalf("config.updated payload=%s err=%v", payload, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("NATS did not deliver config.updated")
	}

	edgeID := uuid.New()
	caPool, clientCert, serial, err := testEdgeClientCertificate(t, edgeID.String(), time.Now().Add(-5*time.Minute), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !hasExtKeyUsage(clientCert.Leaf, x509.ExtKeyUsageClientAuth) || !contains(clientCert.Leaf.DNSNames, edgeID.String()) {
		t.Fatal("test edge certificate must contain clientAuth EKU and the edge ID DNS SAN")
	}
	_, unknownSerialCert, unknownSerial, err := testEdgeClientCertificate(t, edgeID.String(), time.Now().Add(-5*time.Minute), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, expiredCert, _, err := testEdgeClientCertificate(t, edgeID.String(), time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	wrongEdgeID := uuid.New()
	_, wrongNameCert, wrongNameSerial, err := testEdgeClientCertificate(t, "different-edge", time.Now().Add(-5*time.Minute), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range []tls.Certificate{unknownSerialCert, expiredCert, wrongNameCert} {
		ca, parseErr := x509.ParseCertificate(cert.Certificate[1])
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		caPool.AddCert(ca)
	}
	if _, err = admin.Exec(ctx, `INSERT INTO public.edges(id,region,provider,status,cert_serial) VALUES($1,$2,'integration','ready',$3)`, edgeID, region, serial); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `INSERT INTO public.edges(id,region,provider,status,cert_serial) VALUES($1,$2,'integration','ready',$3)`, wrongEdgeID, region, wrongNameSerial); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DELETE FROM public.edges WHERE id=$1`, edgeID) })
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DELETE FROM public.edges WHERE id=$1`, wrongEdgeID) })
	endpoint := snapshot.EdgeHandler{Repository: repository, Objects: objects, Resolver: repository}
	server := httptest.NewUnstartedServer(endpoint)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caPool}
	server.StartTLS()
	t.Cleanup(server.Close)
	serverCert := server.Certificate()
	if serverCert == nil || !hasExtKeyUsage(serverCert, x509.ExtKeyUsageServerAuth) || len(serverCert.IPAddresses) == 0 {
		t.Fatal("test CP certificate must contain serverAuth EKU and an IP SAN")
	}
	clientFor := func(certs ...tls.Certificate) *http.Client {
		client := server.Client()
		transport := client.Transport.(*http.Transport).Clone()
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.Certificates = certs
		client.Transport = transport
		t.Cleanup(client.CloseIdleConnections)
		return client
	}
	client := clientFor(clientCert)
	requestSnapshotWith := func(testClient *http.Client, requestedEdge string, query string) (*http.Response, []byte, error) {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/internal/snapshot?edge_id="+requestedEdge+query, nil)
		if requestErr != nil {
			return nil, nil, requestErr
		}
		response, requestErr := testClient.Do(request)
		if requestErr != nil {
			return nil, nil, requestErr
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			return response, nil, readErr
		}
		return response, body, closeErr
	}
	requestSnapshot := func(query string) (*http.Response, []byte, error) {
		return requestSnapshotWith(client, edgeID.String(), query)
	}
	response, body, err := requestSnapshot("&since=0")
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("ETag") != `"`+record.Checksum+`"` || !bytes.Equal(body, signed) {
		t.Fatalf("mTLS snapshot HTTP response status=%v etag=%q bodyBytes=%d err=%v", response.StatusCode, response.Header.Get("ETag"), len(body), err)
	}
	for _, query := range []string{"&since=" + jsonNumber(record.Version), "&since=" + jsonNumber(record.Version+100)} {
		response, _, err = requestSnapshot(query)
		if err != nil || response.StatusCode != http.StatusNotModified || response.Header.Get("ETag") != `"`+record.Checksum+`"` {
			t.Fatalf("snapshot since 304 status=%v etag=%q err=%v", response.StatusCode, response.Header.Get("ETag"), err)
		}
	}
	response, internalBody, err := requestSnapshot("&since=not-a-number")
	if err != nil || response.StatusCode != http.StatusBadRequest || bytes.Contains(internalBody, []byte(serial)) {
		t.Fatalf("invalid since response status=%v body=%q err=%v", response.StatusCode, internalBody, err)
	}
	response, _, err = requestSnapshotWith(client, uuid.NewString(), "&since=0")
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("client-supplied mismatched edge_id status=%v err=%v, want 403", response.StatusCode, err)
	}
	wrongNameClient := clientFor(wrongNameCert)
	response, _, err = requestSnapshotWith(wrongNameClient, wrongEdgeID.String(), "&since=0")
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("edge certificate CN/SAN mismatch status=%v err=%v, want 403", response.StatusCode, err)
	}
	unknownSerialClient := clientFor(unknownSerialCert)
	response, _, err = requestSnapshotWith(unknownSerialClient, edgeID.String(), "&since=0")
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("unregistered client certificate serial=%s status=%v err=%v, want 403", unknownSerial, response.StatusCode, err)
	}
	if _, err = admin.Exec(ctx, `UPDATE public.edges SET status='revoked' WHERE id=$1`, edgeID); err != nil {
		t.Fatal(err)
	}
	response, _, err = requestSnapshot("&since=0")
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked client certificate status=%v err=%v, want 403", response.StatusCode, err)
	}
	noCertClient := clientFor()
	if _, _, err = requestSnapshotWith(noCertClient, edgeID.String(), "&since=0"); err == nil {
		t.Fatal("mTLS endpoint accepted a connection without a client certificate")
	}
	expiredClient := clientFor(expiredCert)
	if _, _, err = requestSnapshotWith(expiredClient, edgeID.String(), "&since=0"); err == nil {
		t.Fatal("mTLS endpoint accepted an expired client certificate")
	}
	t.Logf("snapshot build-to-edge-apply elapsed=%s (PostgreSQL/NATS real services, local in-process HTTP listener)", time.Since(started))
}

func TestSnapshotWarnSiteIsolatedAndPersistedIntegration(t *testing.T) {
	ctx, admin, redisClient := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, redisClient)
	app := apiRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	worker := workerRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	userID, tenantID := registerSiteIntegrationUser(t, ctx, admin, app, redisClient, cleanup, "snapshot-warning")
	if _, err := admin.Exec(ctx, `UPDATE public.subscriptions SET plan_id=(SELECT id FROM public.plans WHERE code='pro') WHERE tenant_id=$1 AND status='active'`, tenantID); err != nil {
		t.Fatal(err)
	}
	appSites := site.Service{Pool: app}
	workerSites := site.Service{Pool: worker, VerificationCNAMEZone: "verify.example.net"}
	const challengeKeyReference = "warning-challenge-key-reference"
	makeVerifiedSite := func(name string) site.Site {
		t.Helper()
		created, err := appSites.Create(ctx, tenantID, userID, name)
		if err != nil {
			t.Fatal(err)
		}
		proof := addTestDomain(t, appSites, ctx, tenantID, userID, created.ID, name)
		if _, err = appSites.AddOrigin(ctx, tenantID, userID, created.ID, "https://origin.example", siteFakeDNS{ips: []net.IP{net.ParseIP("203.0.113.22")}}); err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, `INSERT INTO public.bot_settings(id,tenant_id,site_id,settings) VALUES($1,$2,$3,$4::jsonb)`, uuid.New(), tenantID, created.ID, `{"mode":"monitor","challenge_hmac_key_id":"`+challengeKeyReference+`"}`); err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, `UPDATE public.domains SET next_verification_at=now()-interval '1 second' WHERE id=$1`, proof.ID); err != nil {
			t.Fatal(err)
		}
		if verified, verifyErr := workerSites.VerifyDueDomains(ctx, siteFakeDNS{records: []string{proof.Token}}, time.Now(), 10); verifyErr != nil || verified != 1 {
			t.Fatalf("verify %s domain count=%d err=%v", name, verified, verifyErr)
		}
		return created
	}
	badRuleSite := makeVerifiedSite("warning-rule-" + strings.ReplaceAll(uuid.NewString(), "-", ""))
	badModeSite := makeVerifiedSite("warning-mode-" + strings.ReplaceAll(uuid.NewString(), "-", ""))
	badOriginSite := makeVerifiedSite("warning-origin-" + strings.ReplaceAll(uuid.NewString(), "-", ""))
	overQuotaSite := makeVerifiedSite("warning-quota-" + strings.ReplaceAll(uuid.NewString(), "-", ""))
	goodSite := makeVerifiedSite("warning-good-" + strings.ReplaceAll(uuid.NewString(), "-", ""))
	for i := 0; i < 22; i++ {
		if _, err := admin.Exec(ctx, `INSERT INTO public.rules(id,tenant_id,site_id,priority,expression,action,mode) VALUES($1,$2,$3,$4,'true == true','block','enforce')`, uuid.New(), tenantID, overQuotaSite.ID, i); err != nil {
			t.Fatal(err)
		}
	}
	const secretReference = "warning-secret-reference"
	if _, err := admin.Exec(ctx, `UPDATE public.bot_settings SET settings=jsonb_set(settings,'{additional_secrets}','{"tls":"`+secretReference+`"}'::jsonb) WHERE site_id=$1 AND tenant_id=$2`, badModeSite.ID, tenantID); err != nil {
		t.Fatal(err)
	}

	repository := snapshot.PostgresRepository{Pool: worker}
	objects := snapshot.FileObjects{Root: t.TempDir()}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := secret.NewMemory()
	const kid = "warning-test-kid"
	if err = store.Put(ctx, "snapshot-signing/"+kid, privateKey); err != nil {
		t.Fatal(err)
	}
	region := "warn-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DELETE FROM public.config_snapshots WHERE scope=$1`, region)
	})
	type warningSiteIDs struct{ badRule, badMode, badOrigin string }
	ids := warningSiteIDs{badRuleSite.ID.String(), badModeSite.ID.String(), badOriginSite.ID.String()}
	var warningWriteErrors []error
	builder := &snapshot.Builder{Repository: repository, Objects: objects, Signer: snapshot.SecretSigner{Store: store, KeyID: kid}, PublicKeys: map[string]ed25519.PublicKey{kid: publicKey}, OnWarning: func(w snapshot.Warning) {
		if w.SiteID == "" {
			return
		}
		if warnErr := repository.WarnSite(ctx, w.SiteID, w.Message); warnErr != nil {
			warningWriteErrors = append(warningWriteErrors, warnErr)
		}
	}}
	first, err := builder.Build(ctx, region)
	if err != nil {
		t.Fatalf("initial snapshot build: %v", err)
	}
	oldSnapshot, err := wafcore.VerifySnapshot(first.Signed, builder.PublicKeys)
	if err != nil {
		t.Fatal(err)
	}
	oldByID := make(map[string]wafcore.Site, len(oldSnapshot.Sites))
	for _, oldSite := range oldSnapshot.Sites {
		oldByID[oldSite.ID] = oldSite
	}
	for _, fixtureSite := range []site.Site{badRuleSite, badModeSite, badOriginSite, overQuotaSite, goodSite} {
		if _, ok := oldByID[fixtureSite.ID.String()]; !ok {
			t.Fatalf("valid baseline site %s was not included before introducing invalid config", fixtureSite.ID)
		}
	}
	if _, err = admin.Exec(ctx, `INSERT INTO public.rules(id,tenant_id,site_id,expression,action,mode) VALUES($1,$2,$3,'invalid rule expression','block','enforce')`, uuid.New(), tenantID, badRuleSite.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `UPDATE public.origins SET url='://invalid-origin' WHERE site_id=$1 AND tenant_id=$2`, badOriginSite.ID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `UPDATE public.bot_settings SET settings=jsonb_set(settings,'{mode}','"unknown-bot-mode"'::jsonb) WHERE site_id=$1 AND tenant_id=$2`, badModeSite.ID, tenantID); err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ {
		record, buildErr := builder.Build(ctx, region)
		if buildErr != nil {
			t.Fatalf("site-local warning build %d failed region-wide: %v", run, buildErr)
		}
		built, verifyErr := wafcore.VerifySnapshot(record.Signed, builder.PublicKeys)
		if verifyErr != nil {
			t.Fatal(verifyErr)
		}
		byID := make(map[string]wafcore.Site, len(built.Sites))
		for _, actual := range built.Sites {
			byID[actual.ID] = actual
		}
		for _, siteID := range []string{ids.badRule, ids.badMode, ids.badOrigin} {
			oldSite, oldOK := oldByID[siteID]
			actual, actualOK := byID[siteID]
			if !oldOK || !actualOK || !reflect.DeepEqual(actual, oldSite) {
				t.Fatalf("site %s was not retained from last-good after invalid config: present=%v snapshot=%+v", siteID, actualOK, actual)
			}
		}
		if _, ok := byID[goodSite.ID.String()]; !ok {
			t.Fatalf("unaffected site %s was lost", goodSite.ID)
		}
		if len(byID[overQuotaSite.ID.String()].Rules) != 20 {
			t.Fatalf("Pro over-quota rules were not capped: got %d, want 20", len(byID[overQuotaSite.ID.String()].Rules))
		}
	}
	failedWarnCtx, cancelWarnings := context.WithCancel(ctx)
	cancelWarnings()
	var forcedWarningError error
	failedSinkBuilder := *builder
	failedSinkBuilder.OnWarning = func(w snapshot.Warning) {
		if w.SiteID != "" {
			forcedWarningError = repository.WarnSite(failedWarnCtx, w.SiteID, w.Message)
		}
	}
	if _, err = failedSinkBuilder.Build(ctx, region); err != nil {
		t.Fatalf("warning sink failure poisoned the region snapshot: %v", err)
	}
	if forcedWarningError == nil {
		t.Fatal("expected the canceled warning write to fail")
	}
	if len(warningWriteErrors) != 0 {
		t.Fatalf("persist site warnings: %v", warningWriteErrors)
	}
	for _, siteID := range []string{ids.badRule, ids.badMode, ids.badOrigin} {
		var count int
		var actualTenant, details string
		if err = admin.QueryRow(ctx, `SELECT count(*),min(tenant_id)::text,min(details::text) FROM public.alerts WHERE tenant_id=$1 AND status='open' AND details->>'kind'='snapshot_site_invalid' AND details->>'site_id'=$2`, tenantID, siteID).Scan(&count, &actualTenant, &details); err != nil {
			t.Fatal(err)
		}
		if count != 1 || actualTenant != tenantID.String() || !strings.Contains(details, siteID) || strings.Contains(details, secretReference) {
			t.Fatalf("site warning count=%d tenant=%q details=%q", count, actualTenant, details)
		}
	}
	var alertCount int
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.alerts WHERE tenant_id=$1 AND status='open' AND details->>'kind'='snapshot_site_invalid'`, tenantID).Scan(&alertCount); err != nil || alertCount != 3 {
		t.Fatalf("site warning count=%d err=%v, want exactly 3 distinct invalid sites", alertCount, err)
	}
}

func TestSnapshotConcurrentReservationsAreGlobalAndStalePublishIsRejectedIntegration(t *testing.T) {
	ctx, admin, redisClient := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, redisClient)
	worker := workerRolePool(t, ctx, admin, os.Getenv("DATABASE_URL"), cleanup)
	region := "version-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DELETE FROM public.config_snapshots WHERE scope=$1`, region)
	})
	repository := snapshot.PostgresRepository{Pool: worker}
	start := make(chan struct{})
	versions := make(chan uint64, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, err := repository.Reserve(ctx, region)
			versions <- v
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(versions)
	close(errs)
	var got []uint64
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for version := range versions {
		got = append(got, version)
	}
	if len(got) != 2 || got[0] == got[1] || got[0] == 0 || got[1] == 0 {
		t.Fatalf("global snapshot versions not unique: %v", got)
	}
	if got[0] > got[1] {
		got[0], got[1] = got[1], got[0]
	}
	for _, version := range got {
		_, err := repository.Publish(ctx, region, snapshot.Record{Version: version, Checksum: strings.Repeat("a", 64), Signature: []byte{}, ObjectKey: "unused"})
		if version == got[0] && err != nil {
			t.Fatalf("publish first version: %v", err)
		}
		if version == got[1] && err != nil {
			t.Fatalf("publish second increasing version: %v", err)
		}
	}
	var activeVersion uint64
	if err := admin.QueryRow(ctx, `SELECT version FROM public.config_snapshots WHERE scope=$1 AND rollout_state='active'`, region).Scan(&activeVersion); err != nil || activeVersion != got[1] {
		t.Fatalf("latest active version=%d err=%v, want %d", activeVersion, err, got[1])
	}
	_, err := repository.Publish(ctx, region, snapshot.Record{Version: got[0], Checksum: strings.Repeat("b", 64), ObjectKey: "stale"})
	if !errors.Is(err, snapshot.ErrStaleBuild) {
		t.Fatalf("lower out-of-order publish err=%v, want ErrStaleBuild", err)
	}
}

func testEdgeClientCertificate(t *testing.T, commonName string, notBefore, notAfter time.Time) (*x509.CertPool, tls.Certificate, string, error) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, "", err
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "snapshot integration test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, "", err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, tls.Certificate{}, "", err
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, tls.Certificate{}, "", err
	}
	clientTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{commonName}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, "", err
	}
	clientCert, err := x509.ParseCertificate(clientDER)
	if err != nil {
		return nil, tls.Certificate{}, "", err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{clientDER, caDER}, PrivateKey: clientKey, Leaf: clientCert}, strings.ToLower(serial.Text(16)), nil
}

func jsonNumber(value uint64) string { return strconv.FormatUint(value, 10) }

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	if cert == nil {
		return false
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == want {
			return true
		}
	}
	return false
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
