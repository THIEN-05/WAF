package snapshot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
)

type memoryObjects struct{ values map[string][]byte }

func (m *memoryObjects) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := m.values[key]
	if !ok {
		return nil, errors.New("missing object")
	}
	return append([]byte(nil), v...), nil
}
func (m *memoryObjects) Put(_ context.Context, key string, v []byte) error {
	m.values[key] = append([]byte(nil), v...)
	return nil
}
func (m *memoryObjects) Delete(_ context.Context, key string) error {
	delete(m.values, key)
	return nil
}

type memoryRepository struct {
	candidates []Candidate
	latest     Record
	reserved   uint64
	published  []Record
	failed     []uint64
}

func (m *memoryRepository) LoadRegion(context.Context, string) ([]Candidate, error) {
	return m.candidates, nil
}
func (m *memoryRepository) Latest(context.Context, string) (Record, error) {
	if m.latest.Version == 0 {
		return Record{}, ErrNoSnapshot
	}
	return m.latest, nil
}
func (m *memoryRepository) Reserve(context.Context, string) (uint64, error) {
	m.reserved++
	return m.reserved, nil
}
func (m *memoryRepository) Publish(_ context.Context, _ string, r Record) ([]string, error) {
	m.latest = r
	m.published = append(m.published, r)
	return nil, nil
}
func (m *memoryRepository) Fail(_ context.Context, _ string, v uint64) error {
	m.failed = append(m.failed, v)
	return nil
}

func testSite(id string) wafcore.Site {
	return wafcore.Site{ID: id, TenantID: "tenant", Status: "active", Plan: "enterprise", Domains: []string{"example.test"}, Origins: []wafcore.Origin{{URL: "https://origin.example", Weight: 1, TLSVerify: true}}, FailMode: "open", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "medium", BodyLimitKB: 64}, Rules: []wafcore.Rule{}, RateLimits: []wafcore.RateLimit{}}
}

func TestBuilderCapsEntitlementsAndKeepsOnlyBrokenSitesFromLastGood(t *testing.T) {
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := wafcore.Snapshot{SchemaVersion: wafcore.SnapshotSchemaVersion, Version: 1, GeneratedAt: time.Unix(100, 0).UTC(), Global: wafcore.GlobalConfig{ManagedRuleset: "managed-v1"}, Sites: []wafcore.Site{testSite("broken")}}
	oldSigned, err := wafcore.SignSnapshot(old, "test", private)
	if err != nil {
		t.Fatal(err)
	}
	objects := &memoryObjects{values: map[string][]byte{"snapshots/us-east/1.json.gz": oldSigned}}
	repo := &memoryRepository{reserved: 1, latest: Record{Version: 1, ObjectKey: "snapshots/us-east/1.json.gz"}, candidates: []Candidate{
		{Site: wafcore.Site{ID: "good", TenantID: "tenant", Status: "active", Plan: "free", Domains: []string{"good.test"}, Origins: []wafcore.Origin{{URL: "https://origin.example", Weight: 1, TLSVerify: true}}, FailMode: "open", WAF: wafcore.WAFConfig{Mode: "block", Sensitivity: "medium", BodyLimitKB: 64}, Entitlements: wafcore.Entitlements{MaxRules: 1, MaxRateLimitPolicies: 1, MaxBodyBytes: 8 * 1024}, Rules: []wafcore.Rule{{ID: "r1", Expression: "true == true", Action: "log"}, {ID: "r2", Expression: "true == true", Action: "block"}}, RateLimits: []wafcore.RateLimit{{ID: "rl1", Match: "true == true", Key: "ip", Limit: 1, WindowS: 1, Action: "block"}, {ID: "rl2", Match: "true == true", Key: "ip", Limit: 2, WindowS: 1, Action: "block"}}}},
		{Site: wafcore.Site{ID: "broken"}, Err: errors.New("site-local source failure")},
	}}
	warnings := 0
	builder := Builder{Repository: repo, Objects: objects, Signer: SecretSigner{Store: newTestKeyStore(t, private), KeyID: "test"}, PublicKeys: map[string]ed25519.PublicKey{"test": public}, Now: func() time.Time { return time.Unix(200, 0) }, OnWarning: func(Warning) { warnings++ }}
	record, err := builder.Build(ctx, "us-east")
	if err != nil {
		t.Fatal(err)
	}
	got, err := wafcore.VerifySnapshot(record.Signed, builder.PublicKeys)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.GeneratedAt.Unix() != 200 || warnings != 1 {
		t.Fatalf("snapshot metadata version=%d generated=%v warnings=%d", got.Version, got.GeneratedAt, warnings)
	}
	if len(got.Sites) != 2 || got.Sites[0].ID != "good" || got.Sites[1].ID != "broken" {
		t.Fatalf("site isolation result: %#v", got.Sites)
	}
	if len(got.Sites[0].Rules) != 1 || len(got.Sites[0].RateLimits) != 1 || got.Sites[0].WAF.BodyLimitKB != 8 {
		t.Fatalf("entitlement caps not applied: %#v", got.Sites[0])
	}
	if got.Sites[1].ID != "broken" {
		t.Fatal("failed site was not preserved from last-good snapshot")
	}
	if record.ObjectKey != "snapshots/us-east/2.json.gz" || len(repo.published) != 1 || repo.latest.Version != 2 {
		t.Fatalf("publish metadata mismatch: %#v", record)
	}
}

func TestEntitlementCapsOnlyPublishChallengeKeyReferenceWhenEntitled(t *testing.T) {
	free := testSite("free")
	free.Bot.Mode = "challenge"
	free.Secrets.ChallengeHMACKeyID = "free-key-reference"
	applyEntitlementCaps(&free)
	if free.Secrets.ChallengeHMACKeyID != "" || free.Bot.Mode != "monitor" {
		t.Fatalf("Free entitlement retained unavailable challenge config: %+v", free)
	}

	pro := testSite("pro")
	pro.Entitlements.BotJSChallenge = true
	pro.Bot.Mode = "monitor"
	pro.Secrets.ChallengeHMACKeyID = "pro-key-reference"
	applyEntitlementCaps(&pro)
	if pro.Secrets.ChallengeHMACKeyID != "pro-key-reference" {
		t.Fatalf("entitled Pro snapshot lost challenge key reference: %+v", pro.Secrets)
	}
}

type keyStore struct{ key []byte }

func (k keyStore) Get(context.Context, string) ([]byte, error) {
	return append([]byte(nil), k.key...), nil
}
func (k keyStore) Put(context.Context, string, []byte) error { return nil }
func (k keyStore) Delete(context.Context, string) error      { return nil }
func newTestKeyStore(_ *testing.T, key ed25519.PrivateKey) keyStore {
	return keyStore{key: append([]byte(nil), key...)}
}

func TestBuilderCompileFailureIsSiteScoped(t *testing.T) {
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repo := &memoryRepository{candidates: []Candidate{
		{Site: testSite("ok")},
		{Site: func() wafcore.Site {
			s := testSite("bad")
			s.Rules = []wafcore.Rule{{ID: "bad-rule", Expression: "this is not dsl", Action: "block"}}
			return s
		}()},
	}}
	objects := &memoryObjects{values: map[string][]byte{}}
	builder := Builder{Repository: repo, Objects: objects, Signer: SecretSigner{Store: keyStore{key: private}, KeyID: "k"}, PublicKeys: map[string]ed25519.PublicKey{"k": public}}
	got, err := builder.Build(ctx, "eu")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := wafcore.VerifySnapshot(got.Signed, builder.PublicKeys)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Sites) != 1 || snapshot.Sites[0].ID != "ok" {
		t.Fatalf("site-local compile error poisoned region: %#v", snapshot.Sites)
	}
	if len(repo.failed) != 0 {
		t.Fatalf("per-site compile error failed entire snapshot: %v", repo.failed)
	}
}

type fakeLatest struct {
	record Record
	err    error
}

func (f fakeLatest) LoadRegion(context.Context, string) ([]Candidate, error)   { return nil, nil }
func (f fakeLatest) Latest(context.Context, string) (Record, error)            { return f.record, f.err }
func (f fakeLatest) Reserve(context.Context, string) (uint64, error)           { return 0, nil }
func (f fakeLatest) Publish(context.Context, string, Record) ([]string, error) { return nil, nil }
func (f fakeLatest) Fail(context.Context, string, uint64) error                { return nil }

type fakeEdgeResolver struct{}

func (fakeEdgeResolver) ResolveEdge(context.Context, *x509.Certificate) (string, string, error) {
	return "edge-1", "region", nil
}

func TestEdgeHandlerRequiresVerifiedMTLSAndSupportsSince(t *testing.T) {
	objects := &memoryObjects{values: map[string][]byte{"snapshots/region/5.json.gz": []byte(`{"signed":true}`)}}
	h := EdgeHandler{Repository: fakeLatest{record: Record{Version: 5, Checksum: "abc", ObjectKey: "snapshots/region/5.json.gz"}}, Objects: objects, Resolver: fakeEdgeResolver{}}
	req := httptest.NewRequest(http.MethodGet, "/internal/snapshot?edge_id=edge-1&since=4", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without mTLS status=%d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/internal/snapshot?edge_id=edge-1&since=4", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "edge-1"}}}, VerifiedChains: [][]*x509.Certificate{{{}}}}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") != `"abc"` || rec.Body.String() != `{"signed":true}` {
		t.Fatalf("snapshot response status=%d headers=%v body=%q", rec.Code, rec.Header(), rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/internal/snapshot?edge_id=edge-1&since=5", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "edge-1"}}}, VerifiedChains: [][]*x509.Certificate{{{}}}}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("current version response status=%d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/internal/snapshot?edge_id=edge-1&since=4", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "different-edge"}}}, VerifiedChains: [][]*x509.Certificate{{{}}}}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("certificate identity mismatch status=%d, want 403", rec.Code)
	}
}

func TestRunDebouncedCoalescesConfigurationChanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	triggers := make(chan struct{}, 4)
	var builds atomic.Int32
	for range 3 {
		triggers <- struct{}{}
	}
	done := make(chan error, 1)
	go func() {
		done <- RunDebounced(ctx, triggers, 10*time.Millisecond, func(context.Context) error {
			builds.Add(1)
			return nil
		}, nil)
	}()
	time.Sleep(40 * time.Millisecond)
	close(triggers)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("debounced builds=%d, want 1", got)
	}
}
