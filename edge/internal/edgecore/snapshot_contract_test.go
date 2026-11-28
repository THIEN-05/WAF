package edgecore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	cpSnapshot "github.com/example/wafplatform/controlplane/snapshot"
	"github.com/example/wafplatform/pkg/wafcore"
)

type contractRepo struct {
	candidates []cpSnapshot.Candidate
	version    uint64
	latest     cpSnapshot.Record
}

func (r *contractRepo) LoadRegion(context.Context, string) ([]cpSnapshot.Candidate, error) {
	return r.candidates, nil
}
func (r *contractRepo) Latest(context.Context, string) (cpSnapshot.Record, error) {
	if r.latest.Version == 0 {
		return cpSnapshot.Record{}, cpSnapshot.ErrNoSnapshot
	}
	return r.latest, nil
}
func (r *contractRepo) Reserve(context.Context, string) (uint64, error) {
	r.version++
	return r.version, nil
}
func (r *contractRepo) Publish(_ context.Context, _ string, record cpSnapshot.Record) ([]string, error) {
	r.latest = record
	return nil, nil
}
func (r *contractRepo) Fail(context.Context, string, uint64) error { return nil }

type contractObjects struct{ objects map[string][]byte }

func (o *contractObjects) Get(_ context.Context, key string) ([]byte, error) {
	return o.objects[key], nil
}
func (o *contractObjects) Put(_ context.Context, key string, value []byte) error {
	o.objects[key] = append([]byte(nil), value...)
	return nil
}
func (o *contractObjects) Delete(_ context.Context, key string) error {
	delete(o.objects, key)
	return nil
}

type contractSigner struct{ key ed25519.PrivateKey }

func (s contractSigner) Sign(_ context.Context, snapshot wafcore.Snapshot) ([]byte, error) {
	return wafcore.SignSnapshot(snapshot, "contract", s.key)
}

func TestControlPlaneSnapshotLoadsIntoRealEdge(t *testing.T) {
	started := time.Now()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	site := wafcore.Site{ID: "01900000-0000-7000-8000-000000000001", TenantID: "01900000-0000-7000-8000-000000000002", Status: "active", Plan: "free", Domains: []string{"contract.example.test"}, Origins: []wafcore.Origin{{URL: "http://203.0.113.25:8080", Weight: 1, HostHeader: "contract.example.test", TLSVerify: true}}, FailMode: "open", WAF: wafcore.WAFConfig{Mode: "monitor", Sensitivity: "medium", BodyLimitKB: 8}, Rules: []wafcore.Rule{{ID: "allow-contract", Expression: "true == true", Action: "log"}}}
	repo := &contractRepo{version: 1, candidates: []cpSnapshot.Candidate{{Site: site, ManagedRuleset: "managed-contract-v1"}}}
	objects := &contractObjects{objects: map[string][]byte{}}
	builder := cpSnapshot.Builder{Repository: repo, Objects: objects, Signer: contractSigner{key: private}, PublicKeys: map[string]ed25519.PublicKey{"contract": public}, Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	record, err := builder.Build(context.Background(), "contract")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := wafcore.VerifySnapshot(record.Signed, builder.PublicKeys)
	if err != nil {
		t.Fatal(err)
	}
	edge := New(nil, "contract-edge")
	defer edge.Close()
	if err = edge.Apply(&decoded); err != nil {
		t.Fatalf("edge rejected control-plane snapshot: %v", err)
	}
	t.Logf("snapshot build-to-edge-apply elapsed=%s", time.Since(started))
	if err = edge.SelfTest(); err != nil {
		t.Fatalf("edge pipeline self-test failed after snapshot apply: %v", err)
	}
	active := edge.Snapshot()
	if active.Version != record.Version || active.Sites[0].ID != site.ID {
		t.Fatalf("edge active snapshot=%+v, built record=%+v", active, record)
	}
	logEvent := wafcore.LogEvent{SchemaVersion: wafcore.LogSchemaVersion, TS: time.Now().UTC(), RequestID: "contract", SiteID: site.ID, TenantID: site.TenantID, EdgeID: "contract-edge", Region: "contract"}
	if err := logEvent.Validate(); err != nil {
		t.Fatalf("shared log schema validation: %v", err)
	}
	if raw, marshalErr := json.Marshal(logEvent); marshalErr != nil || len(raw) == 0 {
		t.Fatalf("shared log contract serialization err=%v", marshalErr)
	}
}
