package referencedata

import (
	"context"
	"strings"
	"testing"
)

type fetchStub struct{ raw []byte }

func (f fetchStub) Fetch(context.Context, Source) ([]byte, error) {
	return append([]byte(nil), f.raw...), nil
}

type repoStub struct {
	active    Document
	published int
}

func (r *repoStub) Active(context.Context, Kind) (Document, error) {
	if r.active.Version == "" {
		return Document{}, ErrNoActiveVersion
	}
	return r.active, nil
}
func (r *repoStub) Publish(_ context.Context, _ Kind, d Document) error {
	r.active = d
	r.published++
	return nil
}

type snapshotStub struct{ calls int }

func (s *snapshotStub) PublishReference(context.Context, Kind, string, []byte) error {
	s.calls++
	return nil
}

type warningsStub struct{ calls int }

func (w *warningsStub) Warn(context.Context, Source, string) { w.calls++ }

func TestBlocklistNormalizerCanonicalizesAndDeduplicatesCIDRs(t *testing.T) {
	got, count, err := (BlocklistNormalizer{}).Normalize(context.Background(), Blocklist, []byte("# feed\n192.0.2.9/24\n192.0.2.0/24\n2001:db8::1/64\n"))
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || string(got) != "192.0.2.0/24\n2001:db8::/64\n" {
		t.Fatalf("normalized=%q count=%d", got, count)
	}
}

func TestUpdaterRejectsUnlicensedSourceAndKeepsActiveOnAnomaly(t *testing.T) {
	repo := &repoStub{active: Document{Version: "old", Bytes: []byte("192.0.2.0/24\n198.51.100.0/24\n203.0.113.0/24\n")}}
	snapshot := &snapshotStub{}
	warnings := &warningsStub{}
	updater := Updater{Fetcher: fetchStub{raw: []byte("192.0.2.0/24\n")}, Repository: repo, Publisher: snapshot, Warnings: warnings, Validator: CompositeNormalizer{}, MaxChangeRatio: .5}
	source := Source{Name: "test", Kind: Blocklist, URL: "https://feed.example.test/block.txt", LicenseName: "test license", LicenseURL: "https://feed.example.test/license", RedistributionAllowed: false}
	if _, err := updater.Update(context.Background(), source); err == nil {
		t.Fatal("unlicensed redistribution accepted")
	}
	source.RedistributionAllowed = true
	if _, err := updater.Update(context.Background(), source); err == nil || !strings.Contains(err.Error(), "active version retained") {
		t.Fatalf("large feed change error=%v", err)
	}
	if repo.published != 0 || snapshot.calls != 0 || warnings.calls != 1 || repo.active.Version != "old" {
		t.Fatalf("unsafe update changed active state: repo=%+v publisher=%d warnings=%d", repo, snapshot.calls, warnings.calls)
	}
}

func TestManagedRulesNormalizerChecksSyntaxAndDuplicateIDs(t *testing.T) {
	good := []byte("- id: rule-1\n  phase: request\n  targets: [args]\n  transforms: [lowercase]\n  pattern: 'select\\s+.*'\n  severity: warning\n  paranoia: 1\n  tags: [owasp-a03]\n  prefilter: [select]\n")
	if _, n, err := (ManagedRulesNormalizer{}).Normalize(context.Background(), ManagedRules, good); err != nil || n != 1 {
		t.Fatalf("valid managed rule count=%d err=%v", n, err)
	}
	bad := []byte("- id: duplicate\n  phase: request\n  targets: [args]\n  pattern: '['\n  severity: error\n  paranoia: 1\n  tags: [owasp-a03]\n- id: duplicate\n  phase: request\n  targets: [args]\n  pattern: 'ok'\n  severity: error\n  paranoia: 1\n  tags: [owasp-a03]\n")
	if _, _, err := (ManagedRulesNormalizer{}).Normalize(context.Background(), ManagedRules, bad); err == nil {
		t.Fatal("invalid/duplicate managed rules accepted")
	}
}
