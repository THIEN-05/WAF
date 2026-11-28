package configsync

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/example/wafplatform/pkg/wafcore"
)

func TestAgentRejectsReplayAndAcceptsRollbackAtNewVersion(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := testSnapshot()
	base.Version = 40
	oldSigned, err := wafcore.SignSnapshot(base, "old", oldPriv)
	if err != nil {
		t.Fatal(err)
	}
	installer := &testInstaller{}
	agent, err := NewAgent(&fakeCP{}, nil, installer, nil, AgentConfig{PublicKeys: map[string]ed25519.PublicKey{"old": oldPub, "new": newPub}})
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ApplySnapshot(oldSigned, `"v40"`); err != nil {
		t.Fatal(err)
	}

	// Rollback restores old content under a fresh, globally increasing version.
	rollback := base
	rollback.Version = 41
	rollbackSigned, err := wafcore.SignSnapshot(rollback, "new", newPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ApplySnapshot(rollbackSigned, `"v41"`); err != nil {
		t.Fatalf("rollback content with a newer version was rejected: %v", err)
	}
	if installer.current != 41 || agent.Status().Version != 41 {
		t.Fatalf("rollback applied version=%d status=%+v, want 41", installer.current, agent.Status())
	}

	if err = agent.ApplySnapshot(oldSigned, `"replay"`); err == nil {
		t.Fatal("lower-version replay was accepted")
	}
	unknown := rollback
	unknown.Version = 42
	unknownSigned, err := wafcore.SignSnapshot(unknown, "unknown", unknownPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ApplySnapshot(unknownSigned, `"unknown"`); err == nil {
		t.Fatal("snapshot signed with an unknown kid was accepted")
	}
	if installer.current != 41 || agent.Status().Version != 41 {
		t.Fatalf("rejected snapshot changed active version: installed=%d status=%+v", installer.current, agent.Status())
	}
}
