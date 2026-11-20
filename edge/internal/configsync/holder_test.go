package configsync

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
)

func testSnapshot() wafcore.Snapshot {
	return wafcore.Snapshot{SchemaVersion: 1, Version: 1, GeneratedAt: time.Now().UTC(), Global: wafcore.GlobalConfig{ManagedRuleset: "test"}}
}
func TestUnsignedRequiresDevFlagAndRejectsProduction(t *testing.T) {
	raw, _ := json.Marshal(testSnapshot())
	h := New(nil, "")
	t.Setenv("EDGE_DEV_UNSIGNED", "")
	t.Setenv("EDGE_ENV", "development")
	if err := h.ApplyUnsignedLocalJSON(raw); err == nil {
		t.Fatal("accepted unsigned snapshot without flag")
	}
	t.Setenv("EDGE_DEV_UNSIGNED", "1")
	if err := h.ApplyUnsignedLocalJSON(raw); err != nil {
		t.Fatalf("dev unsigned apply: %v", err)
	}
	t.Setenv("EDGE_ENV", "production")
	if err := h.ApplyUnsignedLocalJSON(raw); err == nil {
		t.Fatal("accepted unsigned snapshot in production")
	}
}
func TestLoadPublicKeysFromEnvAndFile(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	entry := "rotated=" + base64.StdEncoding.EncodeToString(pub)
	t.Setenv("EDGE_ENV", "production")
	t.Setenv("EDGE_PUBLIC_KEYS", entry)
	t.Setenv("EDGE_PUBLIC_KEYS_FILE", "")
	keys, err := LoadPublicKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("env keyring: keys=%d err=%v", len(keys), err)
	}
	path := filepath.Join(t.TempDir(), "keys.txt")
	if err = os.WriteFile(path, []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDGE_PUBLIC_KEYS", "")
	t.Setenv("EDGE_PUBLIC_KEYS_FILE", path)
	keys, err = LoadPublicKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("file keyring: keys=%d err=%v", len(keys), err)
	}
}
func TestProductionRequiresKeys(t *testing.T) {
	t.Setenv("EDGE_ENV", "production")
	t.Setenv("EDGE_PUBLIC_KEYS", "")
	t.Setenv("EDGE_PUBLIC_KEYS_FILE", "")
	if _, err := LoadPublicKeys(); err == nil {
		t.Fatal("production accepted empty keyring")
	}
}
func TestApplySignedSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, err := wafcore.SignSnapshot(testSnapshot(), "k", priv)
	if err != nil {
		t.Fatal(err)
	}
	h := New(map[string]ed25519.PublicKey{"k": pub}, filepath.Join(t.TempDir(), "last-good.json"))
	if err = h.Apply(raw); err != nil {
		t.Fatal(err)
	}
	if h.Load() == nil || h.Load().Version != 1 {
		t.Fatal("snapshot not applied")
	}
}
