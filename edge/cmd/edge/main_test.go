package main

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSampleYAMLSnapshotNeedsExplicitDevelopmentFlag(t *testing.T) {
	path := filepath.Join("..", "..", "..", "test", "fixtures", "snapshot.sample.yaml")
	t.Setenv("EDGE_ENV", "development")
	t.Setenv("EDGE_DEV_UNSIGNED", "")
	t.Setenv("EDGE_SNAPSHOT_FILE", path)
	if _, err := loadSnapshot(); err == nil {
		t.Fatal("unsigned fixture accepted without opt-in")
	}
	t.Setenv("EDGE_DEV_UNSIGNED", "1")
	snapshot, err := loadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != 1842 || len(snapshot.Sites) != 1 || snapshot.Sites[0].ID != "site_001" {
		t.Fatalf("unexpected sample snapshot: %#v", snapshot)
	}
}

func TestLoadChallengeKeyringRequiresStrongAndSelectableKeys(t *testing.T) {
	t.Setenv("EDGE_CHALLENGE_HMAC_KEYS", "")
	t.Setenv("EDGE_CHALLENGE_HMAC_ACTIVE_KEY_ID", "")
	if keyring, err := loadChallengeKeyring(); err != nil || keyring != nil {
		t.Fatalf("empty keyring=%v err=%v", keyring, err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	t.Setenv("EDGE_CHALLENGE_HMAC_KEYS", "v1="+encoded+",v2="+encoded)
	t.Setenv("EDGE_CHALLENGE_HMAC_ACTIVE_KEY_ID", "v2")
	keyring, err := loadChallengeKeyring()
	if err != nil {
		t.Fatal(err)
	}
	if keyring.ActiveKeyID() != "v2" {
		t.Fatalf("active key id=%q", keyring.ActiveKeyID())
	}
	if _, ok := keyring.Key("v1"); !ok {
		t.Fatal("old key was not retained for cookie verification")
	}
	t.Setenv("EDGE_CHALLENGE_HMAC_ACTIVE_KEY_ID", "missing")
	if _, err = loadChallengeKeyring(); err == nil {
		t.Fatal("missing active key accepted")
	}
	t.Setenv("EDGE_CHALLENGE_HMAC_KEYS", "short="+base64.StdEncoding.EncodeToString([]byte("short")))
	t.Setenv("EDGE_CHALLENGE_HMAC_ACTIVE_KEY_ID", "short")
	if _, err = loadChallengeKeyring(); err == nil {
		t.Fatal("weak key accepted")
	}
}
