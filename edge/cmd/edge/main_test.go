package main

import (
	"path/filepath"
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
