package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfiguredCAUsesAbsoluteRootedPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client-ca.pem")
	want := []byte("test certificate data")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readConfiguredCA(path, "INGEST_CLIENT_CA_FILE")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("CA contents=%q, want %q", got, want)
	}
}

func TestReadConfiguredCARejectsRelativePath(t *testing.T) {
	if _, err := readConfiguredCA(filepath.Join("relative", "client-ca.pem"), "INGEST_CLIENT_CA_FILE"); err == nil {
		t.Fatal("relative CA path was accepted")
	}
}
