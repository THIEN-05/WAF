package snapshot

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileObjectsAtomicRoundTripAndRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	store := FileObjects{Root: root}
	key := "snapshots/region/3.json.gz"
	want := []byte("signed object")
	if err := store.Put(context.Background(), key, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), key)
	if err != nil || string(got) != string(want) {
		t.Fatalf("Get()=%q, %v; want %q", got, err, want)
	}
	if err = store.Put(context.Background(), "../escape", want); err == nil {
		t.Fatal("Put accepted traversal key")
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(root), "escape")); !os.IsNotExist(err) {
		t.Fatalf("object escaped root: stat err=%v", err)
	}
	if err = store.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Get(context.Background(), key); !os.IsNotExist(err) {
		t.Fatalf("Get after Delete err=%v, want not-exist", err)
	}
}
