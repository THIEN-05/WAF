package snapshot

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// FileObjects is a local development/test object store. Production object storage
// must implement Objects with the configured S3-compatible service.
type FileObjects struct{ Root string }

func (f FileObjects) openRoot() (*os.Root, error) {
	if f.Root == "" {
		return nil, fmt.Errorf("object store root is required")
	}
	return os.OpenRoot(f.Root)
}

func objectPath(key string) (string, error) {
	if key == "" || strings.Contains(key, "\\") || !fs.ValidPath(key) {
		return "", fmt.Errorf("invalid relative object key")
	}
	return filepath.FromSlash(key), nil
}

func (f FileObjects) Put(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rel, err := objectPath(key)
	if err != nil {
		return err
	}
	root, err := f.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err = root.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
		return err
	}
	tmpRel := filepath.Join(filepath.Dir(rel), ".snapshot-"+randomSuffix()+".tmp")
	tmp, err := root.OpenFile(tmpRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmpRel) }()
	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// Both names are built from a validated fs.ValidPath key under the configured
	// local development root; os.Rename supplies the atomic replace semantics on
	// Windows where Root.Rename is not supported by all filesystem providers.
	if err = os.Rename(filepath.Join(f.Root, tmpRel), filepath.Join(f.Root, rel)); err != nil {
		return err
	}
	return nil
}

func (f FileObjects) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rel, err := objectPath(key)
	if err != nil {
		return nil, err
	}
	root, err := f.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(rel)
}

func (f FileObjects) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rel, err := objectPath(key)
	if err != nil {
		return err
	}
	root, err := f.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err = root.Remove(rel); err != nil && err != fs.ErrNotExist {
		return err
	}
	return nil
}

func randomSuffix() string {
	return uuid.NewString()
}
