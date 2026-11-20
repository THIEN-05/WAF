package configsync

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/example/wafplatform/pkg/wafcore"
)

type Holder struct {
	ptr      atomic.Pointer[wafcore.Snapshot]
	keys     map[string]ed25519.PublicKey
	lastGood string
}

func New(keys map[string]ed25519.PublicKey, lastGood string) *Holder {
	return &Holder{keys: keys, lastGood: lastGood}
}
func (h *Holder) Load() *wafcore.Snapshot { return h.ptr.Load() }
func (h *Holder) Apply(raw []byte) error {
	s, err := wafcore.VerifySnapshot(raw, h.keys)
	if err != nil {
		return err
	}
	if h.lastGood != "" {
		if err = persist(h.lastGood, raw); err != nil {
			return fmt.Errorf("persist last-known-good: %w", err)
		}
	}
	h.ptr.Store(&s)
	return nil
}
func (h *Holder) LoadLocal(path string) error {
	cleanPath := filepath.Clean(path)
	raw, err := os.ReadFile(cleanPath) //nolint:gosec // path comes from operator configuration, not request input
	if err != nil && h.lastGood != "" {
		raw, err = os.ReadFile(filepath.Clean(h.lastGood)) //nolint:gosec // path comes from operator configuration, not request input
	}
	if err != nil {
		return err
	}
	return h.Apply(raw)
}
func (h *Holder) ApplyUnsignedLocalJSON(raw []byte) error { // Local dev snapshots may be unsigned; production must use Apply.
	if strings.EqualFold(os.Getenv("EDGE_ENV"), "production") {
		return fmt.Errorf("unsigned local snapshots are forbidden in production")
	}
	if os.Getenv("EDGE_DEV_UNSIGNED") != "1" {
		return fmt.Errorf("unsigned local snapshots require EDGE_DEV_UNSIGNED=1")
	}
	var s wafcore.Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return err
	}
	if h.lastGood != "" {
		if err := persist(h.lastGood, raw); err != nil {
			return err
		}
	}
	h.ptr.Store(&s)
	return nil
}

// LoadPublicKeys loads a keyring from EDGE_PUBLIC_KEYS (kid=base64,kid=base64)
// or EDGE_PUBLIC_KEYS_FILE (one kid=base64 entry per line). Production must provide one.
func LoadPublicKeys() (map[string]ed25519.PublicKey, error) {
	data := os.Getenv("EDGE_PUBLIC_KEYS")
	if file := os.Getenv("EDGE_PUBLIC_KEYS_FILE"); file != "" {
		b, err := os.ReadFile(filepath.Clean(file)) //nolint:gosec // keyring file is explicitly configured by the operator
		if err != nil {
			return nil, fmt.Errorf("read public key file: %w", err)
		}
		data = string(b)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, entry := range strings.FieldsFunc(data, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("invalid public key entry; expected kid=base64")
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("decode public key %q: %w", parts[0], err)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key %q has invalid Ed25519 length", parts[0])
		}
		keys[strings.TrimSpace(parts[0])] = ed25519.PublicKey(key)
	}
	if len(keys) == 0 && strings.EqualFold(os.Getenv("EDGE_ENV"), "production") {
		return nil, fmt.Errorf("production requires EDGE_PUBLIC_KEYS or EDGE_PUBLIC_KEYS_FILE")
	}
	return keys, nil
}

// LoadSignedFile verifies a signed snapshot against the configured keyring.
func LoadSignedFile(path string, keys map[string]ed25519.PublicKey) (wafcore.Snapshot, error) {
	raw, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // snapshot path is provided by the operator at startup
	if err != nil {
		return wafcore.Snapshot{}, err
	}
	return wafcore.VerifySnapshot(raw, keys)
}
func persist(path string, raw []byte) error {
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err = f.Write(raw); err != nil {
		writeErr := fmt.Errorf("write temporary snapshot: %w", err)
		if closeErr := f.Close(); closeErr != nil {
			return errors.Join(writeErr, fmt.Errorf("close temporary snapshot after write failure: %w", closeErr))
		}
		return writeErr
	}
	if err = f.Sync(); err != nil {
		syncErr := fmt.Errorf("sync temporary snapshot: %w", err)
		if closeErr := f.Close(); closeErr != nil {
			return errors.Join(syncErr, fmt.Errorf("close temporary snapshot after sync failure: %w", closeErr))
		}
		return syncErr
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temporary snapshot: %w", err)
	}
	return os.Rename(tmp, path)
}
