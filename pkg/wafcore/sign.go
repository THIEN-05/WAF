package wafcore

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type SignedSnapshot struct {
	SchemaVersion int    `json:"schema_version"`
	KeyID         string `json:"kid"`
	Checksum      string `json:"checksum_sha256"`
	Signature     string `json:"signature_ed25519"`
	Payload       []byte `json:"payload_gzip_base64"`
}

// SignSnapshot marshals a validated snapshot, gzip-compresses its JSON and signs kid + checksum.
func SignSnapshot(s Snapshot, kid string, key ed25519.PrivateKey) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if kid == "" {
		return nil, fmt.Errorf("kid is required")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length")
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	zw.Header.ModTime = time.Unix(0, 0)
	if _, err = zw.Write(plain); err != nil {
		return nil, fmt.Errorf("gzip snapshot: %w", err)
	}
	if err = zw.Close(); err != nil {
		return nil, fmt.Errorf("gzip snapshot: %w", err)
	}
	sum := sha256.Sum256(compressed.Bytes())
	checksum := hex.EncodeToString(sum[:])
	env := SignedSnapshot{SchemaVersion: 1, KeyID: kid, Checksum: checksum, Signature: hex.EncodeToString(ed25519.Sign(key, signatureMessage(kid, checksum))), Payload: compressed.Bytes()}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal signed envelope: %w", err)
	}
	return out, nil
}

// VerifySnapshot validates checksum and Ed25519 signature using the public key selected by kid.
func VerifySnapshot(data []byte, keys map[string]ed25519.PublicKey) (Snapshot, error) {
	var env SignedSnapshot
	if err := json.Unmarshal(data, &env); err != nil {
		return Snapshot{}, fmt.Errorf("decode signed envelope: %w", err)
	}
	if env.SchemaVersion != 1 {
		return Snapshot{}, fmt.Errorf("envelope schema_version: unsupported value %d", env.SchemaVersion)
	}
	key, ok := keys[env.KeyID]
	if !ok {
		return Snapshot{}, fmt.Errorf("unknown signing key kid %q", env.KeyID)
	}
	if len(key) != ed25519.PublicKeySize {
		return Snapshot{}, fmt.Errorf("invalid Ed25519 public key for kid %q", env.KeyID)
	}
	sum := sha256.Sum256(env.Payload)
	checksum := hex.EncodeToString(sum[:])
	if !equalHex(checksum, env.Checksum) {
		return Snapshot{}, fmt.Errorf("snapshot checksum mismatch")
	}
	sig, err := hex.DecodeString(env.Signature)
	if err != nil {
		return Snapshot{}, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !ed25519.Verify(key, signatureMessage(env.KeyID, checksum), sig) {
		return Snapshot{}, fmt.Errorf("snapshot signature verification failed")
	}
	zr, err := gzip.NewReader(bytes.NewReader(env.Payload))
	if err != nil {
		return Snapshot{}, fmt.Errorf("open gzip payload: %w", err)
	}
	defer zr.Close()
	const maxPayload = 32 << 20
	plain, err := io.ReadAll(io.LimitReader(zr, maxPayload+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read gzip payload: %w", err)
	}
	if len(plain) > maxPayload {
		return Snapshot{}, fmt.Errorf("snapshot payload exceeds 32 MiB")
	}
	var s Snapshot
	if err = json.Unmarshal(plain, &s); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot payload: %w", err)
	}
	if err = s.Validate(); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

func signatureMessage(kid, checksum string) []byte {
	return []byte("waf-snapshot-v1\x00" + kid + "\x00" + checksum)
}
func equalHex(a, b string) bool { return len(a) == len(b) && bytes.Equal([]byte(a), []byte(b)) }
