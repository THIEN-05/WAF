package configsync

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
)

// CPClient is the edge-facing control-plane contract. Implementations must use
// HTTPS for bootstrap registration and mutual TLS for every method after it.
type CPClient interface {
	Register(context.Context, string, []byte) (Registration, error)
	RenewCertificate(context.Context, string, []byte) (IssuedCertificate, error)
	FetchSnapshot(context.Context, string, uint64, string) (SnapshotReply, error)
	SendHeartbeat(context.Context, string, Heartbeat) error
	FetchSecrets(context.Context, string) (SecretBundle, error)
	SetClientCertificate(tls.Certificate)
}

type Notifier interface {
	Subscribe(context.Context, string) (<-chan struct{}, error)
}
type EmergencyNotifier interface {
	SubscribeEmergency(context.Context, string) (<-chan []byte, error)
}

type SnapshotInstaller interface{ Apply(*wafcore.Snapshot) error }

type Registration struct {
	EdgeID string `json:"edge_id"`
	IssuedCertificate
}

type IssuedCertificate struct {
	CertificatePEM string    `json:"certificate_pem"`
	CAPEM          string    `json:"ca_pem"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type SnapshotReply struct {
	StatusCode int
	ETag       string
	Version    uint64
	Body       []byte
}

type Heartbeat struct {
	SnapshotVersion   uint64        `json:"snapshot_version"`
	SnapshotAge       time.Duration `json:"snapshot_age"`
	SnapshotError     string        `json:"snapshot_error,omitempty"`
	CPUPercent        float64       `json:"cpu_percent,omitempty"`
	MemoryBytes       uint64        `json:"memory_bytes"`
	RequestsPerSec    float64       `json:"requests_per_sec,omitempty"`
	ErrorsPerSec      float64       `json:"errors_per_sec,omitempty"`
	P99               time.Duration `json:"p99,omitempty"`
	CertificateExpiry time.Time     `json:"certificate_expiry"`
	LogDropped        uint64        `json:"log_dropped,omitempty"`
}

type SecretBundle struct {
	Values       map[string][]byte
	Certificates map[string]tls.Certificate
}

type SecretSink interface{ Replace(SecretBundle) error }

type CertificateStore interface {
	Put(string, *tls.Certificate)
}

type ChallengeTokens struct {
	current atomic.Pointer[map[string]string]
}

func NewChallengeTokens(initial map[string]string) (*ChallengeTokens, error) {
	store := &ChallengeTokens{}
	if err := store.Replace(initial); err != nil {
		return nil, err
	}
	return store, nil
}
func (s *ChallengeTokens) Replace(tokens map[string]string) error {
	if len(tokens) > 10000 {
		return errors.New("ACME token store exceeds 10000 entries")
	}
	copy := make(map[string]string, len(tokens))
	total := 0
	for k, v := range tokens {
		if k == "" || len(k) > 256 || len(v) > 4096 {
			return errors.New("invalid ACME token entry")
		}
		total += len(k) + len(v)
		if total > 4<<20 {
			return errors.New("ACME token store exceeds 4 MiB")
		}
		copy[k] = v
	}
	s.current.Store(&copy)
	return nil
}
func (s *ChallengeTokens) Lookup(token string) (string, bool) {
	current := s.current.Load()
	if current == nil {
		return "", false
	}
	value, ok := (*current)[token]
	return value, ok
}
func (s *ChallengeTokens) Set(token, value string) error {
	if token == "" || len(token) > 256 || len(value) > 4096 {
		return errors.New("invalid ACME token entry")
	}
	for {
		old := s.current.Load()
		next := make(map[string]string)
		if old != nil {
			for k, v := range *old {
				next[k] = v
			}
		}
		if len(next) >= 10000 {
			if _, exists := next[token]; !exists {
				return errors.New("ACME token store is full")
			}
		}
		total := len(token) + len(value)
		for k, v := range next {
			if k != token {
				total += len(k) + len(v)
			}
		}
		if total > 4<<20 {
			return errors.New("ACME token store exceeds 4 MiB")
		}
		next[token] = value
		if s.current.CompareAndSwap(old, &next) {
			return nil
		}
	}
}
func (s *ChallengeTokens) Delete(token string) {
	for {
		old := s.current.Load()
		if old == nil {
			return
		}
		next := make(map[string]string, len(*old))
		for k, v := range *old {
			if k != token {
				next[k] = v
			}
		}
		if s.current.CompareAndSwap(old, &next) {
			return
		}
	}
}

// MemorySecrets deliberately has no disk persistence: CP-provisioned plaintext
// secrets and site certificates stay in process memory.
type MemorySecrets struct {
	mu               sync.RWMutex
	values           map[string][]byte
	certs            map[string]tls.Certificate
	certificateStore CertificateStore
}

func NewMemorySecrets() *MemorySecrets {
	return &MemorySecrets{values: map[string][]byte{}, certs: map[string]tls.Certificate{}}
}
func (m *MemorySecrets) Replace(b SecretBundle) error {
	if len(b.Values) > 2048 || len(b.Certificates) > 10000 {
		return errors.New("secret bundle exceeds entry limits")
	}
	values := make(map[string][]byte, len(b.Values))
	total := 0
	for k, v := range b.Values {
		if k == "" || len(k) > 128 || len(v) > 64<<10 {
			return errors.New("secret entry exceeds size limits")
		}
		total += len(v)
		if total > 4<<20 {
			return errors.New("secret bundle exceeds 4 MiB")
		}
		values[k] = append([]byte(nil), v...)
	}
	certs := make(map[string]tls.Certificate, len(b.Certificates))
	certBytes := 0
	for host, cert := range b.Certificates {
		if host == "" || len(host) > 253 || cert.PrivateKey == nil || len(cert.Certificate) == 0 {
			return errors.New("invalid certificate entry")
		}
		for _, der := range cert.Certificate {
			certBytes += len(der)
			if certBytes > 16<<20 {
				return errors.New("TLS certificate bundle exceeds 16 MiB")
			}
		}
		cert.Certificate = append([][]byte(nil), cert.Certificate...)
		for i := range cert.Certificate {
			cert.Certificate[i] = append([]byte(nil), cert.Certificate[i]...)
		}
		certs[host] = cert
	}
	m.mu.Lock()
	m.values, m.certs = values, certs
	store := m.certificateStore
	m.mu.Unlock()
	if store != nil {
		for host, cert := range certs {
			copy := cert
			store.Put(host, &copy)
		}
	}
	return nil
}
func (m *MemorySecrets) SetCertificateStore(store CertificateStore) error {
	if store == nil {
		return errors.New("nil certificate store")
	}
	m.mu.Lock()
	m.certificateStore = store
	m.mu.Unlock()
	return m.InstallCertificates(store)
}
func (m *MemorySecrets) InstallCertificates(store CertificateStore) error {
	if store == nil {
		return errors.New("nil certificate store")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for host, cert := range m.certs {
		if strings.TrimSpace(host) == "" || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
			return fmt.Errorf("invalid TLS certificate entry for SNI %q", host)
		}
	}
	for host, cert := range m.certs {
		copy := cert
		store.Put(host, &copy)
	}
	return nil
}
func (m *MemorySecrets) Secret(id string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.values[id]
	return append([]byte(nil), v...), ok
}
func (m *MemorySecrets) AllSecrets() map[string][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]byte, len(m.values))
	for k, v := range m.values {
		out[k] = append([]byte(nil), v...)
	}
	return out
}
func (m *MemorySecrets) CertificateCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.certs)
}
func (m *MemorySecrets) Certificate(sni string) (tls.Certificate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cert, ok := m.certs[sni]
	cert.Certificate = append([][]byte(nil), cert.Certificate...)
	for i := range cert.Certificate {
		cert.Certificate[i] = append([]byte(nil), cert.Certificate[i]...)
	}
	return cert, ok
}

type SnapshotStatus struct {
	Version     uint64
	Age         time.Duration
	LastError   string
	LastApplied time.Time
}

type AgentConfig struct {
	EdgeID             string
	RegistrationToken  string
	PrivateKey         any // optional caller-owned key; otherwise a new ECDSA key is generated in RAM
	PublicKeys         map[string]ed25519.PublicKey
	LastGoodPath       string
	PollInterval       time.Duration
	HeartbeatInterval  time.Duration
	SecretsInterval    time.Duration
	RenewBefore        time.Duration
	SnapshotStaleAfter time.Duration
	Heartbeat          func(context.Context, Heartbeat) error
	OnSnapshotError    func(error)
	OnSnapshotStale    func(time.Duration)
	OnSnapshotVersion  func(uint64)
	HeartbeatValues    func() Heartbeat
	OnSecrets          func() error
	CommandVerifier    *CommandVerifier
	EmergencyHandler   EmergencyHandler
}

type Agent struct {
	client       CPClient
	notifier     Notifier
	installer    SnapshotInstaller
	secrets      SecretSink
	cfg          AgentConfig
	mu           sync.Mutex
	edgeID       string
	etag         string
	version      uint64
	lastApplied  time.Time
	lastErr      string
	cert         tls.Certificate
	certExpiry   time.Time
	bootstrapped bool
	staleWarned  bool
	status       atomic.Pointer[SnapshotStatus]
}

func NewAgent(client CPClient, notifier Notifier, installer SnapshotInstaller, secrets SecretSink, cfg AgentConfig) (*Agent, error) {
	if client == nil || installer == nil {
		return nil, errors.New("config sync requires CP client and snapshot installer")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 20 * time.Second
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 20 * time.Second
	}
	if cfg.SecretsInterval <= 0 {
		cfg.SecretsInterval = 5 * time.Minute
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = 10 * time.Minute
	}
	if cfg.SnapshotStaleAfter <= 0 {
		cfg.SnapshotStaleAfter = time.Hour
	}
	a := &Agent{client: client, notifier: notifier, installer: installer, secrets: secrets, cfg: cfg, edgeID: cfg.EdgeID}
	a.publishStatus()
	return a, nil
}

func (a *Agent) Status() SnapshotStatus {
	if s := a.status.Load(); s != nil {
		out := *s
		out.Age = time.Since(out.LastApplied)
		if out.Age < 0 {
			out.Age = 0
		}
		if out.LastApplied.IsZero() {
			out.Age = 0
		}
		return out
	}
	return SnapshotStatus{}
}
func (a *Agent) CertificateExpiry() time.Time { a.mu.Lock(); defer a.mu.Unlock(); return a.certExpiry }
func (a *Agent) SetCurrentSnapshot(version uint64, appliedAt time.Time) {
	a.mu.Lock()
	a.version = version
	a.lastApplied = appliedAt
	a.mu.Unlock()
	a.publishStatus()
}
func (a *Agent) SnapshotStale() bool {
	s := a.Status()
	return !s.LastApplied.IsZero() && s.Age > a.cfg.SnapshotStaleAfter
}
func (a *Agent) publishStatus() {
	a.mu.Lock()
	snapshot := &SnapshotStatus{Version: a.version, LastApplied: a.lastApplied, LastError: a.lastErr}
	a.mu.Unlock()
	a.status.Store(snapshot)
}

func makeCSR() (any, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "waf-edge"}}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}
func keyPEM(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if len(der) == 0 {
		return nil, errors.New("cannot encode edge private key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
func decodeSignature(raw string) ([]byte, error) { return hex.DecodeString(raw) }

func EmergencyCommandSigningBytes(c EmergencyCommand) ([]byte, error) {
	canonical, err := json.Marshal(struct {
		KeyID     string          `json:"kid"`
		Nonce     string          `json:"nonce"`
		ExpiresAt time.Time       `json:"expires_at"`
		Action    string          `json:"action"`
		Target    string          `json:"target"`
		Payload   json.RawMessage `json:"payload,omitempty"`
	}{c.KeyID, c.Nonce, c.ExpiresAt.UTC(), c.Action, c.Target, c.Payload})
	if err != nil {
		return nil, err
	}
	return append([]byte("waf-edge-emergency-v1\n"), canonical...), nil
}

// Bootstrap performs one-time token registration; certificate/private key are
// retained only in RAM. It then fetches per-edge secrets over the authenticated client.
func (a *Agent) Bootstrap(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.edgeID != "" && len(a.cert.Certificate) > 0 {
		if a.secrets == nil {
			a.bootstrapped = true
			return nil
		}
		if err := a.refreshSecrets(ctx, a.edgeID); err != nil {
			return err
		}
		a.bootstrapped = true
		return nil
	}
	key, csr, err := makeCSR()
	if err != nil {
		return err
	}
	registration, err := a.client.Register(ctx, a.cfg.RegistrationToken, csr)
	if err != nil {
		return fmt.Errorf("register edge: %w", err)
	}
	if registration.EdgeID == "" {
		return errors.New("registration returned empty edge id")
	}
	cert, expiry, err := validateIssuedCertificate(registration.IssuedCertificate, key)
	if err != nil {
		return fmt.Errorf("parse issued edge certificate: %w", err)
	}
	a.edgeID, a.cert, a.certExpiry = registration.EdgeID, cert, expiry
	a.cfg.RegistrationToken = ""
	a.client.SetClientCertificate(cert)
	if a.secrets != nil {
		if err = a.refreshSecrets(ctx, a.edgeID); err != nil {
			return err
		}
	}
	a.bootstrapped = true
	return nil
}

func (a *Agent) RefreshSecrets(ctx context.Context) error {
	a.mu.Lock()
	id := a.edgeID
	a.mu.Unlock()
	if id == "" {
		return errors.New("cannot fetch secrets before edge registration")
	}
	return a.refreshSecrets(ctx, id)
}
func (a *Agent) refreshSecrets(ctx context.Context, id string) error {
	if a.secrets == nil {
		return nil
	}
	bundle, err := a.client.FetchSecrets(ctx, id)
	if err != nil {
		return fmt.Errorf("fetch edge secrets: %w", err)
	}
	if err = a.secrets.Replace(bundle); err != nil {
		return fmt.Errorf("install edge secrets: %w", err)
	}
	if a.cfg.OnSecrets != nil {
		if err = a.cfg.OnSecrets(); err != nil {
			return fmt.Errorf("apply refreshed edge secrets: %w", err)
		}
	}
	return nil
}

func (a *Agent) TLSCertificate() (tls.Certificate, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cert, len(a.cert.Certificate) > 0
}

func (a *Agent) ApplySnapshot(raw []byte, etag string) error {
	return a.applySnapshot(context.Background(), raw, etag)
}
func (a *Agent) applySnapshot(ctx context.Context, raw []byte, etag string) error {
	if len(raw) == 0 {
		return errors.New("empty signed snapshot")
	}
	snapshot, err := wafcore.VerifySnapshot(raw, a.cfg.PublicKeys)
	if err == nil && a.secrets != nil {
		a.mu.Lock()
		id := a.edgeID
		a.mu.Unlock()
		err = a.refreshSecrets(ctx, id)
	}
	if err == nil {
		err = a.installer.Apply(&snapshot)
	}
	if err != nil {
		a.recordSnapshotError(err)
		return err
	}
	a.mu.Lock()
	a.version, a.etag, a.lastApplied, a.lastErr = snapshot.Version, etag, snapshot.GeneratedAt, ""
	version := a.version
	a.mu.Unlock()
	a.publishStatus()
	if a.cfg.OnSnapshotVersion != nil {
		a.cfg.OnSnapshotVersion(version)
	}
	if a.cfg.LastGoodPath != "" {
		if err = persist(a.cfg.LastGoodPath, raw); err != nil {
			a.recordSnapshotError(err)
			return fmt.Errorf("persist last-known-good after apply: %w", err)
		}
	}
	return nil
}
func (a *Agent) recordSnapshotError(err error) {
	a.mu.Lock()
	a.lastErr = err.Error()
	a.mu.Unlock()
	a.publishStatus()
	if a.cfg.OnSnapshotError != nil {
		a.cfg.OnSnapshotError(err)
	}
}

func (a *Agent) SyncOnce(ctx context.Context) error {
	a.mu.Lock()
	edgeID, version, etag := a.edgeID, a.version, a.etag
	a.mu.Unlock()
	reply, err := a.client.FetchSnapshot(ctx, edgeID, version, etag)
	if err != nil {
		a.recordSnapshotError(err)
		return err
	}
	if reply.StatusCode == 304 {
		a.mu.Lock()
		a.lastErr = ""
		a.mu.Unlock()
		a.publishStatus()
		return nil
	}
	if reply.StatusCode != 200 {
		err = fmt.Errorf("snapshot endpoint returned HTTP %d", reply.StatusCode)
		a.recordSnapshotError(err)
		return err
	}
	return a.applySnapshot(ctx, reply.Body, reply.ETag)
}

func (a *Agent) Run(ctx context.Context) error {
	a.mu.Lock()
	bootstrapped := a.bootstrapped
	a.mu.Unlock()
	a.mu.Lock()
	hasIdentity := a.edgeID != "" && len(a.cert.Certificate) > 0
	hasToken := a.cfg.RegistrationToken != ""
	a.mu.Unlock()
	if !bootstrapped && (hasToken || hasIdentity) {
		retry := time.NewTicker(5 * time.Second)
		defer retry.Stop()
		for {
			if err := a.Bootstrap(ctx); err == nil {
				break
			} else {
				a.recordSnapshotError(fmt.Errorf("edge bootstrap retry: %w", err))
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-retry.C:
			}
		}
	}
	var updates <-chan struct{}
	if a.notifier != nil {
		ch, err := a.notifier.Subscribe(ctx, a.edgeID)
		if err == nil {
			updates = ch
		} else {
			a.recordSnapshotError(fmt.Errorf("NATS config.updated subscription: %w", err))
		}
	}
	if emergency, ok := a.notifier.(EmergencyNotifier); ok && a.cfg.CommandVerifier != nil && a.cfg.EmergencyHandler != nil {
		commands, err := emergency.SubscribeEmergency(ctx, a.edgeID)
		if err != nil {
			a.recordSnapshotError(fmt.Errorf("NATS emergency subscription: %w", err))
		} else {
			go a.cfg.CommandVerifier.Consume(ctx, commands, a.cfg.EmergencyHandler, a.cfg.OnSnapshotError)
		}
	}
	poll := time.NewTicker(a.cfg.PollInterval)
	defer poll.Stop()
	heartbeat := time.NewTicker(a.cfg.HeartbeatInterval)
	defer heartbeat.Stop()
	cert := time.NewTicker(time.Minute)
	defer cert.Stop()
	secrets := time.NewTicker(a.cfg.SecretsInterval)
	defer secrets.Stop()
	if err := a.SyncOnce(ctx); err != nil {
		a.recordSnapshotError(err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-updates:
			if ok {
				if err := a.SyncOnce(ctx); err != nil {
					a.recordSnapshotError(err)
				}
			} else {
				updates = nil
			}
		case <-poll.C:
			if err := a.SyncOnce(ctx); err != nil {
				a.recordSnapshotError(err)
			}
		case <-heartbeat.C:
			values := Heartbeat{}
			if a.cfg.HeartbeatValues != nil {
				values = a.cfg.HeartbeatValues()
			}
			status := a.Status()
			values.SnapshotVersion, values.SnapshotAge = status.Version, status.Age
			values.SnapshotError = status.LastError
			if len(values.SnapshotError) > 256 {
				values.SnapshotError = values.SnapshotError[:256]
			}
			a.mu.Lock()
			values.CertificateExpiry = a.certExpiry
			id := a.edgeID
			a.mu.Unlock()
			if a.cfg.Heartbeat != nil {
				_ = a.cfg.Heartbeat(ctx, values)
			} else {
				_ = a.client.SendHeartbeat(ctx, id, values)
			}
			stale := a.SnapshotStale()
			a.mu.Lock()
			warnStale := stale && !a.staleWarned
			a.staleWarned = stale
			a.mu.Unlock()
			if warnStale {
				if a.cfg.OnSnapshotStale != nil {
					a.cfg.OnSnapshotStale(status.Age)
				} else {
					log.Printf("config sync warning: snapshot stale age=%q version=%d", status.Age, status.Version)
				}
			}
		case <-cert.C:
			if err := a.renewIfNeeded(ctx); err != nil {
				a.recordSnapshotError(fmt.Errorf("renew edge certificate: %w", err))
			}
		case <-secrets.C:
			if err := a.RefreshSecrets(ctx); err != nil {
				a.recordSnapshotError(err)
			}
		}
	}
}
func (a *Agent) renewIfNeeded(ctx context.Context) error {
	a.mu.Lock()
	expiry, id := a.certExpiry, a.edgeID
	a.mu.Unlock()
	if expiry.IsZero() || time.Until(expiry) > a.cfg.RenewBefore {
		return nil
	}
	key, csr, err := makeCSR()
	if err != nil {
		return err
	}
	issued, err := a.client.RenewCertificate(ctx, id, csr)
	if err != nil {
		return err
	}
	cert, expiry, err := validateIssuedCertificate(issued, key)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.cert, a.certExpiry = cert, expiry
	a.mu.Unlock()
	a.client.SetClientCertificate(cert)
	return nil
}

func validateIssuedCertificate(issued IssuedCertificate, privateKey any) (tls.Certificate, time.Time, error) {
	privatePEM, err := keyPEM(privateKey)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}
	cert, err := tls.X509KeyPair([]byte(issued.CertificatePEM), privatePEM)
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}
	if issued.CAPEM == "" {
		return tls.Certificate{}, time.Time{}, errors.New("issued edge certificate has no CA chain")
	}
	roots := x509.NewCertPool()
	remaining := []byte(issued.CAPEM)
	caCount := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		ca, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return tls.Certificate{}, time.Time{}, parseErr
		}
		roots.AddCert(ca)
		caCount++
	}
	if caCount == 0 {
		return tls.Certificate{}, time.Time{}, errors.New("issued edge certificate CA bundle is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return tls.Certificate{}, time.Time{}, fmt.Errorf("issued client certificate chain verification: %w", err)
	}
	cert.Leaf = leaf
	expiry := leaf.NotAfter
	if !issued.ExpiresAt.IsZero() && issued.ExpiresAt.Before(expiry) {
		expiry = issued.ExpiresAt
	}
	if !expiry.After(time.Now()) {
		return tls.Certificate{}, time.Time{}, errors.New("issued edge certificate is expired")
	}
	return cert, expiry, nil
}

// VerifyCommand authenticates signed NATS emergency commands, checks expiry,
// and atomically rejects replayed nonces within a bounded in-memory window.
type EmergencyCommand struct {
	KeyID     string          `json:"kid"`
	Nonce     string          `json:"nonce"`
	ExpiresAt time.Time       `json:"expires_at"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Signature string          `json:"signature"`
}
type CommandVerifier struct {
	keys map[string]ed25519.PublicKey
	mu   sync.Mutex
	seen map[string]time.Time
	max  int
	now  func() time.Time
}

func NewCommandVerifier(keys map[string]ed25519.PublicKey, max int, now func() time.Time) *CommandVerifier {
	if max < 1 {
		max = 10000
	}
	if now == nil {
		now = time.Now
	}
	copied := map[string]ed25519.PublicKey{}
	for k, v := range keys {
		copied[k] = append(ed25519.PublicKey(nil), v...)
	}
	return &CommandVerifier{keys: copied, seen: map[string]time.Time{}, max: max, now: now}
}
func (v *CommandVerifier) Verify(c EmergencyCommand) error {
	key, ok := v.keys[c.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return errors.New("unknown emergency command key")
	}
	sig, err := decodeSignature(c.Signature)
	if err != nil {
		return errors.New("invalid emergency command signature")
	}
	if len(c.Nonce) > 128 || len(c.Payload) > 48<<10 {
		return errors.New("emergency command exceeds size limits")
	}
	switch c.Action {
	case "ban_ip", "purge_cache", "under_attack", "acme_token", "drain":
	default:
		return errors.New("unsupported emergency command action")
	}
	data, err := EmergencyCommandSigningBytes(c)
	if err != nil || !ed25519.Verify(key, data, sig) {
		return errors.New("emergency command signature verification failed")
	}
	now := v.now()
	if c.Nonce == "" || !c.ExpiresAt.After(now) || c.ExpiresAt.Sub(now) > 5*time.Minute {
		return errors.New("emergency command nonce/expiry rejected")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for nonce, expiry := range v.seen {
		if !expiry.After(now) {
			delete(v.seen, nonce)
		}
	}
	if _, exists := v.seen[c.Nonce]; exists {
		return errors.New("emergency command replay rejected")
	}
	if len(v.seen) >= v.max {
		return errors.New("emergency command replay cache full")
	}
	v.seen[c.Nonce] = c.ExpiresAt
	return nil
}

type EmergencyHandler interface{ ApplyEmergency(EmergencyCommand) error }

type EmergencyActions interface {
	BanIP(net.IP, time.Duration) error
	PurgeCache(string) error
	SetUnderAttack(bool) error
	SetACMEToken(string, string) error
	Drain() error
}

type EmergencyDispatcher struct{ Actions EmergencyActions }

func (d EmergencyDispatcher) ApplyEmergency(command EmergencyCommand) error {
	if d.Actions == nil {
		return errors.New("emergency action handler is unavailable")
	}
	switch command.Action {
	case "ban_ip":
		ip := net.ParseIP(command.Target)
		if ip == nil {
			return errors.New("emergency ban target is not an IP")
		}
		var p struct {
			TTL string `json:"ttl"`
		}
		if err := json.Unmarshal(command.Payload, &p); err != nil {
			return err
		}
		ttl, err := time.ParseDuration(p.TTL)
		if err != nil || ttl <= 0 || ttl > 24*time.Hour {
			return errors.New("emergency ban TTL must be between 0 and 24 hours")
		}
		return d.Actions.BanIP(ip, ttl)
	case "purge_cache":
		if command.Target == "" || len(command.Target) > 2048 {
			return errors.New("invalid purge target")
		}
		return d.Actions.PurgeCache(command.Target)
	case "under_attack":
		var p struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(command.Payload, &p); err != nil {
			return err
		}
		return d.Actions.SetUnderAttack(p.Enabled)
	case "acme_token":
		var p struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(command.Payload, &p); err != nil {
			return err
		}
		if command.Target == "" || len(command.Target) > 256 || len(p.Value) > 4096 {
			return errors.New("invalid ACME challenge token")
		}
		return d.Actions.SetACMEToken(command.Target, p.Value)
	case "drain":
		return d.Actions.Drain()
	default:
		return errors.New("unsupported emergency command action")
	}
}

func (v *CommandVerifier) Consume(ctx context.Context, commands <-chan []byte, handler EmergencyHandler, onError func(error)) {
	if handler == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-commands:
			if !ok {
				return
			}
			var command EmergencyCommand
			var err error
			if len(raw) > 64<<10 {
				err = errors.New("emergency command exceeds 64 KiB")
			} else if err = json.Unmarshal(raw, &command); err == nil {
				err = v.Verify(command)
			}
			if err == nil {
				err = handler.ApplyEmergency(command)
			}
			if err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
