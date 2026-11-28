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
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
)

type fakeCP struct {
	mu                sync.Mutex
	token             string
	csr               []byte
	certInstalled     bool
	certInstallations int
	registerFn        func(string, []byte) (Registration, error)
	registered        Registration
	reply             SnapshotReply
	secrets           SecretBundle
	fetchErr          error
	fetches           int
	heartbeats        int
}

func (f *fakeCP) Register(_ context.Context, token string, csr []byte) (Registration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = token
	f.csr = append([]byte(nil), csr...)
	if f.registerFn != nil {
		return f.registerFn(token, csr)
	}
	return f.registered, nil
}
func (f *fakeCP) RenewCertificate(_ context.Context, _ string, csr []byte) (IssuedCertificate, error) {
	issued, _, err := fakeIssuedCertificate(csr)
	return issued, err
}
func (f *fakeCP) FetchSnapshot(context.Context, string, uint64, string) (SnapshotReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	if f.fetchErr != nil {
		return SnapshotReply{}, f.fetchErr
	}
	return f.reply, nil
}
func (f *fakeCP) SendHeartbeat(context.Context, string, Heartbeat) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats++
	return nil
}
func (f *fakeCP) FetchSecrets(context.Context, string) (SecretBundle, error) { return f.secrets, nil }
func (f *fakeCP) SetClientCertificate(_ tls.Certificate) {
	f.mu.Lock()
	f.certInstalled = true
	f.certInstallations++
	f.mu.Unlock()
}

type testInstaller struct {
	mu      sync.Mutex
	current uint64
	fail    bool
}

func (i *testInstaller) Apply(s *wafcore.Snapshot) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.fail {
		return fmt.Errorf("compile rejected")
	}
	i.current = s.Version
	return nil
}

func fakeIssuedCertificate(csrPEM []byte) (IssuedCertificate, *x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return IssuedCertificate{}, nil, fmt.Errorf("missing CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssuedCertificate{}, nil, err
	}
	if err = csr.CheckSignature(); err != nil {
		return IssuedCertificate{}, nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return IssuedCertificate{}, nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake cp CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return IssuedCertificate{}, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return IssuedCertificate{}, nil, err
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, csr.PublicKey, caKey)
	if err != nil {
		return IssuedCertificate{}, nil, err
	}
	return IssuedCertificate{CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), ExpiresAt: leafTemplate.NotAfter}, ca, nil
}

func TestAgentBootstrapIssuesAndKeepsIdentityAndSecretsInMemory(t *testing.T) {
	client := &fakeCP{secrets: SecretBundle{Values: map[string][]byte{"origin-key": []byte("secret")}}}
	client.registerFn = func(_ string, csr []byte) (Registration, error) {
		issued, _, err := fakeIssuedCertificate(csr)
		return Registration{EdgeID: "edge-17", IssuedCertificate: issued}, err
	}
	store := NewMemorySecrets()
	agent, err := NewAgent(client, nil, &testInstaller{}, store, AgentConfig{RegistrationToken: "one-time-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.token != "one-time-token" || len(client.csr) == 0 || !client.certInstalled {
		t.Fatalf("bootstrap token=%q csr=%d cert_installed=%v", client.token, len(client.csr), client.certInstalled)
	}
	if agent.cfg.RegistrationToken != "" {
		t.Fatal("one-time registration token retained after successful registration")
	}
	if cert, ok := agent.TLSCertificate(); !ok || cert.Leaf == nil || cert.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("issued mTLS cert=%v ok=%v", cert.Leaf, ok)
	}
	if got, ok := store.Secret("origin-key"); !ok || string(got) != "secret" {
		t.Fatalf("in-memory secret=%q ok=%v", got, ok)
	}
}

type fakeCertificateStore map[string]*tls.Certificate

func (f fakeCertificateStore) Put(host string, cert *tls.Certificate) { f[host] = cert }
func TestMemorySecretsRefreshesCertificateBySNI(t *testing.T) {
	store := fakeCertificateStore{}
	secrets := NewMemorySecrets()
	if err := secrets.SetCertificateStore(store); err != nil {
		t.Fatal(err)
	}
	first := tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: &ecdsa.PrivateKey{}}
	if err := secrets.Replace(SecretBundle{Certificates: map[string]tls.Certificate{"site.test": first}}); err != nil {
		t.Fatal(err)
	}
	if got := store["site.test"]; got == nil || got.Certificate[0][0] != 1 {
		t.Fatalf("initial cert=%v", got)
	}
	second := tls.Certificate{Certificate: [][]byte{{2}}, PrivateKey: &ecdsa.PrivateKey{}}
	if err := secrets.Replace(SecretBundle{Certificates: map[string]tls.Certificate{"site.test": second}}); err != nil {
		t.Fatal(err)
	}
	if got := store["site.test"]; got == nil || got.Certificate[0][0] != 2 {
		t.Fatalf("rotated cert=%v", got)
	}
}

func TestAgentRefreshSecretsUsesAuthenticatedClientAndCallback(t *testing.T) {
	client := &fakeCP{secrets: SecretBundle{Values: map[string][]byte{"rotated": []byte("secret")}}}
	store := NewMemorySecrets()
	called := 0
	agent, err := NewAgent(client, nil, &testInstaller{}, store, AgentConfig{EdgeID: "registered-edge", OnSecrets: func() error { called++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.RefreshSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if value, ok := store.Secret("rotated"); !ok || string(value) != "secret" || called != 1 {
		t.Fatalf("secret=%q ok=%v callback=%d", value, ok, called)
	}
}

func TestAgentRenewsCertificateBeforeExpiry(t *testing.T) {
	client := &fakeCP{}
	client.registerFn = func(_ string, csr []byte) (Registration, error) {
		issued, _, err := fakeIssuedCertificate(csr)
		return Registration{EdgeID: "edge-renew", IssuedCertificate: issued}, err
	}
	agent, err := NewAgent(client, nil, &testInstaller{}, nil, AgentConfig{RegistrationToken: "one-time"})
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := agent.TLSCertificate()
	agent.mu.Lock()
	agent.certExpiry = time.Now().Add(-time.Second)
	agent.mu.Unlock()
	if err = agent.renewIfNeeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, ok := agent.TLSCertificate()
	if !ok || after.Leaf == nil || after.PrivateKey == before.PrivateKey {
		t.Fatal("renewal did not replace client identity")
	}
	client.mu.Lock()
	count := client.certInstallations
	client.mu.Unlock()
	if count != 2 {
		t.Fatalf("client cert installations=%d, want bootstrap+renewal", count)
	}
}

func TestAgentSnapshotVerifyCompileSwapAndLastGood(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot()
	snapshot.Version = 12
	raw, err := wafcore.SignSnapshot(snapshot, "active", priv)
	if err != nil {
		t.Fatal(err)
	}
	installer := &testInstaller{}
	lastGood := filepath.Join(t.TempDir(), "last-good.snapshot")
	agent, err := NewAgent(&fakeCP{}, nil, installer, nil, AgentConfig{PublicKeys: map[string]ed25519.PublicKey{"active": pub}, LastGoodPath: lastGood})
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ApplySnapshot(raw, "etag-12"); err != nil {
		t.Fatal(err)
	}
	if installer.current != 12 || agent.Status().Version != 12 {
		t.Fatalf("installed=%d status=%+v", installer.current, agent.Status())
	}
	persisted, err := os.ReadFile(lastGood)
	if err != nil || string(persisted) != string(raw) {
		t.Fatalf("LKG match=%v err=%v", string(persisted) == string(raw), err)
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 1
	if err = agent.ApplySnapshot(bad, "bad"); err == nil {
		t.Fatal("tampered signature accepted")
	}
	if installer.current != 12 || agent.Status().Version != 12 || agent.Status().LastError == "" {
		t.Fatalf("bad snapshot changed active state: installed=%d status=%+v", installer.current, agent.Status())
	}
	newSnapshot := snapshot
	newSnapshot.Version = 13
	newRaw, err := wafcore.SignSnapshot(newSnapshot, "active", priv)
	if err != nil {
		t.Fatal(err)
	}
	installer.fail = true
	if err = agent.ApplySnapshot(newRaw, "etag-13"); err == nil {
		t.Fatal("compile/install failure accepted")
	}
	if installer.current != 12 || agent.Status().Version != 12 {
		t.Fatalf("compile failure changed active state: installed=%d status=%+v", installer.current, agent.Status())
	}
}

func TestAgentCPOutageKeepsLastAppliedSnapshot(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot()
	snapshot.Version = 7
	raw, err := wafcore.SignSnapshot(snapshot, "k", priv)
	if err != nil {
		t.Fatal(err)
	}
	cp := &fakeCP{}
	installer := &testInstaller{}
	agent, err := NewAgent(cp, nil, installer, nil, AgentConfig{PublicKeys: map[string]ed25519.PublicKey{"k": pub}})
	if err != nil {
		t.Fatal(err)
	}
	if err = agent.ApplySnapshot(raw, "etag-7"); err != nil {
		t.Fatal(err)
	}
	cp.fetchErr = fmt.Errorf("control plane unavailable")
	if err = agent.SyncOnce(context.Background()); err == nil {
		t.Fatal("CP outage was not reported")
	}
	if installer.current != 7 || agent.Status().Version != 7 || agent.Status().LastError == "" {
		t.Fatalf("CP outage changed snapshot: installed=%d status=%+v", installer.current, agent.Status())
	}
}

type failingNotifier struct{}

func (failingNotifier) Subscribe(context.Context, string) (<-chan struct{}, error) {
	return nil, fmt.Errorf("NATS unavailable")
}
func TestAgentFallsBackToLongPollWhenNATSUnavailable(t *testing.T) {
	cp := &fakeCP{reply: SnapshotReply{StatusCode: 304}}
	reported := make(chan error, 8)
	agent, err := NewAgent(cp, failingNotifier{}, &testInstaller{}, nil, AgentConfig{PollInterval: 10 * time.Millisecond, HeartbeatInterval: 10 * time.Millisecond, OnSnapshotError: func(err error) { reported <- err }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Millisecond)
	defer cancel()
	if err = agent.Run(ctx); err != context.DeadlineExceeded {
		t.Fatalf("Run error=%v", err)
	}
	cp.mu.Lock()
	fetches, beats := cp.fetches, cp.heartbeats
	cp.mu.Unlock()
	sawNATS := false
	for {
		select {
		case e := <-reported:
			if strings.Contains(e.Error(), "NATS unavailable") {
				sawNATS = true
			}
		default:
			goto drained
		}
	}
drained:
	if fetches < 3 || beats == 0 || !sawNATS {
		t.Fatalf("fallback fetches=%d heartbeats=%d status=%+v", fetches, beats, agent.Status())
	}
}

func TestCommandVerifierRejectsReplayExpiredAndTamperedCommands(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	verifier := NewCommandVerifier(map[string]ed25519.PublicKey{"cmd-v1": pub}, 2, func() time.Time { return now })
	command := EmergencyCommand{KeyID: "cmd-v1", Nonce: "nonce-1", ExpiresAt: now.Add(time.Minute), Action: "under_attack", Target: "site-1", Payload: []byte(`{"enabled":true}`)}
	message, err := EmergencyCommandSigningBytes(command)
	if err != nil {
		t.Fatal(err)
	}
	command.Signature = hex.EncodeToString(ed25519.Sign(priv, message))
	if err = verifier.Verify(command); err != nil {
		t.Fatal(err)
	}
	if err = verifier.Verify(command); err == nil {
		t.Fatal("replayed nonce accepted")
	}
	tampered := command
	tampered.Target = "site-2"
	tampered.Nonce = "nonce-2"
	if err = verifier.Verify(tampered); err == nil {
		t.Fatal("tampered command accepted")
	}
	expired := command
	expired.Nonce = "nonce-3"
	expired.ExpiresAt = now.Add(-time.Second)
	if err = verifier.Verify(expired); err == nil {
		t.Fatal("expired command accepted")
	}
}

type fakeEmergencyActions struct {
	banned, purge, token string
	underAttack, drained bool
}

func (f *fakeEmergencyActions) BanIP(ip net.IP, _ time.Duration) error {
	f.banned = ip.String()
	return nil
}
func (f *fakeEmergencyActions) PurgeCache(target string) error { f.purge = target; return nil }
func (f *fakeEmergencyActions) SetUnderAttack(enabled bool) error {
	f.underAttack = enabled
	return nil
}
func (f *fakeEmergencyActions) SetACMEToken(token, value string) error {
	f.token = token + "=" + value
	return nil
}
func (f *fakeEmergencyActions) Drain() error { f.drained = true; return nil }
func TestEmergencyDispatcherAppliesValidatedPayloads(t *testing.T) {
	actions := &fakeEmergencyActions{}
	dispatcher := EmergencyDispatcher{Actions: actions}
	command := EmergencyCommand{Action: "ban_ip", Target: "192.0.2.10", Payload: json.RawMessage(`{"ttl":"2m"}`)}
	if err := dispatcher.ApplyEmergency(command); err != nil || actions.banned != "192.0.2.10" {
		t.Fatalf("ban=%q err=%v", actions.banned, err)
	}
	command.Target = "invalid"
	if err := dispatcher.ApplyEmergency(command); err == nil {
		t.Fatal("invalid IP ban target accepted")
	}
}
func TestChallengeTokenStoreUpdatesAndDeletes(t *testing.T) {
	store, err := NewChallengeTokens(map[string]string{"known": "response"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := store.Lookup("known"); !ok || got != "response" {
		t.Fatalf("lookup=%q ok=%v", got, ok)
	}
	if err := store.Set("new", "proof"); err != nil {
		t.Fatal(err)
	}
	if got, ok := store.Lookup("new"); !ok || got != "proof" {
		t.Fatalf("new lookup=%q ok=%v", got, ok)
	}
	store.Delete("known")
	if _, ok := store.Lookup("known"); ok {
		t.Fatal("deleted token still present")
	}
	if err := store.Set("", "proof"); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestHTTPClientRequiresHTTPSAndPreservesSnapshotQuery(t *testing.T) {
	if _, err := NewHTTPClient("http://cp.test", nil, time.Second); err == nil {
		t.Fatal("plain HTTP control-plane URL accepted")
	}
	client, err := NewHTTPClient("https://cp.test/api", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := url.Parse(client.endpoint("/internal/snapshot?since=42&edge_id=edge-1"))
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Path != "/api/internal/snapshot" || endpoint.Query().Get("since") != "42" || endpoint.Query().Get("edge_id") != "edge-1" {
		t.Fatalf("snapshot endpoint path=%q query=%v", endpoint.Path, endpoint.Query())
	}
}
