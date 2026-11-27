package fleet

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type State string

const (
	Registering    State = "registering"
	Ready          State = "ready"
	Degraded       State = "degraded"
	Draining       State = "draining"
	Offline        State = "offline"
	Decommissioned State = "decommissioned"
)

var ErrInvalidTransition = errors.New("invalid edge state transition")
var ErrBootstrapRejected = errors.New("bootstrap token rejected")
var ErrEdgeCertificateRejected = errors.New("edge certificate rejected")

func CanTransition(from, to State) bool {
	switch from {
	case Registering:
		return to == Ready
	case Ready:
		return to == Degraded || to == Draining || to == Offline
	case Degraded:
		return to == Ready || to == Draining || to == Offline
	case Draining:
		return to == Offline || to == Decommissioned
	case Offline:
		return to == Decommissioned
	case Decommissioned:
		return false
	default:
		return false
	}
}

// Authority is an internal development CA. Production must inject a signer backed by a
// SecretStore/PKI; the in-memory development CA is deliberately process-local.
type Authority struct {
	certificate *x509.Certificate
	privateKey  crypto.Signer
}

func NewDevelopmentAuthority(now time.Time) (*Authority, []byte, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate development CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "WAF Development Edge CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create development CA: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return &Authority{certificate: parsed, privateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func NewAuthorityFromPEM(certificatePEM, privateKeyPEM []byte) (*Authority, error) {
	certBlock, _ := pem.Decode(certificatePEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("edge CA certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.New("edge CA certificate is invalid")
	}
	keyBlock, _ := pem.Decode(privateKeyPEM)
	if keyBlock == nil {
		return nil, errors.New("edge CA private key PEM is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.New("edge CA private key must be PKCS#8")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("edge CA private key is not a signer")
	}
	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("edge CA certificate must be a self-signed CA")
	}
	return &Authority{certificate: cert, privateKey: signer}, nil
}

func (a *Authority) IssueCSR(csrPEM []byte, edgeID uuid.UUID, now time.Time, lifetime time.Duration) (certPEM []byte, serial string, notAfter time.Time, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		err = errors.New("invalid CSR PEM")
		return
	}
	csr, parseErr := x509.ParseCertificateRequest(block.Bytes)
	if parseErr != nil || csr.CheckSignature() != nil {
		err = errors.New("invalid CSR signature")
		return
	}
	if !acceptablePublicKey(csr.PublicKey) {
		err = errors.New("CSR public key must be Ed25519, P-256/P-384, or RSA 2048+")
		return
	}
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	serialNumber, serialErr := randomSerial()
	if serialErr != nil {
		err = serialErr
		return
	}
	uri := &url.URL{Scheme: "spiffe", Host: "waf", Path: "/edge/" + edgeID.String()}
	notAfter = now.Add(lifetime)
	tmpl := &x509.Certificate{SerialNumber: serialNumber, Subject: pkix.Name{CommonName: edgeID.String()}, URIs: []*url.URL{uri}, NotBefore: now.Add(-5 * time.Minute), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, signErr := x509.CreateCertificate(rand.Reader, tmpl, a.certificate, csr.PublicKey, a.privateKey)
	if signErr != nil {
		err = fmt.Errorf("sign edge certificate: %w", signErr)
		return
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serial = serialNumber.Text(16)
	return
}

func (a *Authority) VerifyEdgeCertificate(cert *x509.Certificate, edgeID uuid.UUID, now time.Time) bool {
	if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.Subject.CommonName != edgeID.String() {
		return false
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	clientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return false
	}
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" && uri.Host == "waf" && uri.Path == "/edge/"+edgeID.String() {
			return true
		}
	}
	return false
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

func acceptablePublicKey(key any) bool {
	switch public := key.(type) {
	case ed25519.PublicKey:
		return len(public) == ed25519.PublicKeySize
	case *ecdsa.PublicKey:
		return public.Curve == elliptic.P256() || public.Curve == elliptic.P384()
	case *rsa.PublicKey:
		return public.N != nil && public.N.BitLen() >= 2048
	default:
		return false
	}
}

type Service struct {
	Pool                  *pgxpool.Pool
	CA                    *Authority
	Now                   func() time.Time
	CertificateLifetime   time.Duration
	DNSWithdrawalInterval time.Duration
}
type Bootstrap struct {
	EdgeID    uuid.UUID `json:"edge_id"`
	Region    string    `json:"region"`
	Provider  string    `json:"provider"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Registration struct {
	EdgeID        uuid.UUID `json:"edge_id"`
	Certificate   string    `json:"certificate"`
	CACertificate string    `json:"ca_certificate"`
	Serial        string    `json:"serial"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// CreateBootstrapToken is an operator provisioning API. Only the SHA-256 digest is persisted.
func (s Service) CreateBootstrapToken(ctx context.Context, region, provider string) (Bootstrap, error) {
	region, provider = strings.TrimSpace(region), strings.TrimSpace(provider)
	if s.Pool == nil || region == "" || len(region) > 128 || (provider != "cloudflare" && provider != "route53" && provider != "integration") {
		return Bootstrap{}, errors.New("region and provider are required")
	}
	edgeID, err := uuid.NewV7()
	if err != nil {
		return Bootstrap{}, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Bootstrap{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	expires := s.now().Add(time.Hour)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Bootstrap{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `INSERT INTO public.edges(id,region,provider,status) VALUES($1,$2,$3,'registering')`, edgeID, region, provider); err != nil {
		return Bootstrap{}, err
	}
	tokenID, idErr := uuid.NewV7()
	if idErr != nil {
		return Bootstrap{}, idErr
	}
	if _, err = tx.Exec(ctx, `INSERT INTO public.edge_bootstrap_tokens(id,edge_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, tokenID, edgeID, hash[:], expires); err != nil {
		return Bootstrap{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Bootstrap{}, err
	}
	return Bootstrap{EdgeID: edgeID, Region: region, Provider: provider, Token: token, ExpiresAt: expires}, nil
}

func (s Service) Register(ctx context.Context, token string, csrPEM, caPEM []byte) (Registration, error) {
	if s.Pool == nil || s.CA == nil || len(token) < 32 || len(token) > 256 {
		return Registration{}, ErrBootstrapRejected
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return Registration{}, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || !acceptablePublicKey(csr.PublicKey) {
		return Registration{}, errors.New("invalid CSR signature")
	}
	hash := sha256.Sum256([]byte(token))
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Registration{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var edgeID uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE public.edge_bootstrap_tokens SET consumed_at=now() WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>$2 RETURNING edge_id`, hash[:], s.now()).Scan(&edgeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Registration{}, ErrBootstrapRejected
	}
	if err != nil {
		return Registration{}, err
	}
	lifetime := s.CertificateLifetime
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	certPEM, serial, notAfter, err := s.CA.IssueCSR(csrPEM, edgeID, s.now(), lifetime)
	if err != nil {
		return Registration{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO public.edge_certificates(serial,edge_id,status,not_after) VALUES($1,$2,'active',$3)`, serial, edgeID, notAfter); err != nil {
		return Registration{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE public.edges SET cert_serial=$2,cert_not_after=$3,status='registering',updated_at=now() WHERE id=$1`, edgeID, serial, notAfter); err != nil {
		return Registration{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Registration{}, err
	}
	return Registration{EdgeID: edgeID, Certificate: string(certPEM), CACertificate: string(caPEM), Serial: serial, ExpiresAt: notAfter}, nil
}

// RenewCertificate rotates an edge leaf using its current mTLS identity. The previous
// serial remains accepted until expiration to allow in-flight connections to finish.
func (s Service) RenewCertificate(ctx context.Context, edgeID uuid.UUID, currentSerial string, csrPEM, caPEM []byte) (Registration, error) {
	if s.Pool == nil || s.CA == nil {
		return Registration{}, errors.New("fleet certificate dependencies are required")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return Registration{}, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || !acceptablePublicKey(csr.PublicKey) {
		return Registration{}, errors.New("invalid CSR signature")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Registration{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state State
	err = tx.QueryRow(ctx, `SELECT e.status FROM public.edge_certificates c JOIN public.edges e ON e.id=c.edge_id WHERE c.serial=$1 AND c.edge_id=$2 AND c.status='active' AND c.not_after>$3 AND e.compromised_at IS NULL FOR UPDATE OF c,e`, currentSerial, edgeID, s.now()).Scan(&state)
	if err != nil {
		return Registration{}, ErrEdgeCertificateRejected
	}
	if state == Draining || state == Offline || state == Decommissioned {
		return Registration{}, ErrInvalidTransition
	}
	lifetime := s.CertificateLifetime
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	certPEM, serial, notAfter, err := s.CA.IssueCSR(csrPEM, edgeID, s.now(), lifetime)
	if err != nil {
		return Registration{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO public.edge_certificates(serial,edge_id,status,not_after) VALUES($1,$2,'active',$3)`, serial, edgeID, notAfter); err != nil {
		return Registration{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE public.edges SET cert_serial=$2,cert_not_after=$3,updated_at=now() WHERE id=$1`, edgeID, serial, notAfter); err != nil {
		return Registration{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Registration{}, err
	}
	return Registration{EdgeID: edgeID, Certificate: string(certPEM), CACertificate: string(caPEM), Serial: serial, ExpiresAt: notAfter}, nil
}

type Heartbeat struct {
	SnapshotVersion    int64   `json:"snapshot_version"`
	SnapshotAgeSeconds int64   `json:"snapshot_age_seconds"`
	CPUPercent         float64 `json:"cpu_percent"`
	MemoryBytes        uint64  `json:"memory_bytes"`
	RPS                float64 `json:"rps"`
	ErrorRate          float64 `json:"error_rate"`
	P99Millis          float64 `json:"p99_ms"`
	LogDropped         uint64  `json:"log_dropped"`
}

func (h Heartbeat) Validate() error {
	if h.SnapshotVersion < 0 || h.SnapshotAgeSeconds < 0 || h.CPUPercent < 0 || h.CPUPercent > 100 || h.RPS < 0 || h.ErrorRate < 0 || h.ErrorRate > 1 || h.P99Millis < 0 {
		return errors.New("invalid heartbeat metrics")
	}
	return nil
}

func (s Service) Heartbeat(ctx context.Context, edgeID uuid.UUID, serial string, h Heartbeat) error {
	if err := h.Validate(); err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var certStatus string
	err = tx.QueryRow(ctx, `SELECT status FROM public.edge_certificates WHERE serial=$1 AND edge_id=$2 AND not_after>$3 FOR UPDATE`, serial, edgeID, s.now()).Scan(&certStatus)
	if err != nil || certStatus != "active" {
		return ErrEdgeCertificateRejected
	}
	var state State
	if err = tx.QueryRow(ctx, `SELECT status FROM public.edges WHERE id=$1 FOR UPDATE`, edgeID).Scan(&state); err != nil {
		return err
	}
	if state == Draining || state == Offline || state == Decommissioned {
		return ErrInvalidTransition
	}
	next := Ready
	if h.ErrorRate >= 0.2 || h.SnapshotAgeSeconds > 300 {
		next = Degraded
	}
	if state != next && !CanTransition(state, next) {
		return ErrInvalidTransition
	}
	if _, err = tx.Exec(ctx, `UPDATE public.edges SET status=$2,last_heartbeat_at=$3,last_heartbeat=$4::jsonb,snapshot_version=$5,healthy_streak=CASE WHEN $2='ready' THEN healthy_streak+1 ELSE 0 END,unhealthy_streak=CASE WHEN $2='degraded' THEN unhealthy_streak+1 ELSE 0 END,updated_at=now() WHERE id=$1`, edgeID, next, s.now(), marshalHeartbeat(h), h.SnapshotVersion); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func marshalHeartbeat(h Heartbeat) string {
	// Values are numeric-only and the structure is fixed; encoding/json cannot fail for this type.
	b, _ := json.Marshal(h)
	return string(b)
}

type DNSProvider interface {
	EnsureEdge(context.Context, string, uuid.UUID) error
	WithdrawEdge(context.Context, string, uuid.UUID) error
}
type ProviderStub struct{ Name string }

type CloudflareStub struct{}

func (CloudflareStub) EnsureEdge(context.Context, string, uuid.UUID) error {
	return errors.New("cloudflare DNS integration is not configured")
}
func (CloudflareStub) WithdrawEdge(context.Context, string, uuid.UUID) error {
	return errors.New("cloudflare DNS integration is not configured")
}

type Route53Stub struct{}

func (Route53Stub) EnsureEdge(context.Context, string, uuid.UUID) error {
	return errors.New("Route53 DNS integration is not configured")
}
func (Route53Stub) WithdrawEdge(context.Context, string, uuid.UUID) error {
	return errors.New("Route53 DNS integration is not configured")
}

func (p ProviderStub) EnsureEdge(context.Context, string, uuid.UUID) error {
	return fmt.Errorf("%s DNS provider is not configured", p.Name)
}
func (p ProviderStub) WithdrawEdge(context.Context, string, uuid.UUID) error {
	return fmt.Errorf("%s DNS provider is not configured", p.Name)
}

type FakeDNS struct {
	mu      sync.Mutex
	Records map[string]map[uuid.UUID]bool
	Fail    bool
}

func (f *FakeDNS) EnsureEdge(_ context.Context, region string, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail {
		return errors.New("fake DNS failure")
	}
	if f.Records == nil {
		f.Records = map[string]map[uuid.UUID]bool{}
	}
	if f.Records[region] == nil {
		f.Records[region] = map[uuid.UUID]bool{}
	}
	f.Records[region][id] = true
	return nil
}
func (f *FakeDNS) WithdrawEdge(_ context.Context, region string, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Fail {
		return errors.New("fake DNS failure")
	}
	delete(f.Records[region], id)
	return nil
}

type DNSCandidate struct {
	ID              uuid.UUID
	HealthyStreak   int
	UnhealthyStreak int
	Present         bool
}
type DNSAction struct {
	EdgeID uuid.UUID
	Add    bool
}

// PlanDNS applies consecutive-observation hysteresis and a per-pass withdrawal cap.
// It never plans the final active edge for withdrawal.
func PlanDNS(edges []DNSCandidate, consecutive, maxWithdrawals int) []DNSAction {
	if consecutive < 1 {
		consecutive = 1
	}
	if maxWithdrawals < 0 {
		maxWithdrawals = 0
	}
	active := 0
	for _, e := range edges {
		if e.Present {
			active++
		}
	}
	actions := make([]DNSAction, 0)
	for _, e := range edges {
		if !e.Present && e.HealthyStreak >= consecutive {
			actions = append(actions, DNSAction{EdgeID: e.ID, Add: true})
		}
	}
	withdrawn := 0
	for _, e := range edges {
		if e.Present && e.UnhealthyStreak >= consecutive && active-withdrawn > 1 && withdrawn < maxWithdrawals {
			actions = append(actions, DNSAction{EdgeID: e.ID})
			withdrawn++
		}
	}
	return actions
}

// SweepHealth degrades stale heartbeats and reconciles DNS. maxWithdrawalsPerRegion is
// enforced per invocation; schedule the sweeper no more frequently than the desired rate.
func (s Service) SweepHealth(ctx context.Context, providers map[string]DNSProvider, staleAfter time.Duration, consecutive, maxWithdrawalsPerRegion int) error {
	if s.Pool == nil {
		return errors.New("fleet database is required")
	}
	if staleAfter <= 0 {
		staleAfter = 90 * time.Second
	}
	if consecutive < 1 {
		consecutive = 3
	}
	now := s.now()
	_, err := s.Pool.Exec(ctx, `UPDATE public.edges SET unhealthy_streak=unhealthy_streak+1,status=CASE WHEN status='draining' THEN 'draining' WHEN unhealthy_streak+1 >= $2 THEN 'offline' ELSE 'degraded' END,updated_at=now() WHERE status IN ('ready','degraded','draining') AND (status='draining' OR last_heartbeat_at < $1)`, now.Add(-staleAfter), consecutive)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `UPDATE public.edges SET status='offline',updated_at=now() WHERE status='registering' AND created_at<$1`, now.Add(-staleAfter))
	if err != nil {
		return err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,region,provider,status,healthy_streak,unhealthy_streak,dns_present FROM public.edges WHERE status NOT IN ('decommissioned','revoked') ORDER BY region,id`)
	if err != nil {
		return err
	}
	type row struct {
		id               uuid.UUID
		region, provider string
		status           State
		candidate        DNSCandidate
	}
	var all []row
	for rows.Next() {
		var item row
		if err = rows.Scan(&item.id, &item.region, &item.provider, &item.status, &item.candidate.HealthyStreak, &item.candidate.UnhealthyStreak, &item.candidate.Present); err != nil {
			rows.Close()
			return err
		}
		item.candidate.ID = item.id
		if item.status != Ready {
			item.candidate.HealthyStreak = 0
		}
		all = append(all, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	byRegion := map[string][]row{}
	for _, item := range all {
		byRegion[item.region] = append(byRegion[item.region], item)
	}
	var providerFailures []error
	for region, items := range byRegion {
		candidates := make([]DNSCandidate, 0, len(items))
		byID := make(map[uuid.UUID]row, len(items))
		for _, item := range items {
			candidates = append(candidates, item.candidate)
			byID[item.id] = item
		}
		for _, action := range PlanDNS(candidates, consecutive, maxWithdrawalsPerRegion) {
			item := byID[action.EdgeID]
			if !action.Add {
				interval := s.DNSWithdrawalInterval
				if interval <= 0 {
					interval = time.Minute
				}
				allowed, reserveErr := s.reserveDNSWithdrawal(ctx, region, interval)
				if reserveErr != nil {
					return reserveErr
				}
				if !allowed {
					continue
				}
			}
			provider := providers[item.provider]
			if provider == nil {
				provider = ProviderStub{Name: item.provider}
			}
			if action.Add {
				err = provider.EnsureEdge(ctx, region, item.id)
			} else {
				err = provider.WithdrawEdge(ctx, region, item.id)
			}
			if err != nil {
				providerFailures = append(providerFailures, fmt.Errorf("DNS reconcile region=%q edge=%s: %w", region, item.id, err))
				continue
			}
			_, err = s.Pool.Exec(ctx, `UPDATE public.edges SET dns_present=$2,updated_at=now() WHERE id=$1`, item.id, action.Add)
			if err != nil {
				return err
			}
		}
	}
	return errors.Join(providerFailures...)
}

func (s Service) reserveDNSWithdrawal(ctx context.Context, region string, interval time.Duration) (bool, error) {
	var reserved string
	err := s.Pool.QueryRow(ctx, `INSERT INTO public.edge_dns_withdrawal_limits(region,last_withdrawal_at) VALUES($1,$2) ON CONFLICT(region) DO UPDATE SET last_withdrawal_at=EXCLUDED.last_withdrawal_at WHERE public.edge_dns_withdrawal_limits.last_withdrawal_at<=EXCLUDED.last_withdrawal_at-($3*interval '1 millisecond') RETURNING region`, region, s.now(), interval.Milliseconds()).Scan(&reserved)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return reserved == region, nil
}

func (s Service) Drain(ctx context.Context, edgeID uuid.UUID) error {
	result, err := s.Pool.Exec(ctx, `UPDATE public.edges SET status='draining',updated_at=now() WHERE id=$1 AND status IN ('ready','degraded')`, edgeID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrInvalidTransition
	}
	return nil
}

func (s Service) Decommission(ctx context.Context, edgeID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var region string
	var present bool
	var state State
	if err = tx.QueryRow(ctx, `SELECT region,dns_present,status FROM public.edges WHERE id=$1 FOR UPDATE`, edgeID).Scan(&region, &present, &state); err != nil {
		return err
	}
	if state != Draining && state != Offline {
		return ErrInvalidTransition
	}
	if present {
		return errors.New("DNS withdrawal must complete before decommission")
	}
	if _, err = tx.Exec(ctx, `UPDATE public.edges SET dns_present=false,status='decommissioned',decommissioned_at=$2,updated_at=now() WHERE id=$1`, edgeID, s.now()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE public.edge_certificates SET status='revoked',revoked_at=$2 WHERE edge_id=$1 AND status='active'`, edgeID, s.now()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s Service) RevokeCompromised(ctx context.Context, edgeID uuid.UUID, dns DNSProvider) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var region string
	var present bool
	if err = tx.QueryRow(ctx, `SELECT region,dns_present FROM public.edges WHERE id=$1 FOR UPDATE`, edgeID).Scan(&region, &present); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE public.edges SET status='offline',compromised_at=$2,updated_at=now() WHERE id=$1 AND status<>'decommissioned'`, edgeID, s.now()); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE public.edge_certificates SET status='revoked',revoked_at=$2 WHERE edge_id=$1 AND status='active'`, edgeID, s.now()); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if present {
		if dns == nil {
			return errors.New("edge certificate revoked; DNS provider is required for withdrawal")
		}
		if err = dns.WithdrawEdge(ctx, region, edgeID); err != nil {
			return errors.Join(errors.New("edge certificate revoked but DNS withdrawal failed"), err)
		}
		if _, err = s.Pool.Exec(ctx, `UPDATE public.edges SET dns_present=false WHERE id=$1`, edgeID); err != nil {
			return err
		}
	}
	return nil
}

// CertificateActive checks revocation and expiry using the same persisted serial that mTLS presents.
func (s Service) CertificateActive(ctx context.Context, edgeID uuid.UUID, serial string) bool {
	var active bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.edge_certificates c JOIN public.edges e ON e.id=c.edge_id WHERE c.serial=$1 AND c.edge_id=$2 AND c.status='active' AND c.not_after>$3 AND e.status NOT IN ('offline','decommissioned','revoked') AND e.compromised_at IS NULL)`, serial, edgeID, s.now()).Scan(&active)
	return err == nil && active
}

// keep pgx.Tx in this package's public API documentation and prevent accidental query-only pool mocks.
var _ pgx.Tx
