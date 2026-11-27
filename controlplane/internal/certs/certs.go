package certs

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/example/wafplatform/controlplane/internal/platform/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrIssuerUnavailable = errors.New("certificate issuer is unavailable")

type Order struct {
	DomainID uuid.UUID
	Hostname string
	Wildcard bool
}
type Issued struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	NotAfter       time.Time
	Issuer         string
}
type ACMEIssuer interface {
	Issue(context.Context, Order) (Issued, error)
	Revoke(context.Context, string) error
}
type ChallengePublisher interface {
	PublishHTTP01(context.Context, string, string) error
}
type DNS01Provider interface {
	PublishDNS01(context.Context, string, string) error
}
type DNS01Stub struct{ Name string }

func (p DNS01Stub) PublishDNS01(context.Context, string, string) error {
	return fmt.Errorf("%s DNS-01 provider is not configured", p.Name)
}

// ProviderStub marks the production provider boundary. Wire lego/certmagic here in deployment.
type ProviderStub struct{ Name string }

func (p ProviderStub) Issue(context.Context, Order) (Issued, error) {
	return Issued{}, fmt.Errorf("%s ACME provider is not configured: %w", p.Name, ErrIssuerUnavailable)
}
func (p ProviderStub) Revoke(context.Context, string) error {
	return fmt.Errorf("%s ACME provider is not configured: %w", p.Name, ErrIssuerUnavailable)
}

type FakeIssuer struct {
	Now     func() time.Time
	Calls   int
	Revoked []string
	Fail    error
}

func (f *FakeIssuer) Issue(_ context.Context, o Order) (Issued, error) {
	f.Calls++
	if f.Fail != nil {
		return Issued{}, f.Fail
	}
	now := time.Now()
	if f.Now != nil {
		now = f.Now()
	}
	return Issued{CertificatePEM: []byte("fake-certificate:" + o.Hostname), PrivateKeyPEM: []byte("fake-private-key"), NotAfter: now.Add(90 * 24 * time.Hour), Issuer: "fake"}, nil
}
func (f *FakeIssuer) Revoke(_ context.Context, ref string) error {
	f.Revoked = append(f.Revoked, ref)
	return f.Fail
}

type Manager struct {
	Pool               *pgxpool.Pool
	Issuer             ACMEIssuer
	Secrets            secret.Store
	Now                func() time.Time
	MaxOrdersPerMinute int
	RateLimitKey       string
	mu                 sync.Mutex
	active             map[uuid.UUID]struct{}
	window             time.Time
	orders             int
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}
func (m *Manager) claim(id uuid.UUID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.active == nil {
		m.active = map[uuid.UUID]struct{}{}
	}
	if _, ok := m.active[id]; ok {
		return false
	}
	if m.window.IsZero() || now.Sub(m.window) >= time.Minute {
		m.window = now
		m.orders = 0
	}
	limit := m.MaxOrdersPerMinute
	if limit <= 0 {
		limit = 10
	}
	if m.orders >= limit {
		return false
	}
	m.orders++
	m.active[id] = struct{}{}
	return true
}
func (m *Manager) release(id uuid.UUID) { m.mu.Lock(); delete(m.active, id); m.mu.Unlock() }

// RenewDue claims each due certificate transactionally, performs issuance outside the
// transaction, keeps private material only in SecretStore, and schedules bounded backoff.
func (m *Manager) RenewDue(ctx context.Context, limit int) (int, error) {
	if m.Pool == nil || m.Issuer == nil || m.Secrets == nil {
		return 0, errors.New("certificate manager dependencies are required")
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	tx, err := m.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT c.id,c.tenant_id,c.domain_id,d.hostname,c.renewal_attempts,c.not_after,c.secret_ref FROM public.certificates c JOIN public.domains d ON d.id=c.domain_id WHERE c.status IN ('active','renewing') AND c.not_after<= $1 AND (c.next_attempt_at IS NULL OR c.next_attempt_at<=$2) AND (c.status='active' OR c.renewal_claimed_at IS NULL OR c.renewal_claimed_at<=$2-interval '5 minutes') ORDER BY c.not_after FOR UPDATE OF c SKIP LOCKED LIMIT $3`, m.now().Add(30*24*time.Hour), m.now(), limit)
	if err != nil {
		return 0, err
	}
	type candidate struct {
		id, tenant, domain uuid.UUID
		hostname           string
		attempts           int
		notAfter           time.Time
		oldRef             string
	}
	var batch []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.tenant, &c.domain, &c.hostname, &c.attempts, &c.notAfter, &c.oldRef); err != nil {
			rows.Close()
			return 0, err
		}
		if m.claim(c.domain) {
			batch = append(batch, c)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	rateLimitKey := m.RateLimitKey
	if rateLimitKey == "" {
		rateLimitKey = "default"
	}
	issuerLimit := m.MaxOrdersPerMinute
	if issuerLimit <= 0 {
		issuerLimit = 10
	}
	eligible := batch[:0]
	for _, c := range batch {
		allowed, rateErr := reserveIssuerQuota(ctx, tx, rateLimitKey, issuerLimit, m.now())
		if rateErr != nil {
			for _, b := range batch {
				m.release(b.domain)
			}
			return 0, rateErr
		}
		if !allowed {
			m.release(c.domain)
			continue
		}
		if _, err = tx.Exec(ctx, `UPDATE public.certificates SET status='renewing',renewal_claimed_at=$2,updated_at=now() WHERE id=$1`, c.id, m.now()); err != nil {
			for _, b := range batch {
				m.release(b.domain)
			}
			return 0, err
		}
		eligible = append(eligible, c)
	}
	batch = eligible
	if err = tx.Commit(ctx); err != nil {
		for _, b := range batch {
			m.release(b.domain)
		}
		return 0, err
	}
	renewed := 0
	var workerErrors []error
	for _, c := range batch {
		issued, issueErr := m.Issuer.Issue(ctx, Order{DomainID: c.domain, Hostname: c.hostname, Wildcard: strings.HasPrefix(c.hostname, "*.")})
		if issueErr == nil {
			ref := secretRef(c.id, issued.CertificatePEM)
			issueErr = m.Secrets.Put(ctx, ref, issued.CertificatePEM)
			if issueErr == nil {
				issueErr = m.Secrets.Put(ctx, ref+"/private-key", issued.PrivateKeyPEM)
			}
			if issueErr == nil {
				_, issueErr = m.Pool.Exec(ctx, `UPDATE public.certificates SET status='active',secret_ref=$2,issuer=$3,not_after=$4,renewal_attempts=0,next_attempt_at=NULL,renewal_claimed_at=NULL,last_error_code='',updated_at=now() WHERE id=$1`, c.id, ref, issued.Issuer, issued.NotAfter)
			}
			if issueErr != nil {
				_ = m.Secrets.Delete(ctx, ref)
				_ = m.Secrets.Delete(ctx, ref+"/private-key")
			} else if c.oldRef != "" && c.oldRef != ref {
				if deleteErr := m.Secrets.Delete(ctx, c.oldRef+"/private-key"); deleteErr != nil && !errors.Is(deleteErr, secret.ErrNotFound) {
					workerErrors = append(workerErrors, fmt.Errorf("delete replaced certificate private key: %w", deleteErr))
				}
				if deleteErr := m.Secrets.Delete(ctx, c.oldRef); deleteErr != nil && !errors.Is(deleteErr, secret.ErrNotFound) {
					workerErrors = append(workerErrors, fmt.Errorf("delete replaced certificate: %w", deleteErr))
				}
			}
		}
		if issueErr != nil {
			attempt := c.attempts + 1
			delay := retryDelay(attempt)
			_, dbErr := m.Pool.Exec(ctx, `UPDATE public.certificates SET status='active',renewal_attempts=$2,next_attempt_at=$3,renewal_claimed_at=NULL,last_error_code='issuer_failure',updated_at=now() WHERE id=$1`, c.id, attempt, m.now().Add(delay))
			if dbErr != nil {
				workerErrors = append(workerErrors, fmt.Errorf("schedule certificate retry: %w", dbErr))
			}
			if dbErr == nil && !c.notAfter.After(m.now().Add(14*24*time.Hour)) {
				alertID, idErr := uuid.NewV7()
				if idErr != nil {
					workerErrors = append(workerErrors, idErr)
				} else if _, alertErr := m.Pool.Exec(ctx, `INSERT INTO public.alerts(id,tenant_id,status,details) SELECT $1,$2,'open',jsonb_build_object('kind','certificate_renewal_failed','certificate_id',$3::text,'expires_at',$4::text) WHERE NOT EXISTS(SELECT 1 FROM public.alerts WHERE tenant_id=$2 AND status='open' AND details->>'kind'='certificate_renewal_failed' AND details->>'certificate_id'=$3::text)`, alertID, c.tenant, c.id, c.notAfter.UTC().Format(time.RFC3339)); alertErr != nil {
					workerErrors = append(workerErrors, fmt.Errorf("persist certificate renewal warning: %w", alertErr))
				}
			}
		} else {
			renewed++
		}
		m.release(c.domain)
	}
	return renewed, errors.Join(workerErrors...)
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 11 {
		return 24 * time.Hour
	}
	d := time.Minute * time.Duration(1<<uint(attempt-1))
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}

func reserveIssuerQuota(ctx context.Context, tx pgx.Tx, issuer string, limit int, now time.Time) (bool, error) {
	var count int
	err := tx.QueryRow(ctx, `INSERT INTO public.certificate_issuance_rate_limits(issuer_key,window_started_at,orders_count) VALUES($1,$2,1) ON CONFLICT(issuer_key) DO UPDATE SET window_started_at=CASE WHEN public.certificate_issuance_rate_limits.window_started_at<=EXCLUDED.window_started_at-interval '1 minute' THEN EXCLUDED.window_started_at ELSE public.certificate_issuance_rate_limits.window_started_at END,orders_count=CASE WHEN public.certificate_issuance_rate_limits.window_started_at<=EXCLUDED.window_started_at-interval '1 minute' THEN 1 ELSE public.certificate_issuance_rate_limits.orders_count+1 END WHERE public.certificate_issuance_rate_limits.window_started_at<=EXCLUDED.window_started_at-interval '1 minute' OR public.certificate_issuance_rate_limits.orders_count<$3 RETURNING orders_count`, issuer, now, limit).Scan(&count)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return count <= limit, nil
}

func secretRef(id uuid.UUID, cert []byte) string {
	sum := sha256.Sum256(cert)
	return fmt.Sprintf("certificates/%s/%s", id, hex.EncodeToString(sum[:8]))
}

// ValidateCustomerUpload verifies certificate/key match, validity and trust chain.
func ValidateCustomerUpload(certPEM, keyPEM []byte, roots *x509.CertPool, hostname string, now time.Time) (tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate and private key do not match: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return tls.Certificate{}, errors.New("certificate is expired or not yet valid")
	}
	if err = leaf.VerifyHostname(hostname); err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate hostname mismatch: %w", err)
	}
	if roots == nil {
		return tls.Certificate{}, errors.New("certificate trust roots are required")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if c, e := x509.ParseCertificate(der); e == nil {
			intermediates.AddCert(c)
		}
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate chain rejected: %w", err)
	}
	pair.Leaf = leaf
	return pair, nil
}

func (m *Manager) RevokeAndDelete(ctx context.Context, certificateID uuid.UUID) error {
	var ref string
	if err := m.Pool.QueryRow(ctx, `SELECT secret_ref FROM public.certificates WHERE id=$1`, certificateID).Scan(&ref); err != nil {
		return err
	}
	certificate, secretErr := m.Secrets.Get(ctx, ref)
	if secretErr != nil && !errors.Is(secretErr, secret.ErrNotFound) {
		return secretErr
	}
	if err := m.Issuer.Revoke(ctx, string(certificate)); err != nil && !errors.Is(err, ErrIssuerUnavailable) {
		return err
	}
	if err := m.Secrets.Delete(ctx, ref); err != nil && !errors.Is(err, secret.ErrNotFound) {
		return err
	}
	if err := m.Secrets.Delete(ctx, ref+"/private-key"); err != nil && !errors.Is(err, secret.ErrNotFound) {
		return err
	}
	_, err := m.Pool.Exec(ctx, `UPDATE public.certificates SET status='revoked',updated_at=now() WHERE id=$1`, certificateID)
	return err
}

// CertificateStatus is intentionally small and excludes private material.
type CertificateStatus struct {
	ID            uuid.UUID
	ExpiresAt     time.Time
	DaysRemaining int
	RenewalDue    bool
}

func Status(id uuid.UUID, notAfter, now time.Time) CertificateStatus {
	return CertificateStatus{ID: id, ExpiresAt: notAfter, DaysRemaining: int(notAfter.Sub(now).Hours() / 24), RenewalDue: notAfter.Before(now.Add(30 * 24 * time.Hour))}
}
