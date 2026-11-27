package configsync

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const maxControlPlaneResponse = 32 << 20

// HTTPClient implements the edge CP contract. Registration uses the supplied
// HTTPS bootstrap client; all later API calls require the issued mTLS identity.
type HTTPClient struct {
	base      *url.URL
	bootstrap *http.Client
	client    *http.Client
	cert      atomic.Pointer[tls.Certificate]
}

func NewHTTPClient(baseURL string, roots *x509.CertPool, timeout time.Duration) (*HTTPClient, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("control plane URL must be an absolute HTTPS URL without userinfo, query, or fragment")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	h := &HTTPClient{base: base}
	transport := func(requireClientCert bool) *http.Transport {
		config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
		if requireClientCert {
			config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert := new(tls.Certificate)
				if c := h.cert.Load(); c != nil {
					return c, nil
				}
				return cert, errors.New("control plane mTLS certificate is not installed")
			}
		}
		return &http.Transport{TLSClientConfig: config, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: timeout, IdleConnTimeout: 90 * time.Second}
	}
	h.bootstrap = &http.Client{Transport: transport(false), Timeout: timeout}
	h.client = &http.Client{Transport: transport(true), Timeout: timeout}
	checkRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.bootstrap.CheckRedirect, h.client.CheckRedirect = checkRedirect, checkRedirect
	return h, nil
}

func (h *HTTPClient) SetClientCertificate(cert tls.Certificate) {
	copy := cert
	h.cert.Store(&copy)
	h.client.CloseIdleConnections()
}

func (h *HTTPClient) endpoint(path string) string {
	u := *h.base
	rel, err := url.Parse(path)
	if err != nil {
		return ""
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(rel.Path, "/")
	u.RawQuery = rel.RawQuery
	return u.String()
}

func (h *HTTPClient) do(ctx context.Context, client *http.Client, method, path string, body []byte, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, h.endpoint(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
func readLimited(resp *http.Response) (data []byte, err error) {
	defer func() {
		if closeErr := resp.Body.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxControlPlaneResponse+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxControlPlaneResponse {
		return nil, errors.New("control plane response exceeds 32 MiB")
	}
	return data, nil
}
func expectOK(resp *http.Response) ([]byte, error) {
	data, err := readLimited(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("control plane returned HTTP %d", resp.StatusCode)
	}
	return data, nil
}

func (h *HTTPClient) Register(ctx context.Context, token string, csr []byte) (Registration, error) {
	if token == "" || len(token) > 4096 || len(csr) == 0 || len(csr) > 16<<10 {
		return Registration{}, errors.New("invalid one-time registration credentials")
	}
	body, err := json.Marshal(struct {
		CSR string `json:"csr_pem"`
	}{string(csr)})
	if err != nil {
		return Registration{}, err
	}
	resp, err := h.do(ctx, h.bootstrap, http.MethodPost, "/v1/edges/register", body, token)
	if err != nil {
		return Registration{}, err
	}
	raw, err := expectOK(resp)
	if err != nil {
		return Registration{}, err
	}
	var got Registration
	if err = json.Unmarshal(raw, &got); err != nil {
		return Registration{}, err
	}
	return got, nil
}
func (h *HTTPClient) RenewCertificate(ctx context.Context, edgeID string, csr []byte) (IssuedCertificate, error) {
	if edgeID == "" || len(csr) == 0 || len(csr) > 16<<10 {
		return IssuedCertificate{}, errors.New("invalid certificate renewal request")
	}
	body, _ := json.Marshal(struct {
		CSR string `json:"csr_pem"`
	}{string(csr)})
	resp, err := h.do(ctx, h.client, http.MethodPost, "/v1/edges/"+url.PathEscape(edgeID)+"/certificate", body, "")
	if err != nil {
		return IssuedCertificate{}, err
	}
	raw, err := expectOK(resp)
	if err != nil {
		return IssuedCertificate{}, err
	}
	var cert IssuedCertificate
	if err = json.Unmarshal(raw, &cert); err != nil {
		return cert, err
	}
	return cert, nil
}
func (h *HTTPClient) FetchSnapshot(ctx context.Context, edgeID string, since uint64, etag string) (SnapshotReply, error) {
	if edgeID == "" {
		return SnapshotReply{}, errors.New("empty edge id")
	}
	query := url.Values{}
	query.Set("since", strconv.FormatUint(since, 10))
	query.Set("edge_id", edgeID)
	path := "/internal/snapshot?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.endpoint(path), nil)
	if err != nil {
		return SnapshotReply{}, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return SnapshotReply{}, err
	}
	if resp.StatusCode == http.StatusNotModified {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return SnapshotReply{}, closeErr
		}
		return SnapshotReply{StatusCode: resp.StatusCode, ETag: resp.Header.Get("ETag")}, nil
	}
	data, err := readLimited(resp)
	if err != nil {
		return SnapshotReply{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return SnapshotReply{}, fmt.Errorf("snapshot endpoint returned HTTP %d", resp.StatusCode)
	}
	return SnapshotReply{StatusCode: resp.StatusCode, ETag: resp.Header.Get("ETag"), Body: data}, nil
}
func (h *HTTPClient) SendHeartbeat(ctx context.Context, edgeID string, hb Heartbeat) error {
	if edgeID == "" {
		return errors.New("empty edge id")
	}
	body, err := json.Marshal(hb)
	if err != nil {
		return err
	}
	resp, err := h.do(ctx, h.client, http.MethodPost, "/v1/edges/"+url.PathEscape(edgeID)+"/heartbeat", body, "")
	if err != nil {
		return err
	}
	_, err = expectOK(resp)
	return err
}
func (h *HTTPClient) FetchSecrets(ctx context.Context, edgeID string) (SecretBundle, error) {
	if edgeID == "" {
		return SecretBundle{}, errors.New("empty edge id")
	}
	resp, err := h.do(ctx, h.client, http.MethodGet, "/v1/edges/"+url.PathEscape(edgeID)+"/secrets", nil, "")
	if err != nil {
		return SecretBundle{}, err
	}
	raw, err := expectOK(resp)
	if err != nil {
		return SecretBundle{}, err
	}
	var wire struct {
		Values       map[string][]byte `json:"values"`
		Certificates map[string]struct {
			CertificatePEM string `json:"certificate_pem"`
			PrivateKeyPEM  string `json:"private_key_pem"`
		} `json:"certificates"`
	}
	if err = json.Unmarshal(raw, &wire); err != nil {
		return SecretBundle{}, err
	}
	bundle := SecretBundle{Values: wire.Values, Certificates: map[string]tls.Certificate{}}
	for host, pair := range wire.Certificates {
		cert, e := tls.X509KeyPair([]byte(pair.CertificatePEM), []byte(pair.PrivateKeyPEM))
		if e != nil {
			return SecretBundle{}, fmt.Errorf("invalid TLS certificate for SNI %q: %w", host, e)
		}
		bundle.Certificates[host] = cert
	}
	return bundle, nil
}
