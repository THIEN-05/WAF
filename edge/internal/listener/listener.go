package listener

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
)

type Fingerprinter interface {
	Fingerprint(*tls.ClientHelloInfo) (ja3, ja4 string)
}
type StubFingerprinter struct{}

func (StubFingerprinter) Fingerprint(*tls.ClientHelloInfo) (string, string) { return "", "" }

type CertCache struct {
	mu      sync.RWMutex
	certs   map[string]*tls.Certificate
	Default *tls.Certificate
}

func NewCertCache() *CertCache { return &CertCache{certs: map[string]*tls.Certificate{}} }
func NewSelfSignedDefault() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "waf edge default"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"waf.invalid"}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
func (c *CertCache) Put(host string, cert *tls.Certificate) {
	c.mu.Lock()
	c.certs[strings.ToLower(strings.TrimSuffix(host, "."))] = cert
	c.mu.Unlock()
}
func (c *CertCache) Get(host string) *tls.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cert := c.certs[strings.ToLower(strings.TrimSuffix(host, "."))]; cert != nil {
		return cert
	}
	return c.Default
}

type Config struct {
	HTTPAddr, TLSAddr              string
	ReadHeaderTimeout, IdleTimeout time.Duration
	ClientHelloTimeout             time.Duration
	MaxHeaderBytes, MaxPerIP       int
	TrustedProxyCIDRs              []string
	EnableProxyProtocol            bool
	Cache                          *CertCache
	HTTPChallengeToken             func(string) (string, bool)
	CanonicalHTTPHost              func(string) (string, bool)
	Fingerprinter                  Fingerprinter
}
type Servers struct {
	HTTP, TLS         *http.Server
	limit             *perIPLimiter
	listeners         []net.Listener
	HTTPAddr, TLSAddr string
}

func NewHTTPHandler(challenge func(string) (string, bool), redirectPort string, canonicalHost func(string) (string, bool)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const challengePrefix = "/.well-known/acme-challenge/"
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, challengePrefix) {
			token := strings.TrimPrefix(r.URL.Path, challengePrefix)
			if token == "" || challenge == nil {
				http.NotFound(w, r)
				return
			}
			value, ok := challenge(token)
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, value)
			return
		}
		host, ok := "", false
		if canonicalHost != nil {
			host, ok = canonicalHost(r.Host)
		}
		if !ok || host == "" {
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		if redirectPort != "443" && redirectPort != "" {
			host = net.JoinHostPort(host, redirectPort)
		}
		requestPath := r.URL.Path
		if requestPath == "" {
			requestPath = "/"
		}
		location := url.URL{Scheme: "https", Host: host, Path: requestPath, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
		w.Header().Set("Location", location.String())
		w.WriteHeader(http.StatusPermanentRedirect)
	})
}
func Start(cfg Config, handler http.Handler) (*Servers, error) {
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":80"
	}
	if cfg.TLSAddr == "" {
		cfg.TLSAddr = ":443"
	}
	if cfg.Cache == nil {
		cfg.Cache = NewCertCache()
	}
	if cfg.Cache.Default == nil {
		cert, err := NewSelfSignedDefault()
		if err != nil {
			return nil, fmt.Errorf("create default certificate: %w", err)
		}
		cfg.Cache.Default = cert
	}
	if cfg.Fingerprinter == nil {
		cfg.Fingerprinter = StubFingerprinter{}
	}
	if cfg.ReadHeaderTimeout == 0 {
		cfg.ReadHeaderTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 90 * time.Second
	}
	if cfg.ClientHelloTimeout == 0 {
		cfg.ClientHelloTimeout = 3 * time.Second
	}
	if cfg.MaxHeaderBytes == 0 {
		cfg.MaxHeaderBytes = 48 << 10
	}
	if cfg.MaxPerIP == 0 {
		cfg.MaxPerIP = 200
	}
	limiter := newPerIPLimiter(cfg.MaxPerIP)
	httpLn, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return nil, err
	}
	tlsLn, err := net.Listen("tcp", cfg.TLSAddr)
	if err != nil {
		if closeErr := httpLn.Close(); closeErr != nil {
			return nil, errors.Join(fmt.Errorf("listen TLS: %w", err), fmt.Errorf("close HTTP listener: %w", closeErr))
		}
		return nil, err
	}
	trusted := parseCIDRs(cfg.TrustedProxyCIDRs)
	if cfg.EnableProxyProtocol {
		httpLn = proxyProtocolListener{Listener: httpLn, trusted: trusted}
		tlsLn = proxyProtocolListener{Listener: tlsLn, trusted: trusted}
	}
	httpLn = limiter.Wrap(httpLn)
	tlsLn = limiter.Wrap(tlsLn)
	httpSrv := &http.Server{Handler: NewHTTPHandler(cfg.HTTPChallengeToken, "443", cfg.CanonicalHTTPHost), ReadHeaderTimeout: cfg.ReadHeaderTimeout, IdleTimeout: cfg.IdleTimeout, MaxHeaderBytes: cfg.MaxHeaderBytes}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		_, _ = cfg.Fingerprinter.Fingerprint(hello)
		return cfg.Cache.Get(hello.ServerName), nil
	}}
	tlsSrv := &http.Server{Handler: handler, TLSConfig: tlsCfg, ReadHeaderTimeout: cfg.ReadHeaderTimeout, IdleTimeout: cfg.IdleTimeout, MaxHeaderBytes: cfg.MaxHeaderBytes,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if tlsConn, ok := conn.(*tls.Conn); ok {
				if capture, ok := tlsConn.NetConn().(*helloCaptureConn); ok {
					return reqctx.WithFingerprintSource(ctx, capture)
				}
			}
			return ctx
		},
	}
	servers := &Servers{HTTP: httpSrv, TLS: tlsSrv, limit: limiter, listeners: []net.Listener{httpLn, tlsLn}, HTTPAddr: httpLn.Addr().String(), TLSAddr: tlsLn.Addr().String()}
	go func() { _ = httpSrv.Serve(httpLn) }()
	go func() {
		_ = tlsSrv.Serve(tls.NewListener(helloCaptureListener{Listener: tlsLn, PeekTimeout: cfg.ClientHelloTimeout}, tlsCfg))
	}()
	return servers, nil
}
func (s *Servers) Shutdown(ctx context.Context) error {
	e1 := s.HTTP.Shutdown(ctx)
	e2 := s.TLS.Shutdown(ctx)
	_ = s.limit
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	if e1 != nil {
		return e1
	}
	return e2
}

type perIPLimiter struct {
	max    int
	mu     sync.Mutex
	counts map[string]int
	conns  map[net.Conn]string
}

func newPerIPLimiter(max int) *perIPLimiter {
	return &perIPLimiter{max: max, counts: map[string]int{}, conns: map[net.Conn]string{}}
}
func (l *perIPLimiter) Wrap(base net.Listener) net.Listener {
	return &limitedListener{Listener: base, limiter: l}
}
func (l *perIPLimiter) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for c := range l.conns {
		_ = c.Close()
	}
}

type limitedListener struct {
	net.Listener
	limiter *perIPLimiter
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		l.limiter.mu.Lock()
		if l.limiter.counts[host] >= l.limiter.max {
			l.limiter.mu.Unlock()
			_ = c.Close()
			continue
		}
		l.limiter.counts[host]++
		l.limiter.conns[c] = host
		l.limiter.mu.Unlock()
		return &limitedConn{Conn: c, onClose: func() {
			l.limiter.mu.Lock()
			defer l.limiter.mu.Unlock()
			delete(l.limiter.conns, c)
			l.limiter.counts[host]--
		}}, nil
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.onClose); return err }

func parseCIDRs(values []string) []*net.IPNet {
	out := []*net.IPNet{}
	for _, v := range values {
		_, n, e := net.ParseCIDR(v)
		if e == nil {
			out = append(out, n)
		}
	}
	return out
}

type proxyProtocolListener struct {
	net.Listener
	trusted []*net.IPNet
}

const proxyProtocolV1MaxLine = 108

func (l proxyProtocolListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		remote := net.ParseIP(host)
		trusted := false
		for _, n := range l.trusted {
			if n.Contains(remote) {
				trusted = true
				break
			}
		}
		if !trusted {
			return c, nil
		}
		parsed, parseErr := parseProxyProtocolV1(c)
		if parseErr != nil {
			// A malformed preamble must not turn one bad connection into a
			// permanent http.Server.Serve accept failure.
			_ = c.Close()
			continue
		}
		return parsed, nil
	}
}

func parseProxyProtocolV1(c net.Conn) (net.Conn, error) {
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, fmt.Errorf("set PROXY protocol read deadline: %w", err)
	}
	br := bufio.NewReaderSize(c, proxyProtocolV1MaxLine+1)
	line, e := br.ReadSlice('\n')
	clearErr := c.SetReadDeadline(time.Time{})
	if e != nil {
		return nil, e
	}
	if clearErr != nil {
		return nil, fmt.Errorf("clear PROXY protocol read deadline: %w", clearErr)
	}
	if len(line) > proxyProtocolV1MaxLine || !strings.HasSuffix(string(line), "\r\n") {
		return nil, fmt.Errorf("invalid or oversized PROXY protocol v1 header")
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, fmt.Errorf("invalid PROXY protocol v1 header")
	}
	if fields[1] == "UNKNOWN" {
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid PROXY UNKNOWN header")
		}
		return &bufferedConn{Conn: c, r: br}, nil
	}
	if len(fields) != 6 || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return nil, fmt.Errorf("invalid PROXY protocol address")
	}
	src := net.ParseIP(fields[2])
	dst := net.ParseIP(fields[3])
	port, e := strconv.Atoi(fields[4])
	dstPort, dstPortErr := strconv.Atoi(fields[5])
	validFamily := src != nil && dst != nil && ((fields[1] == "TCP4" && src.To4() != nil && dst.To4() != nil) || (fields[1] == "TCP6" && src.To4() == nil && dst.To4() == nil))
	if !validFamily || e != nil || dstPortErr != nil || port < 0 || port > 65535 || dstPort < 0 || dstPort > 65535 {
		return nil, fmt.Errorf("invalid PROXY source")
	}
	return &proxyConn{bufferedConn: bufferedConn{Conn: c, r: br}, remote: &net.TCPAddr{IP: src, Port: port}}, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type proxyConn struct {
	bufferedConn
	remote net.Addr
}

func (c *proxyConn) RemoteAddr() net.Addr { return c.remote }
