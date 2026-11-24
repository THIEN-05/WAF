package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/router"
)

func TestHTTPChallengeAndRedirect(t *testing.T) {
	h := NewHTTPHandler(func(token string) (string, bool) { return "proof-" + token, token == "good" }, "443", canonicalTestHTTPHost)
	for _, tc := range []struct {
		path   string
		status int
		body   string
		host   string
	}{{"/.well-known/acme-challenge/good", 200, "proof-good", "unknown.test"}, {"/.well-known/acme-challenge/missing", 404, "", "known.test"}, {"/path?q=1", 308, "", "known.test"}} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://known.test"+tc.path, nil)
		req.Host = tc.host
		h.ServeHTTP(rr, req)
		if rr.Code != tc.status {
			t.Errorf("%s status=%d", tc.path, rr.Code)
		}
		if tc.body != "" && !strings.Contains(rr.Body.String(), tc.body) {
			t.Errorf("body=%q", rr.Body.String())
		}
		if tc.status == 308 && rr.Header().Get("Location") != "https://known.test/path?q=1" {
			t.Errorf("location=%q", rr.Header().Get("Location"))
		}
	}
}

func TestHTTPRedirectRejectsUnknownHost(t *testing.T) {
	h := NewHTTPHandler(nil, "443", canonicalTestHTTPHost)
	for _, host := range []string{"evil.com", "known.test@evil.com", "known.test:80:evil", "known.test:bad", "user@known.test", "known.test/evil", "known.test\r\nX-Evil: yes", strings.Repeat("a", 300) + ".test", "[2001:db8::1]", "xn--e1afmkfd.xn--p1ai"} {
		r := httptest.NewRequest(http.MethodGet, "http://known.test/path", nil)
		r.Host = host
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != http.StatusMisdirectedRequest || rr.Header().Get("Location") != "" {
			t.Errorf("Host=%q status=%d location=%q", host, rr.Code, rr.Header().Get("Location"))
		}
	}
}

func TestHTTPRedirectUsesCanonicalHostAndKeepsPathQuery(t *testing.T) {
	h := NewHTTPHandler(nil, "443", canonicalTestHTTPHost)
	r := httptest.NewRequest(http.MethodGet, "http://known.test/a%2Fb?q=a%2Fb&x=1", nil)
	r.Host = "KNOWN.TEST.:80"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if got, want := rr.Header().Get("Location"), "https://known.test/a%2Fb?q=a%2Fb&x=1"; rr.Code != http.StatusPermanentRedirect || got != want {
		t.Fatalf("status=%d location=%q want %q", rr.Code, got, want)
	}

	r = httptest.NewRequest(http.MethodGet, "http://known.test/", nil)
	r.URL.Path = "//evil.com/path"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || u.Host != "known.test" || !strings.HasPrefix(u.Path, "//evil.com/") {
		t.Fatalf("external redirect location=%q parsed=%+v err=%v", rr.Header().Get("Location"), u, err)
	}
	r.URL.Path = "/\\evil.com/path"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	u, err = url.Parse(rr.Header().Get("Location"))
	if err != nil || u.Host != "known.test" {
		t.Fatalf("backslash path escaped canonical host: location=%q parsed=%+v err=%v", rr.Header().Get("Location"), u, err)
	}
}

func canonicalTestHTTPHost(host string) (string, bool) {
	canonical := router.NormalizeHost(host)
	return canonical, canonical == "known.test"
}
func TestMissingCertificateFallsBack(t *testing.T) {
	cache := NewCertCache()
	cert, err := NewSelfSignedDefault()
	if err != nil {
		t.Fatal(err)
	}
	cache.Default = cert
	if cache.Get("unknown.test") == nil {
		t.Fatal("missing SNI should receive default certificate")
	}
}

func TestLoopbackUnknownSNIUsesFallbackThenHTTPRejectsMismatch(t *testing.T) {
	servers, err := Start(Config{HTTPAddr: "127.0.0.1:0", TLSAddr: "127.0.0.1:0", Cache: NewCertCache()}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "site.test" || r.Host != "site.test" {
			http.Error(w, "misdirected", http.StatusMisdirectedRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := servers.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown servers: %v", err)
		}
	})
	conn, err := tls.Dial("tcp", servers.TLSAddr, &tls.Config{InsecureSkipVerify: true, ServerName: "unknown.test", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("fallback TLS handshake: %v", err)
	}
	closeOnCleanup(t, conn)
	_, _ = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "421") {
		t.Fatalf("HTTP response line %q", line)
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.remote }

type queueListener struct {
	mu     sync.Mutex
	conns  []net.Conn
	closed chan struct{}
}

func (l *queueListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.conns) > 0 {
		c := l.conns[0]
		l.conns = l.conns[1:]
		l.mu.Unlock()
		return c, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, errors.New("listener closed")
}
func (l *queueListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}
func (l *queueListener) Addr() net.Addr { return fakeAddr("test") }

func TestPerIPConnectionLimit(t *testing.T) {
	server1, client1 := net.Pipe()
	server2, client2 := net.Pipe()
	closeOnCleanup(t, client1)
	closeOnCleanup(t, client2)
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.22"), Port: 9000}
	base := &queueListener{conns: []net.Conn{fakeConn{server1, remote}, fakeConn{server2, remote}}, closed: make(chan struct{})}
	close(base.closed)
	limited := newPerIPLimiter(1).Wrap(base)
	first, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}
	closeOnCleanup(t, first)
	if _, err = limited.Accept(); err == nil {
		t.Fatal("expected listener end after rejecting over-limit connection")
	}
	_ = client2.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = client2.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-limit connection was not closed")
	}
}

func TestReadHeaderTimeoutClosesSlowloris(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	closeOnCleanup(t, clientConn)
	base := &queueListener{conns: []net.Conn{fakeConn{serverConn, &net.TCPAddr{IP: net.ParseIP("192.0.2.3"), Port: 9001}}}, closed: make(chan struct{})}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }), ReadHeaderTimeout: 80 * time.Millisecond}
	done := make(chan struct{})
	go func() { _ = srv.Serve(base); close(done) }()
	_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: slow"))
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := bufio.NewReader(clientConn).ReadByte()
	if err == nil {
		t.Fatal("slowloris connection stayed open")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func TestProxyProtocolV1OnlyFromTrustedCIDR(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	closeOnCleanup(t, clientConn)
	base := &queueListener{conns: []net.Conn{fakeConn{serverConn, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000}}}, closed: make(chan struct{})}
	go func() { _, _ = io.WriteString(clientConn, "PROXY TCP4 198.51.100.7 203.0.113.1 42312 443\r\npayload") }()
	_, trusted, _ := net.ParseCIDR("192.0.2.0/24")
	conn, err := (proxyProtocolListener{Listener: base, trusted: []*net.IPNet{trusted}}).Accept()
	if err != nil {
		t.Fatal(err)
	}
	closeOnCleanup(t, conn)
	if got := conn.RemoteAddr().String(); got != "198.51.100.7:42312" {
		t.Fatalf("trusted source address=%q", got)
	}
	buf := make([]byte, 7)
	if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != "payload" {
		t.Fatalf("buffered payload=%q err=%v", buf, err)
	}
}

func TestProxyProtocolV1RejectsMalformedTruncatedAndOversizedHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, header string
	}{
		{name: "truncated", header: "PROXY TCP4 198.51.100.7"},
		{name: "bad signature", header: "NOTPROXY TCP4 198.51.100.7 203.0.113.1 42312 443\r\n"},
		{name: "bad address", header: "PROXY TCP4 not-an-ip 203.0.113.1 42312 443\r\n"},
		{name: "bad ports", header: "PROXY TCP4 198.51.100.7 203.0.113.1 99999 443\r\n"},
		{name: "bad unknown fields", header: "PROXY UNKNOWN extra\r\n"},
		{name: "oversized", header: "PROXY UNKNOWN " + strings.Repeat("x", 200) + "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			base := &queueListener{conns: []net.Conn{fakeConn{serverConn, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000}}}, closed: make(chan struct{})}
			close(base.closed)
			_, trusted, _ := net.ParseCIDR("192.0.2.0/24")
			writeDone := make(chan struct{})
			go func() {
				_, _ = io.WriteString(clientConn, tc.header)
				_ = clientConn.Close()
				close(writeDone)
			}()
			conn, err := (proxyProtocolListener{Listener: base, trusted: []*net.IPNet{trusted}}).Accept()
			if err == nil || conn != nil {
				t.Fatalf("malformed header accepted: conn=%v err=%v", conn, err)
			}
			<-writeDone
			_ = clientConn.Close()
		})
	}
}

func TestProxyProtocolV1MalformedConnectionDoesNotStopAccepting(t *testing.T) {
	badServer, badClient := net.Pipe()
	goodServer, goodClient := net.Pipe()
	t.Cleanup(func() {
		if err := badClient.Close(); err != nil {
			t.Errorf("close malformed proxy client: %v", err)
		}
	})
	t.Cleanup(func() {
		if err := goodClient.Close(); err != nil {
			t.Errorf("close valid proxy client: %v", err)
		}
	})
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1000}
	base := &queueListener{conns: []net.Conn{fakeConn{badServer, remote}, fakeConn{goodServer, remote}}, closed: make(chan struct{})}
	close(base.closed)
	_, trusted, _ := net.ParseCIDR("192.0.2.0/24")
	go func() {
		_, _ = io.WriteString(badClient, "not a proxy header\r\n")
		_ = badClient.Close()
	}()
	go func() { _, _ = io.WriteString(goodClient, "PROXY TCP4 198.51.100.7 203.0.113.1 42312 443\r\npayload") }()
	conn, err := (proxyProtocolListener{Listener: base, trusted: []*net.IPNet{trusted}}).Accept()
	if err != nil {
		t.Fatalf("listener stopped after malformed preamble: %v", err)
	}
	closeOnCleanup(t, conn)
	if got := conn.RemoteAddr().String(); got != "198.51.100.7:42312" {
		t.Fatalf("valid peer after malformed preamble=%q", got)
	}
	payload := make([]byte, 7)
	if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "payload" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
}

func TestProxyProtocolV1IsIgnoredFromUntrustedSource(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		if err := clientConn.Close(); err != nil {
			t.Errorf("close untrusted proxy protocol client: %v", err)
		}
	})
	base := &queueListener{conns: []net.Conn{fakeConn{serverConn, &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 1000}}}, closed: make(chan struct{})}
	_, trusted, _ := net.ParseCIDR("192.0.2.0/24")
	conn, err := (proxyProtocolListener{Listener: base, trusted: []*net.IPNet{trusted}}).Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close untrusted proxy protocol accepted connection: %v", err)
		}
	})
	if got := conn.RemoteAddr().String(); got != "198.51.100.10:1000" {
		t.Fatalf("untrusted PROXY header changed peer address to %q", got)
	}
	const header = "PROXY TCP4 203.0.113.7 203.0.113.1 42312 443\r\n"
	writeDone := make(chan error, 1)
	go func() { _, writeErr := io.WriteString(clientConn, header); writeDone <- writeErr }()
	buf := make([]byte, len(header))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != header {
		t.Fatalf("untrusted header was consumed: bytes=%q err=%v", buf, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write untrusted header: %v", err)
	}
}

func closeOnCleanup(t *testing.T, closer interface{ Close() error }) {
	t.Helper()
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Errorf("close test connection: %v", err)
		}
	})
}
