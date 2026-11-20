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
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPChallengeAndRedirect(t *testing.T) {
	h := NewHTTPHandler(func(token string) (string, bool) { return "proof-" + token, token == "good" }, "443")
	for _, tc := range []struct {
		path   string
		status int
		body   string
	}{{"/.well-known/acme-challenge/good", 200, "proof-good"}, {"/.well-known/acme-challenge/missing", 404, ""}, {"/path?q=1", 308, ""}} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://example.test"+tc.path, nil))
		if rr.Code != tc.status {
			t.Errorf("%s status=%d", tc.path, rr.Code)
		}
		if tc.body != "" && !strings.Contains(rr.Body.String(), tc.body) {
			t.Errorf("body=%q", rr.Body.String())
		}
		if tc.status == 308 && rr.Header().Get("Location") != "https://example.test/path?q=1" {
			t.Errorf("location=%q", rr.Header().Get("Location"))
		}
	}
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

func TestUnknownSNIUsesFallbackThenHTTPRejectsMismatch(t *testing.T) {
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

func closeOnCleanup(t *testing.T, closer interface{ Close() error }) {
	t.Helper()
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Errorf("close test connection: %v", err)
		}
	})
}
