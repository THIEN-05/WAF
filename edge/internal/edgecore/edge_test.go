package edgecore

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/pipeline"
	"github.com/example/wafplatform/edge/internal/proxy"
	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
	"gopkg.in/yaml.v3"
)

type panicPhase struct{}

func (panicPhase) Name() string                              { return "panic-test" }
func (panicPhase) Handle(*reqctx.RequestCtx) reqctx.Decision { panic("phase boom") }
func siteSnapshot(status, failMode, origin string, version uint64) *wafcore.Snapshot {
	return &wafcore.Snapshot{SchemaVersion: 1, Version: version, GeneratedAt: time.Now(), Global: wafcore.GlobalConfig{ManagedRuleset: "test"}, Sites: []wafcore.Site{{ID: "site", TenantID: "tenant", Status: status, Plan: "pro", Domains: []string{"site.test"}, Origins: []wafcore.Origin{{URL: origin, Weight: 1}}, FailMode: failMode}}}
}
func localOrigin(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	_ = host
	return srv, port
}
func installLocalPool(e *Edge, port string) {
	e.poolFactory = func(origins []wafcore.Origin, via string) *proxy.OriginPool {
		p := proxy.NewOriginPool(origins, via)
		p.SetResolver(func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.77")}, nil })
		p.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		})
		return p
	}
}

func TestPanicRespectsFailMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int
		body string
	}{{"open", 200, "origin ok"}, {"closed", 503, "internal edge error"}} {
		t.Run(tc.mode, func(t *testing.T) {
			origin, port := localOrigin(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "origin ok") })
			defer origin.Close()
			snap := siteSnapshot("active", tc.mode, "http://203.0.113.77:80", 1)
			e := New(snap, "edge-test")
			installLocalPool(e, port)
			e.pipeline = pipeline.New(e.metrics, panicPhase{})
			r := httptest.NewRequest(http.MethodGet, "http://site.test/", nil)
			r.RemoteAddr = "192.0.2.9:1234"
			rr := httptest.NewRecorder()
			e.ServeHTTP(rr, r)
			if rr.Code != tc.want || !strings.Contains(rr.Body.String(), tc.body) {
				t.Fatalf("response=(%d,%q), want status %d containing %q", rr.Code, rr.Body.String(), tc.want, tc.body)
			}
		})
	}
}

func TestReloadDoesNotInterruptInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	origin, port := localOrigin(t, func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = fmt.Fprint(w, "completed")
	})
	defer origin.Close()
	e := New(siteSnapshot("active", "closed", "http://203.0.113.77:80", 1), "edge-test")
	installLocalPool(e, port)
	srv := httptest.NewServer(e)
	defer srv.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	result := make(chan error, 1)
	go func() {
		defer wg.Done()
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			result <- err
			return
		}
		req.Host = "site.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			result <- err
			return
		}
		defer resp.Body.Close()
		buf := new(strings.Builder)
		_, err = io.Copy(buf, resp.Body)
		if err == nil && !strings.Contains(buf.String(), "completed") {
			err = fmt.Errorf("response body %q", buf.String())
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("origin request did not start")
	}
	e.Apply(siteSnapshot("active", "closed", "http://203.0.113.77:80", 2))
	close(release)
	wg.Wait()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if e.runtime.Load().snapshot.Version != 2 {
		t.Fatal("new snapshot not applied")
	}
}

func TestSampleSnapshotServesThroughFakeOrigin(t *testing.T) {
	data, err := os.ReadFile("../../../test/fixtures/snapshot.sample.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot wafcore.Snapshot
	if err = yaml.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	origin, port := localOrigin(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "origin=%s proto=%s", r.Host, r.Proto) })
	defer origin.Close()
	snapshot.Sites[0].Origins = []wafcore.Origin{{URL: "http://203.0.113.77:80", Weight: 1, HostHeader: "example.com", TLSVerify: true}}
	e := New(&snapshot, "edge-test")
	installLocalPool(e, port)
	srv := httptest.NewServer(e)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/sample", nil)
	req.Host = "www.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "proto=HTTP/1.1") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestHostAndSiteStatusResponses(t *testing.T) {
	snap := siteSnapshot("suspended", "closed", "http://203.0.113.1", 1)
	snap.Sites = append(snap.Sites, wafcore.Site{ID: "pending", TenantID: "t", Status: "pending", Plan: "p", Domains: []string{"pending.test"}, FailMode: "closed"})
	e := New(snap, "edge")
	for _, tc := range []struct {
		host string
		code int
	}{{"unknown.test", 421}, {"site.test", 402}, {"pending.test", 403}} {
		r := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/", nil)
		r.RemoteAddr = "192.0.2.1:10"
		rr := httptest.NewRecorder()
		e.ServeHTTP(rr, r)
		if rr.Code != tc.code {
			t.Errorf("host %s got %d want %d", tc.host, rr.Code, tc.code)
		}
	}
}

type hijackWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}
func TestPanicAfterHeadersClosesConnectionAndCountsMetric(t *testing.T) {
	e := New(siteSnapshot("active", "closed", "http://203.0.113.1", 1), "edge")
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	tw := &trackingWriter{ResponseWriter: &hijackWriter{ResponseRecorder: rec, conn: serverConn}, wrote: true}
	ctx := reqctx.New(httptest.NewRequest(http.MethodGet, "http://site.test/", nil), e.runtime.Load().snapshot, "request-1", nil)
	ctx.Site = &e.runtime.Load().snapshot.Sites[0]
	e.recoverPanic(tw, ctx, "boom")
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection was not closed after committed headers")
	}
	metrics := httptest.NewRecorder()
	e.Metrics().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "edge_blocked_total{action=\"panic\"} 1") {
		t.Fatalf("panic metric missing: %s", metrics.Body.String())
	}
}
