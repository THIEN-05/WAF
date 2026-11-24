package listener

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
)

func helloSample(ciphers, extensions []byte) []byte {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(ciphers)))
	body = append(body, tmp...)
	body = append(body, ciphers...)
	body = append(body, 1, 0)
	if extensions != nil {
		binary.BigEndian.PutUint16(tmp, uint16(len(extensions)))
		body = append(body, tmp...)
		body = append(body, extensions...)
	}
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}
func ext(id uint16, d []byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, id)
	binary.BigEndian.PutUint16(b[2:], uint16(len(d)))
	return append(b, d...)
}
func TestClientHelloFingerprintsRepresentativeProfiles(t *testing.T) {
	// Handcrafted wire fixtures model Go TLS, curl/OpenSSL-like and browser-like hellos; golden values lock JA3/JA4 formats.
	samples := map[string][]byte{
		"go":           helloSample([]byte{0x13, 1, 0x13, 2, 0x13, 3, 0xc0, 0x2f}, append(ext(10, []byte{0, 4, 0, 0x1d, 0, 0x17}), ext(43, []byte{2, 3, 4})...)),
		"curl-like":    helloSample([]byte{0xc0, 0x2f, 0xc0, 0x30, 0, 0x9c}, append(ext(11, []byte{1, 0}), ext(13, []byte{0, 2, 4, 3})...)),
		"browser-fake": helloSample([]byte{0x13, 1, 0x13, 2, 0xc0, 0x2f, 0x0a, 0x0a}, append(append(ext(0, []byte{0, 0}), ext(16, []byte{0, 3, 2, 'h', '2'})...), ext(43, []byte{4, 3, 4, 3, 3})...)),
	}
	want := map[string][2]string{
		"go":           {"24708288047a39c8042839c634426ab4", "t13i040200_77f0cd3447db_b0ac53b37fa7"},
		"curl-like":    {"0469aea30815d7297e529b5e76dd34b6", "t12i030200_13bac7b83268_768417403adc"},
		"browser-fake": {"f5d02a1f961455968539fc744857bf0c", "t13d0303h2_40b44b994229_b9a491fefe05"},
	}
	seen := map[string]bool{}
	for name, raw := range samples {
		t.Run(name, func(t *testing.T) {
			ja3, ja4, err := fingerprintClientHello(raw)
			if err != nil || len(ja3) != 32 || !strings.HasPrefix(ja4, "t") {
				t.Fatalf("fingerprints ja3=%q ja4=%q err=%v", ja3, ja4, err)
			}
			if ja3 != want[name][0] || ja4 != want[name][1] {
				t.Fatalf("fingerprint=(%s,%s), want (%s,%s)", ja3, ja4, want[name][0], want[name][1])
			}
			seen[ja3] = true
		})
	}
	if len(seen) < 2 {
		t.Fatalf("representative profiles collapsed to %d JA3 values", len(seen))
	}
}

func TestFingerprintIndependentFoxIOChromeCapture(t *testing.T) {
	// Vector source: raw client record extracted from FoxIO's pcap fixture
	// https://github.com/FoxIO-LLC/ja4/blob/4ab8e3f18f4b27e0b896c4ec2c251e20506eb87e/pcap/browsers-x509.pcapng
	// (verified byte-for-byte by SHA-256 e05937fe5f3659f1b94b46305e419b878ba309ebcba8308750acaac704112906).
	// Expected JA3/JA4 are the independently reported output for edge.microsoft.com in
	// https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING/blob/797a8b074e135f659da1ee3193b5a4cc111dfc26/README.md.
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "fingerprints", "foxio_chrome_clienthello.hex"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	ja3, ja4, err := fingerprintClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ja3 != "34fcb8e0ef812f18e760b52314a54fd0" || ja4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("FoxIO Chrome capture fingerprints=(%s,%s), want (34fcb8e0ef812f18e760b52314a54fd0,t13d1516h2_8daaf6152771_e5627efa2ab1)", ja3, ja4)
	}
}

func TestFingerprintIndependentFoxIOTLS12ALPNCapture(t *testing.T) {
	// Raw record from FoxIO's official tls-alpn-h2.pcap fixture, pinned by the
	// matching SHA-256 in its provenance: https://github.com/FoxIO-LLC/ja4/blob/4ab8e3f18f4b27e0b896c4ec2c251e20506eb87e/pcap/tls-alpn-h2.pcap.
	// JA3 is the output of Salesforce's original script at https://github.com/salesforce/ja3/tree/502cc6395811c54743b0561419d61900a6df3ff7 (dpkt v1.9.1, 6cd0909d613a66033ecdefaca6cc07cfa7d46d6b).
	// The JA4 value is the published vector recorded with the pcap by https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING/blob/797a8b074e135f659da1ee3193b5a4cc111dfc26/testdata/pcap/PROVENANCE.md.
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "fingerprints", "foxio_tls12_alpn_h2_clienthello.hex"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	ja3, ja4, err := fingerprintClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ja3 != "3faa4ad39f690c4ef1c3160caa375465" || ja4 != "t12d4605h2_85626a9a5f7f_aaf95bb78ec9" {
		t.Fatalf("FoxIO TLS 1.2 capture fingerprints=(%s,%s), want (3faa4ad39f690c4ef1c3160caa375465,t12d4605h2_85626a9a5f7f_aaf95bb78ec9)", ja3, ja4)
	}
}
func TestClientHelloGarbageAndTruncationReturnBlank(t *testing.T) {
	for name, b := range map[string][]byte{"junk": []byte("garbage"), "empty": nil, "truncated": helloSample([]byte{0, 47}, nil)[:12], "oversized": append([]byte{22, 3, 1, 0xff, 0xff, 1, 0, 0, 0}, make([]byte, 10)...)} {
		t.Run(name, func(t *testing.T) {
			ja3, ja4, err := fingerprintClientHello(b)
			if err == nil || ja3 != "" || ja4 != "" {
				t.Fatalf("got %q %q %v", ja3, ja4, err)
			}
		})
	}
}

func tlsRecord(payload []byte) []byte {
	out := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(out[3:5], uint16(len(payload)))
	return append(out, payload...)
}

func TestClientHelloAcrossTLSRecordsAndOver16KiBCap(t *testing.T) {
	complete := helloSample([]byte{0x13, 1, 0x13, 2}, append(ext(10, []byte{0, 2, 0, 0x1d}), ext(43, []byte{2, 3, 4})...))
	handshake := complete[5:]
	split := len(handshake) / 2
	fragmented := append(tlsRecord(handshake[:split]), tlsRecord(handshake[split:])...)
	wantJA3, wantJA4, err := fingerprintClientHello(complete)
	if err != nil {
		t.Fatal(err)
	}
	gotJA3, gotJA4, err := fingerprintClientHello(fragmented)
	if err != nil || gotJA3 != wantJA3 || gotJA4 != wantJA4 {
		t.Fatalf("fragmented hello=(%s,%s,%v), want (%s,%s)", gotJA3, gotJA4, err, wantJA3, wantJA4)
	}
	tooManyRecords := []byte{}
	for start, i := 0, 0; start < len(handshake); i++ {
		end := (i + 1) * (len(handshake) / 17)
		if i == 16 || end > len(handshake) {
			end = len(handshake)
		}
		tooManyRecords = append(tooManyRecords, tlsRecord(handshake[start:end])...)
		start = end
	}
	if ja3, ja4, err := fingerprintClientHello(tooManyRecords); err == nil || ja3 != "" || ja4 != "" {
		t.Fatalf("hello fragmented across too many records was accepted: (%s,%s,%v)", ja3, ja4, err)
	}

	largeExtension := ext(0x1234, make([]byte, 16<<10))
	oversized := helloSample([]byte{0x13, 1}, largeExtension)
	ja3, ja4, err := fingerprintClientHello(oversized)
	if err == nil || ja3 != "" || ja4 != "" {
		t.Fatalf("oversized hello not rejected: ja3=%q ja4=%q err=%v", ja3, ja4, err)
	}
	if !rawClientHelloComplete(oversized) {
		t.Fatal("complete over-limit hello was mistaken for an incomplete peek")
	}
}

func TestClientHelloRepeatedExtensionsAndGREASEAreBounded(t *testing.T) {
	baseExts := append(ext(10, []byte{0, 2, 0, 0x1d}), ext(43, []byte{2, 3, 4})...)
	base := helloSample([]byte{0x13, 1, 0x13, 2}, baseExts)
	greaseExts := append(ext(0x2a2a, []byte{1, 2, 3}), baseExts...)
	withGREASE := helloSample([]byte{0x0a, 0x0a, 0x13, 1, 0x13, 2}, greaseExts)
	a, b, err := fingerprintClientHello(base)
	if err != nil {
		t.Fatal(err)
	}
	c, d, err := fingerprintClientHello(withGREASE)
	if err != nil || a != c || b != d {
		t.Fatalf("GREASE changed fingerprint: (%s,%s) versus (%s,%s), err=%v", a, b, c, d, err)
	}
	duplicate := helloSample([]byte{0x13, 1}, append(baseExts, ext(10, []byte{0, 2, 0, 0x17})...))
	if _, _, err := fingerprintClientHello(duplicate); err != nil {
		t.Fatalf("repeated extension panicked/rejected unexpectedly: %v", err)
	}
}

func FuzzFingerprintClientHello(f *testing.F) {
	f.Add(helloSample([]byte{0x13, 1, 0xc0, 0x2f}, ext(43, []byte{2, 3, 4})))
	f.Add([]byte("junk"))
	f.Add(helloSample([]byte{0, 47}, nil)[:12])
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxCapturedHelloBytes {
			t.Skip()
		}
		_, _, _ = fingerprintClientHello(raw)
	})
}

func BenchmarkFingerprintClientHello(b *testing.B) {
	raw := helloSample([]byte{0x13, 1, 0x13, 2, 0xc0, 0x2f}, append(ext(10, []byte{0, 4, 0, 0x1d, 0, 0x17}), ext(43, []byte{2, 3, 4})...))
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		if _, _, err := fingerprintClientHello(raw); err != nil {
			b.Fatal(err)
		}
	}
}

type testHelloConn struct{ *bytes.Reader }

func (testHelloConn) Close() error                     { return nil }
func (testHelloConn) Write(p []byte) (int, error)      { return len(p), nil }
func (testHelloConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (testHelloConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (testHelloConn) SetDeadline(time.Time) error      { return nil }
func (testHelloConn) SetReadDeadline(time.Time) error  { return nil }
func (testHelloConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkFingerprintPeekAndCompute(b *testing.B) {
	raw := helloSample([]byte{0x13, 1, 0x13, 2, 0xc0, 0x2f}, append(ext(10, []byte{0, 4, 0, 0x1d, 0, 0x17}), ext(43, []byte{2, 3, 4})...))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		capture := &helloCaptureConn{Conn: testHelloConn{Reader: bytes.NewReader(raw)}}
		buf := make([]byte, 2048)
		for {
			if _, err := capture.Read(buf); err != nil {
				break
			}
		}
		if ja3, ja4 := capture.Fingerprint(); ja3 == "" || ja4 == "" {
			b.Fatal("fingerprint missing")
		}
	}
}
func TestLoopbackTLSListenerAttachesFingerprintToRequestContext(t *testing.T) {
	got := make(chan [2]string, 1)
	servers, err := Start(Config{HTTPAddr: "127.0.0.1:0", TLSAddr: "127.0.0.1:0"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := reqctx.New(r, nil, "id", nil)
		got <- [2]string{c.JA3, c.JA4}
		reqctx.Release(c)
		w.WriteHeader(204)
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	t.Cleanup(func() { _ = servers.Shutdown(ctx) })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "site.test", MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 3 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, "https://"+servers.TLSAddr+"/", nil)
	req.Host = "site.test"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	select {
	case fp := <-got:
		if fp[0] == "" || fp[1] == "" {
			t.Fatalf("empty fingerprints: %v", fp)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not receive TLS request")
	}
}

func TestLoopbackSlowClientHelloTimeoutReleasesConnections(t *testing.T) {
	servers, err := Start(Config{HTTPAddr: "127.0.0.1:0", TLSAddr: "127.0.0.1:0", ClientHelloTimeout: 120 * time.Millisecond, MaxPerIP: 6}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	goroutinesBefore := runtime.NumGoroutine()
	var heapBefore runtime.MemStats
	runtime.ReadMemStats(&heapBefore)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	t.Cleanup(func() { _ = servers.Shutdown(ctx) })
	const clients = 16
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		conn, dialErr := net.DialTimeout("tcp", servers.TLSAddr, time.Second)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					t.Errorf("close slow TLS client: %v", closeErr)
				}
			}()
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte{22, 3, 1, 0x40, 0}) // deliberately incomplete record header/body
			for j := 0; j < 20; j++ {
				_, writeErr := conn.Write([]byte{1})
				if writeErr != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}(conn)
	}
	wg.Wait()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		servers.limit.mu.Lock()
		active := 0
		for _, count := range servers.limit.counts {
			active += count
		}
		servers.limit.mu.Unlock()
		if active == 0 {
			runtime.GC()
			var heapAfter runtime.MemStats
			runtime.ReadMemStats(&heapAfter)
			if goroutines := runtime.NumGoroutine(); goroutines > goroutinesBefore+4 {
				t.Fatalf("slow ClientHello left goroutines behind: before=%d after=%d", goroutinesBefore, goroutines)
			}
			if heapAfter.HeapAlloc > heapBefore.HeapAlloc+(8<<20) {
				t.Fatalf("slow ClientHello retained too much heap: before=%d after=%d", heapBefore.HeapAlloc, heapAfter.HeapAlloc)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	servers.limit.mu.Lock()
	defer servers.limit.mu.Unlock()
	t.Fatalf("slow ClientHello connections were retained: active=%v", servers.limit.counts)
}
