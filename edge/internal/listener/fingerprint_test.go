package listener

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net/http"
	"strings"
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
