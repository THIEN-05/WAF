package reqctx

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/wafplatform/pkg/wafcore"
)

func TestBodyInspectionReadsOnceAndReplaysOriginalBytes(t *testing.T) {
	original := []byte("form=hello&value=world")
	request := httptest.NewRequest(http.MethodPost, "http://site.test/", bytes.NewReader(original))
	request.ContentLength = int64(len(original))
	ctx := New(request, nil, "request-id", nil)
	defer Release(ctx)

	if got := ctx.BodyText(); got != string(original) {
		t.Fatalf("inspection body=%q", got)
	}
	if got := ctx.BodyText(); got != string(original) {
		t.Fatalf("second inspection body=%q", got)
	}
	replayed, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, original) {
		t.Fatalf("origin replay=%q want %q", replayed, original)
	}
	if request.ContentLength != int64(len(original)) || len(request.TransferEncoding) != 0 {
		t.Fatalf("body framing changed: content_length=%d transfer_encoding=%v", request.ContentLength, request.TransferEncoding)
	}
}

func TestBodyPrefixCapStreamsRemainderAndPreservesFraming(t *testing.T) {
	original := []byte(strings.Repeat("x", 32))
	request := httptest.NewRequest(http.MethodPost, "http://site.test/", bytes.NewReader(original))
	request.ContentLength = int64(len(original))
	ctx := New(request, nil, "request-id", nil)
	ctx.Entitlements.MaxBodyBytes = 8
	defer Release(ctx)

	if got := ctx.BodyPrefix(0); got != string(original[:8]) {
		t.Fatalf("inspection prefix length=%d value=%q", len(got), got)
	}
	if !ctx.BodyTruncated() {
		t.Fatal("body beyond package cap was not marked truncated")
	}
	replayed, err := io.ReadAll(request.Body)
	if err != nil || !bytes.Equal(replayed, original) {
		t.Fatalf("origin replay=%q err=%v want %q", replayed, err, original)
	}
	if request.ContentLength != int64(len(original)) {
		t.Fatalf("Content-Length changed to %d", request.ContentLength)
	}
}

func TestGzipBodyIsInspectedBoundedlyAndRawBytesReplayToOrigin(t *testing.T) {
	plain := []byte("query=normal content")
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), compressed.Bytes()...)
	request := httptest.NewRequest(http.MethodPost, "http://site.test/", bytes.NewReader(raw))
	request.Header.Set("Content-Encoding", "gzip")
	request.ContentLength = int64(len(raw))
	ctx := New(request, nil, "request-id", nil)
	defer Release(ctx)
	if got := ctx.BodyText(); got != string(plain) {
		t.Fatalf("decoded body=%q want %q", got, plain)
	}
	replayed, err := io.ReadAll(request.Body)
	if err != nil || !bytes.Equal(replayed, raw) {
		t.Fatalf("origin compressed replay=%x err=%v want %x", replayed, err, raw)
	}
	if request.Header.Get("Content-Encoding") != "gzip" || request.ContentLength != int64(len(raw)) {
		t.Fatalf("origin encoding/framing changed: headers=%v length=%d", request.Header, request.ContentLength)
	}
}

func TestGzipExpansionAndUnsupportedEncodingAreMarkedTruncated(t *testing.T) {
	plain := bytes.Repeat([]byte("a"), 64*1024)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://site.test/", bytes.NewReader(compressed.Bytes()))
	request.Header.Set("Content-Encoding", "gzip")
	ctx := New(request, nil, "request-id", nil)
	ctx.Site = &wafcore.Site{Entitlements: wafcore.Entitlements{MaxBodyBytes: 4096}}
	defer Release(ctx)
	decoded := ctx.BodyText()
	if len(decoded) > 4096 || !ctx.BodyTruncated() {
		t.Fatalf("gzip expansion was not bounded: decoded=%d truncated=%v", len(decoded), ctx.BodyTruncated())
	}

	request = httptest.NewRequest(http.MethodPost, "http://site.test/", strings.NewReader("opaque compressed bytes"))
	request.Header.Set("Content-Encoding", "br")
	ctx = New(request, nil, "request-id", nil)
	defer Release(ctx)
	_ = ctx.BodyText()
	if !ctx.BodyTruncated() {
		t.Fatal("unsupported Content-Encoding was treated as fully inspected")
	}
}
