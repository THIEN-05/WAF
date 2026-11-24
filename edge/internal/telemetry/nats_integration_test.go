//go:build integration

package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/nats-io/nats.go"
)

func integrationNATSAddr() string {
	if value := strings.TrimSpace(os.Getenv("NATS_ADDR")); value != "" {
		return value
	}
	return "127.0.0.1:4222"
}

func connectIntegrationNATS(t *testing.T, url string) *nats.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		conn, err := nats.Connect(url, nats.Timeout(500*time.Millisecond))
		if err == nil {
			return conn
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("required NATS is unavailable at %s: %v", url, last)
	return nil
}

type natsTCPProxy struct {
	upstream, addr string
	mu             sync.Mutex
	listener       net.Listener
	active         map[net.Conn]struct{}
	acceptDone     chan struct{}
	wg             sync.WaitGroup
}

type gatedNATSSink struct {
	inner   *NATSBatchSink
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedNATSSink) Publish(ctx context.Context, payload []byte) error {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return g.inner.Publish(ctx, payload)
}

func newNATSTCPProxy(upstream string) *natsTCPProxy {
	return &natsTCPProxy{upstream: upstream, active: map[net.Conn]struct{}{}}
}
func (p *natsTCPProxy) Start() error {
	l, err := net.Listen("tcp", p.addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.listener = l
	p.addr = l.Addr().String()
	p.acceptDone = make(chan struct{})
	done := p.acceptDone
	p.mu.Unlock()
	go func() {
		defer close(done)
		for {
			client, err := l.Accept()
			if err != nil {
				return
			}
			upstream, err := net.DialTimeout("tcp", p.upstream, time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			p.mu.Lock()
			p.active[client] = struct{}{}
			p.active[upstream] = struct{}{}
			p.mu.Unlock()
			p.wg.Add(1)
			go p.bridge(client, upstream)
		}
	}()
	return nil
}
func (p *natsTCPProxy) bridge(a, b net.Conn) {
	defer p.wg.Done()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
	p.mu.Lock()
	delete(p.active, a)
	delete(p.active, b)
	p.mu.Unlock()
}
func (p *natsTCPProxy) Stop() {
	p.mu.Lock()
	l := p.listener
	done := p.acceptDone
	p.listener = nil
	for c := range p.active {
		_ = c.Close()
	}
	p.mu.Unlock()
	if l != nil {
		_ = l.Close()
		<-done
	}
	p.wg.Wait()
}
func (p *natsTCPProxy) Addr() string { p.mu.Lock(); defer p.mu.Unlock(); return p.addr }

func decodeBatch(t *testing.T, compressed []byte) CompressedBatch {
	t.Helper()
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	raw, err := decoder.DecodeAll(compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	var batch CompressedBatch
	if err = json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestIntegrationNATSBatchOutageAndRecovery(t *testing.T) {
	serverURL := "nats://" + integrationNATSAddr()
	subscriber := connectIntegrationNATS(t, serverURL)
	defer subscriber.Close()
	sub, err := subscriber.SubscribeSync("edge.logs.integration.*")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	proxy := newNATSTCPProxy(integrationNATSAddr())
	if err = proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()
	sink, err := NewNATSBatchSink("nats://"+proxy.Addr(), "edge.logs.integration.batch")
	if err != nil {
		t.Fatal(err)
	}
	shipper, err := NewShipper(sink, ShipperConfig{QueueSize: 16, BatchSize: 2, FlushInterval: 50 * time.Millisecond, IPMaskV4Bits: 24, IPMaskV6Bits: 56})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { shipper.Close(); sink.Close() }()
	if !shipper.Record(validLogEvent("batch-1", time.Now()), true, "free") || !shipper.Record(validLogEvent("batch-2", time.Now()), true, "free") {
		t.Fatal("failed to enqueue security events")
	}
	msg, err := sub.NextMsg(3 * time.Second)
	if err != nil {
		t.Fatalf("NATS batch delivery: %v", err)
	}
	batch := decodeBatch(t, msg.Data)
	if len(batch.Events) != 2 {
		t.Fatalf("NATS batch contained %d events, want 2", len(batch.Events))
	}
	for _, event := range batch.Events {
		if err := event.Validate(); err != nil {
			t.Fatalf("event does not match wafcore schema: %v", err)
		}
	}
	gate := &gatedNATSSink{inner: sink, entered: make(chan struct{}), release: make(chan struct{})}
	full, err := NewShipper(gate, ShipperConfig{QueueSize: 1, BatchSize: 1, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !full.Record(validLogEvent("full-1", time.Now()), true, "pro") {
		t.Fatal("first queued event rejected")
	}
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("NATS batch worker did not reach gated publish")
	}
	if !full.Record(validLogEvent("full-2", time.Now()), true, "pro") {
		t.Fatal("second event should fill queue")
	}
	start := time.Now()
	if full.Record(validLogEvent("full-3", time.Now()), true, "pro") {
		t.Fatal("full telemetry queue accepted third event")
	}
	if time.Since(start) > 50*time.Millisecond || full.Dropped() != 1 {
		t.Fatalf("queue-full behavior blocked=%s dropped=%d", time.Since(start), full.Dropped())
	}
	close(gate.release)
	for i := 0; i < 2; i++ {
		if _, err = sub.NextMsg(3 * time.Second); err != nil {
			t.Fatalf("NATS did not receive queued record %d after releasing worker: %v", i, err)
		}
	}
	full.Close()

	proxy.Stop()
	outageStart := time.Now()
	for i := 0; i < 4; i++ {
		_ = shipper.Record(validLogEvent("during-outage", time.Now()), true, "free")
	}
	if time.Since(outageStart) > 50*time.Millisecond {
		t.Fatal("request-side enqueue blocked while NATS path was down")
	}
	if err = proxy.Start(); err != nil {
		t.Fatalf("restart test proxy: %v", err)
	}
	deadline := time.Now().Add(8 * time.Second)
	recovered := false
	for time.Now().Before(deadline) && !recovered {
		_ = shipper.Record(validLogEvent("after-recovery", time.Now()), true, "free")
		msg, err = sub.NextMsg(300 * time.Millisecond)
		if err == nil {
			for _, event := range decodeBatch(t, msg.Data).Events {
				if event.RequestID == "after-recovery" {
					recovered = true
				}
			}
		}
	}
	if !recovered {
		t.Fatal("NATS publishing did not recover after transport returned")
	}
}
