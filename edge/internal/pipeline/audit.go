package pipeline

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	AuditWAFBudgetExceeded  = "waf_budget_exceeded"
	AuditWAFBodyTruncated   = "waf_body_truncated"
	AuditWAFBodyReadTimeout = "waf_body_read_timeout"
)

type AuditEvent struct {
	Kind string
	At   time.Time
}

// AuditWriter is the extension point for durable telemetry sinks.
type AuditWriter interface {
	WriteAudit(AuditEvent)
}

// AsyncAuditSink never blocks request processing. A full queue drops the event
// and exposes the drop count to metrics.
type AsyncAuditSink struct {
	queue     chan AuditEvent
	stop      chan struct{}
	done      chan struct{}
	writer    AuditWriter
	startOnce sync.Once
	closeOnce sync.Once
	closed    atomic.Bool
	started   atomic.Bool
	dropped   atomic.Uint64
}

func NewAsyncAuditSink(writer AuditWriter, capacity int) *AsyncAuditSink {
	if capacity < 1 {
		capacity = 128
	}
	return &AsyncAuditSink{queue: make(chan AuditEvent, capacity), stop: make(chan struct{}), done: make(chan struct{}), writer: writer}
}

func (s *AsyncAuditSink) Emit(event AuditEvent) bool {
	if s == nil || s.writer == nil || s.closed.Load() {
		return false
	}
	s.startOnce.Do(func() { s.started.Store(true); go s.run() })
	select {
	case s.queue <- event:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

func (s *AsyncAuditSink) run() {
	defer close(s.done)
	for {
		select {
		case event := <-s.queue:
			s.writer.WriteAudit(event)
		case <-s.stop:
			for {
				select {
				case event := <-s.queue:
					s.writer.WriteAudit(event)
				default:
					return
				}
			}
		}
	}
}

func (s *AsyncAuditSink) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.startOnce.Do(func() {})
		close(s.stop)
		if s.started.Load() {
			<-s.done
		}
	})
}

func (s *AsyncAuditSink) Dropped() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

// MemoryAuditWriter is the in-memory sink used until durable telemetry (P6a).
type MemoryAuditWriter struct {
	mu     sync.Mutex
	counts map[string]uint64
}

func NewMemoryAuditWriter() *MemoryAuditWriter {
	return &MemoryAuditWriter{counts: make(map[string]uint64)}
}
func (w *MemoryAuditWriter) WriteAudit(event AuditEvent) {
	w.mu.Lock()
	w.counts[event.Kind]++
	w.mu.Unlock()
}
func (w *MemoryAuditWriter) Counts() map[string]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	copy := make(map[string]uint64, len(w.counts))
	for k, v := range w.counts {
		copy[k] = v
	}
	return copy
}
