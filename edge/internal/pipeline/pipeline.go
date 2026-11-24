package pipeline

import (
	"sync"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
)

type Phase interface {
	Name() string
	Handle(*reqctx.RequestCtx) reqctx.Decision
}

type Metrics interface {
	ObservePhase(string, time.Duration)
	Blocked(string)
	LogDropped(uint64)
}
type Pipeline struct {
	phases   []Phase
	observer Metrics
}

func New(observer Metrics, phases ...Phase) *Pipeline {
	return &Pipeline{phases: append([]Phase(nil), phases...), observer: observer}
}
func (p *Pipeline) Run(c *reqctx.RequestCtx) reqctx.Decision {
	score := 0
	tags := make([]string, 0, 8)
	seenTags := make(map[string]struct{})
	var logOnly reqctx.Decision
	hasLogOnly := false
	for _, ph := range p.phases {
		if c.PhaseSkipped(ph.Name()) {
			continue
		}
		start := time.Now()
		d := ph.Handle(c)
		if p.observer != nil {
			p.observer.ObservePhase(ph.Name(), time.Since(start))
		}
		score += d.Score
		for _, tag := range d.Tags {
			if _, exists := seenTags[tag]; !exists && len(tags) < 32 {
				seenTags[tag] = struct{}{}
				tags = append(tags, tag)
				if sink, ok := p.observer.(interface{ EnqueueAudit(AuditEvent) bool }); ok {
					if tag == AuditWAFBudgetExceeded || tag == AuditWAFBodyTruncated || tag == AuditWAFBodyReadTimeout || tag == AuditWAFWorkExhausted || tag == AuditWAFDegradedParanoia || tag == AuditWAFDegradedScope || tag == AuditWAFDegradedFailMode {
						sink.EnqueueAudit(AuditEvent{Kind: tag, At: time.Now()})
					}
				}
			}
		}
		d.Score = score
		d.Tags = append([]string(nil), tags...)
		c.SetDecision(d)
		if d.Terminal() {
			return d
		}
		if d.Action == reqctx.ActionLogOnly {
			logOnly = d
			hasLogOnly = true
		}
	}
	d := reqctx.Decision{Action: reqctx.ActionAllow, Phase: "pipeline", Reason: "no terminal decision", Score: score, Tags: tags}
	if hasLogOnly {
		logOnly.Score = score
		logOnly.Tags = append([]string(nil), tags...)
		d = logOnly
	}
	c.SetDecision(d)
	return d
}

type Histogram struct {
	mu          sync.Mutex
	phaseCounts map[string]uint64
	blocked     map[string]uint64
	logDropped  uint64
	audit       *AsyncAuditSink
	auditMemory *MemoryAuditWriter
}

func NewHistogram() *Histogram {
	writer := NewMemoryAuditWriter()
	return NewHistogramWithAudit(writer, 256)
}

func NewHistogramWithAudit(writer AuditWriter, capacity int) *Histogram {
	h := &Histogram{phaseCounts: map[string]uint64{}, blocked: map[string]uint64{}}
	if memory, ok := writer.(*MemoryAuditWriter); ok {
		h.auditMemory = memory
	}
	h.audit = NewAsyncAuditSink(writer, capacity)
	return h
}

func (h *Histogram) EnqueueAudit(event AuditEvent) bool { return h.audit.Emit(event) }
func (h *Histogram) AuditCounts() map[string]uint64 {
	if h.auditMemory == nil {
		return nil
	}
	return h.auditMemory.Counts()
}
func (h *Histogram) Close() { h.audit.Close() }

func (h *Histogram) Blocked(action string) { h.mu.Lock(); h.blocked[action]++; h.mu.Unlock() }
func (h *Histogram) LogDropped(n uint64)   { h.mu.Lock(); h.logDropped += n; h.mu.Unlock() }
func (h *Histogram) ObservePhase(name string, _ time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.phaseCounts[name]++
}

// Snapshot returns counters for unit tests and in-memory diagnostics. Production
// Prometheus exposition is provided by edge/internal/telemetry.
func (h *Histogram) Snapshot() (phases, blocked map[string]uint64, logDropped uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	copyMap := func(src map[string]uint64) map[string]uint64 {
		out := make(map[string]uint64, len(src))
		for key, value := range src {
			out[key] = value
		}
		return out
	}
	return copyMap(h.phaseCounts), copyMap(h.blocked), h.logDropped
}
