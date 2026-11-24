package pipeline

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
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
	counts      map[string][]uint64
	sums        map[string]float64
	bounds      []float64
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
	h := &Histogram{counts: map[string][]uint64{}, sums: map[string]float64{}, bounds: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}, blocked: map[string]uint64{}}
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
func (h *Histogram) ObservePhase(name string, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.counts[name] == nil {
		h.counts[name] = make([]uint64, len(h.bounds)+1)
	}
	seconds := d.Seconds()
	h.sums[name] += seconds
	for i, b := range h.bounds {
		if seconds <= b {
			h.counts[name][i]++
		}
	}
	h.counts[name][len(h.bounds)]++
}
func (h *Histogram) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	out := firstErrorWriter{writer: w}
	for phase, counts := range h.counts {
		for i, b := range h.bounds {
			out.Printf("edge_phase_duration_seconds_bucket{phase=%q,le=%q} %d\n", phase, strconv.FormatFloat(b, 'f', -1, 64), counts[i])
		}
		out.Printf("edge_phase_duration_seconds_bucket{phase=%q,le=\"+Inf\"} %d\n", phase, counts[len(h.bounds)])
		out.Printf("edge_phase_duration_seconds_sum{phase=%q} %f\n", phase, h.sums[phase])
		out.Printf("edge_phase_duration_seconds_count{phase=%q} %d\n", phase, counts[len(h.bounds)])
	}
	for action, count := range h.blocked {
		out.Printf("edge_blocked_total{action=%q} %d\n", action, count)
	}
	out.Printf("edge_log_dropped_total %d\n", h.logDropped)
	auditCounts := h.AuditCounts()
	out.Printf("edge_waf_budget_exceeded_total %d\n", auditCounts[AuditWAFBudgetExceeded])
	out.Printf("edge_waf_body_truncated_total %d\n", auditCounts[AuditWAFBodyTruncated])
	out.Printf("edge_waf_body_read_timeout_total %d\n", auditCounts[AuditWAFBodyReadTimeout])
	out.Printf("edge_waf_work_exhausted_total %d\n", auditCounts[AuditWAFWorkExhausted])
	out.Printf("edge_waf_degraded_paranoia_total %d\n", auditCounts[AuditWAFDegradedParanoia])
	out.Printf("edge_waf_degraded_scope_total %d\n", auditCounts[AuditWAFDegradedScope])
	out.Printf("edge_waf_degraded_fail_mode_total %d\n", auditCounts[AuditWAFDegradedFailMode])
	out.Printf("edge_waf_audit_dropped_total %d\n", h.audit.Dropped())
	if out.err != nil {
		log.Printf("metrics exporter: lỗi ghi phản hồi: %v", out.err)
	}
}

type firstErrorWriter struct {
	writer http.ResponseWriter
	err    error
}

func (w *firstErrorWriter) Printf(format string, args ...any) {
	if w.err != nil {
		return
	}
	_, w.err = fmt.Fprintf(w.writer, format, args...)
}
