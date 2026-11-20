package pipeline

import (
	"fmt"
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
	for _, ph := range p.phases {
		start := time.Now()
		d := ph.Handle(c)
		if p.observer != nil {
			p.observer.ObservePhase(ph.Name(), time.Since(start))
		}
		c.SetDecision(d)
		if d.Terminal() {
			return d
		}
	}
	d := reqctx.Decision{Action: reqctx.ActionAllow, Phase: "pipeline", Reason: "no terminal decision"}
	c.SetDecision(d)
	return d
}

type Histogram struct {
	mu         sync.Mutex
	counts     map[string][]uint64
	sums       map[string]float64
	bounds     []float64
	blocked    map[string]uint64
	logDropped uint64
}

func NewHistogram() *Histogram {
	return &Histogram{counts: map[string][]uint64{}, sums: map[string]float64{}, bounds: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}, blocked: map[string]uint64{}}
}

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
	for phase, counts := range h.counts {
		for i, b := range h.bounds {
			fmt.Fprintf(w, "edge_phase_duration_seconds_bucket{phase=%q,le=%q} %d\n", phase, strconv.FormatFloat(b, 'f', -1, 64), counts[i])
		}
		fmt.Fprintf(w, "edge_phase_duration_seconds_bucket{phase=%q,le=\"+Inf\"} %d\n", phase, counts[len(h.bounds)])
		fmt.Fprintf(w, "edge_phase_duration_seconds_sum{phase=%q} %f\n", phase, h.sums[phase])
		fmt.Fprintf(w, "edge_phase_duration_seconds_count{phase=%q} %d\n", phase, counts[len(h.bounds)])
	}
	for action, count := range h.blocked {
		fmt.Fprintf(w, "edge_blocked_total{action=%q} %d\n", action, count)
	}
	fmt.Fprintf(w, "edge_log_dropped_total %d\n", h.logDropped)
}
