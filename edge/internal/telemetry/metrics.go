package telemetry

import (
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/example/wafplatform/edge/internal/pipeline"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusMetrics adapts the existing pipeline metrics interface to the
// official Prometheus registry. Labels are deliberately bounded and never
// contain tenant, site, path, host, request ID, or rule ID.
type PrometheusMetrics struct {
	registry         *prometheus.Registry
	requests         *prometheus.CounterVec
	phases           *prometheus.HistogramVec
	blocked          *prometheus.CounterVec
	rateLimited      prometheus.Counter
	logDropped       prometheus.Counter
	cacheHits        prometheus.Counter
	originErrors     *prometheus.CounterVec
	snapshotVer      prometheus.Gauge
	snapshotAge      prometheus.Gauge
	snapshotStale    prometheus.Gauge
	clientCertExpiry prometheus.Gauge
	goroutines       prometheus.Gauge
	memoryBytes      prometheus.Gauge
	auditDropped     prometheus.Counter
	auditCounters    *prometheus.CounterVec
}

func NewPrometheusMetrics() *PrometheusMetrics {
	r := prometheus.NewRegistry()
	m := &PrometheusMetrics{
		registry:         r,
		requests:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "edge_requests_total", Help: "Requests handled by the edge."}, []string{"method", "status_class"}),
		phases:           prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "edge_phase_duration_seconds", Help: "Time spent in each request phase.", Buckets: prometheus.DefBuckets}, []string{"phase"}),
		blocked:          prometheus.NewCounterVec(prometheus.CounterOpts{Name: "edge_blocked_total", Help: "Requests blocked or challenged by policy group."}, []string{"group"}),
		rateLimited:      prometheus.NewCounter(prometheus.CounterOpts{Name: "edge_rate_limited_total", Help: "Requests rejected by rate limiting."}),
		logDropped:       prometheus.NewCounter(prometheus.CounterOpts{Name: "edge_log_dropped_total", Help: "Telemetry records dropped because the bounded queue was full or delivery failed."}),
		cacheHits:        prometheus.NewCounter(prometheus.CounterOpts{Name: "edge_cache_hits_total", Help: "Responses served from edge cache."}),
		originErrors:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "edge_origin_errors_total", Help: "Origin failures by bounded response class."}, []string{"status_class"}),
		snapshotVer:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "edge_snapshot_version", Help: "Version of the active edge configuration snapshot."}),
		snapshotAge:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "edge_snapshot_age_seconds", Help: "Age of the active edge configuration snapshot."}),
		snapshotStale:    prometheus.NewGauge(prometheus.GaugeOpts{Name: "edge_snapshot_stale", Help: "Whether the active edge configuration snapshot exceeded its age threshold."}),
		clientCertExpiry: prometheus.NewGauge(prometheus.GaugeOpts{Name: "edge_mtls_certificate_expiry_timestamp_seconds", Help: "Expiry time of the active edge mTLS client certificate."}),
		goroutines:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "edge_goroutines", Help: "Current Go runtime goroutine count."}),
		memoryBytes:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "edge_memory_bytes", Help: "Current Go runtime allocated heap bytes."}),
		auditDropped:     prometheus.NewCounter(prometheus.CounterOpts{Name: "edge_audit_dropped_total", Help: "Asynchronous audit events dropped because the bounded queue was full."}),
		auditCounters:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "edge_audit_events_total", Help: "Asynchronous WAF audit events by bounded event kind."}, []string{"kind"}),
	}
	r.MustRegister(m.requests, m.phases, m.blocked, m.rateLimited, m.logDropped, m.cacheHits, m.originErrors, m.snapshotVer, m.snapshotAge, m.snapshotStale, m.clientCertExpiry, m.goroutines, m.memoryBytes, m.auditDropped, m.auditCounters)
	return m
}

func (m *PrometheusMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
func (m *PrometheusMetrics) Registry() *prometheus.Registry { return m.registry }
func (m *PrometheusMetrics) ObservePhase(name string, d time.Duration) {
	m.phases.WithLabelValues(phaseLabel(name)).Observe(d.Seconds())
}
func (m *PrometheusMetrics) Blocked(action string) { m.BlockedGroup(action) }
func (m *PrometheusMetrics) BlockedGroup(group string) {
	m.blocked.WithLabelValues(policyGroup(group)).Inc()
}
func (m *PrometheusMetrics) RateLimited() { m.rateLimited.Inc() }
func (m *PrometheusMetrics) CacheHit()    { m.cacheHits.Inc() }
func (m *PrometheusMetrics) OriginError(status int) {
	m.originErrors.WithLabelValues(statusClass(status)).Inc()
}
func (m *PrometheusMetrics) LogDropped(n uint64) {
	if n != 0 {
		m.logDropped.Add(float64(n))
	}
}
func (m *PrometheusMetrics) AuditDropped(n uint64) {
	if n != 0 {
		m.auditDropped.Add(float64(n))
	}
}
func (m *PrometheusMetrics) AuditEvent(kind string) {
	m.auditCounters.WithLabelValues(auditKind(kind)).Inc()
}
func (m *PrometheusMetrics) ObserveRequest(method string, status int) {
	m.requests.WithLabelValues(methodLabel(method), statusClass(status)).Inc()
}
func (m *PrometheusMetrics) SetSnapshot(version uint64, ageSeconds float64, stale bool) {
	m.snapshotVer.Set(float64(version))
	m.snapshotAge.Set(ageSeconds)
	if stale {
		m.snapshotStale.Set(1)
	} else {
		m.snapshotStale.Set(0)
	}
}
func (m *PrometheusMetrics) SetClientCertificateExpiry(expiry time.Time) {
	if expiry.IsZero() {
		m.clientCertExpiry.Set(0)
		return
	}
	m.clientCertExpiry.Set(float64(expiry.Unix()))
}
func (m *PrometheusMetrics) RefreshRuntime() {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	m.goroutines.Set(float64(runtime.NumGoroutine()))
	m.memoryBytes.Set(float64(stats.HeapAlloc))
}

func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}
func statusClass(status int) string {
	if status < 100 || status > 599 {
		return "unknown"
	}
	return strconv.Itoa(status/100) + "xx"
}
func phaseLabel(name string) string {
	switch name {
	case "access", "ratelimit", "rules", "waf", "bot", "pipeline":
		return name
	default:
		return "other"
	}
}
func policyGroup(name string) string {
	switch strings.ToLower(name) {
	case "access", "ratelimit", "rules", "waf", "bot", "panic", "block", "challenge", "rate_limited":
		return strings.ToLower(name)
	default:
		return "other"
	}
}
func auditKind(kind string) string {
	switch kind {
	case pipeline.AuditWAFBudgetExceeded, pipeline.AuditWAFBodyTruncated, pipeline.AuditWAFBodyReadTimeout, pipeline.AuditWAFWorkExhausted, pipeline.AuditWAFDegradedParanoia, pipeline.AuditWAFDegradedScope, pipeline.AuditWAFDegradedFailMode:
		return kind
	default:
		return "other"
	}
}
