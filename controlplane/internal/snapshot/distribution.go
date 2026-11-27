package snapshot

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
)

type EdgeHandler struct {
	Repository Repository
	Objects    Objects
	Resolver   EdgeIdentityResolver
}

type EdgeIdentityResolver interface {
	ResolveEdge(context.Context, *x509.Certificate) (edgeID, region string, err error)
}

func (h EdgeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	if h.Resolver == nil {
		http.Error(w, "edge identity resolver unavailable", http.StatusServiceUnavailable)
		return
	}
	requestedEdge := r.URL.Query().Get("edge_id")
	if requestedEdge == "" {
		http.Error(w, "edge_id is required", http.StatusBadRequest)
		return
	}
	registeredEdge, region, err := h.Resolver.ResolveEdge(r.Context(), r.TLS.PeerCertificates[0])
	if err != nil || registeredEdge != requestedEdge || !certificateNamesEdge(r.TLS.PeerCertificates[0], registeredEdge) || !validRegion(region) {
		http.Error(w, "edge identity is not registered", http.StatusForbidden)
		return
	}
	latest, err := h.Repository.Latest(r.Context(), region)
	if errors.Is(err, ErrNoSnapshot) {
		http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	etag := `"` + latest.Checksum + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	sinceRaw := r.URL.Query().Get("since")
	if sinceRaw != "" {
		since, parseErr := strconv.ParseUint(sinceRaw, 10, 64)
		if parseErr != nil {
			http.Error(w, "invalid since version", http.StatusBadRequest)
			return
		}
		if latest.Version <= since {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	data, err := h.Objects.Get(r.Context(), latest.ObjectKey)
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func certificateNamesEdge(cert *x509.Certificate, edgeID string) bool {
	if cert == nil || edgeID == "" {
		return false
	}
	if cert.Subject.CommonName == edgeID {
		return true
	}
	for _, name := range cert.DNSNames {
		if name == edgeID {
			return true
		}
	}
	for _, uri := range cert.URIs {
		if uri != nil && uri.Path == "/edges/"+edgeID {
			return true
		}
	}
	return false
}

type UpdateNotifier interface {
	Publish(subject string, data []byte) error
}

func NotifyUpdated(notifier UpdateNotifier, region string, record Record) error {
	if notifier == nil {
		return errors.New("snapshot notifier is required")
	}
	body, err := json.Marshal(struct {
		Region   string `json:"region"`
		Version  uint64 `json:"version"`
		Checksum string `json:"checksum_sha256"`
	}{region, record.Version, record.Checksum})
	if err != nil {
		return err
	}
	if err := notifier.Publish("config.updated", body); err != nil {
		return err
	}
	if flusher, ok := notifier.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// RunDebounced coalesces config.changed events because each build reads the latest
// committed database state. A one-slot trigger channel intentionally collapses bursts.
func RunDebounced(ctx context.Context, triggers <-chan struct{}, delay time.Duration, build func(context.Context) error, onError func(error)) error {
	if delay <= 0 {
		delay = 3 * time.Second
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()
		case _, ok := <-triggers:
			if !ok {
				if timer != nil {
					timer.Stop()
				}
				return nil
			}
			if timer == nil {
				timer = time.NewTimer(delay)
				timerC = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(delay)
			}
		case <-timerC:
			timerC = nil
			if err := build(ctx); err != nil && onError != nil {
				onError(err)
			}
			timer = nil
		}
	}
}
