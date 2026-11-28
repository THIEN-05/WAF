package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/example/wafplatform/controlplane/internal/platform/problem"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func apiEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func (s *Server) siteAnalytics(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	siteID, err := uuid.Parse(chi.URLParam(r, "site_id"))
	if err != nil {
		problem.Write(w, r, http.StatusNotFound, "not_found", "Not found", "Resource not found")
		return
	}
	kind := chi.URLParam(r, "view")
	var from, to time.Time
	if raw := r.URL.Query().Get("from"); raw != "" {
		from, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			problem.Write(w, r, http.StatusBadRequest, "invalid_range", "Invalid range", "Use RFC3339 timestamps")
			return
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		to, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			problem.Write(w, r, http.StatusBadRequest, "invalid_range", "Invalid range", "Use RFC3339 timestamps")
			return
		}
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 {
			problem.Write(w, r, http.StatusBadRequest, "invalid_limit", "Invalid limit", "Limit must be a positive integer")
			return
		}
	}
	result, err := s.analytics.Query(r.Context(), p.tenantID, siteID, kind, from, to, limit)
	if err != nil {
		status, code := http.StatusServiceUnavailable, "analytics_unavailable"
		if strings.Contains(err.Error(), "site not found") {
			status, code = http.StatusNotFound, "not_found"
		} else if strings.Contains(err.Error(), "range exceeds") || strings.Contains(err.Error(), "unsupported analytics") {
			status, code = http.StatusBadRequest, "invalid_analytics_query"
		}
		problem.Write(w, r, status, code, "Analytics unavailable", "The requested analytics could not be loaded")
		return
	}
	w.Header().Set("Cache-Control", "private, max-age=0")
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(result); err != nil {
		return
	}
}
