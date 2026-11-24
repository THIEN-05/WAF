package problem

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/example/wafplatform/controlplane/internal/platform/logger"
)

type Detail struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Instance  string `json:"instance,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Code      string `json:"code,omitempty"`
}

func Write(w http.ResponseWriter, r *http.Request, status int, code, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	path := r.URL.Path
	if strings.Contains(path, "?") {
		path = path[:strings.IndexByte(path, '?')]
	}
	_ = json.NewEncoder(w).Encode(Detail{Type: "about:blank", Title: title, Status: status, Detail: detail, Instance: path, RequestID: logger.RequestID(r.Context()), Code: code})
}
