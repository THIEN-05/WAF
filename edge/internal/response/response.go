package response

import (
	"fmt"
	"html"
	"net/http"
	"strconv"

	"github.com/example/wafplatform/edge/internal/reqctx"
)

type SecurityHeaders struct {
	HSTS               bool
	ContentTypeNosniff bool
	FrameOptions       string
	ReferrerPolicy     string
	RemoveServer       bool
}

func ApplyHeaders(h http.Header, c SecurityHeaders) {
	if c.HSTS {
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	if c.ContentTypeNosniff {
		h.Set("X-Content-Type-Options", "nosniff")
	}
	if c.FrameOptions != "" {
		h.Set("X-Frame-Options", c.FrameOptions)
	}
	if c.ReferrerPolicy != "" {
		h.Set("Referrer-Policy", c.ReferrerPolicy)
	}
	if c.RemoveServer {
		h.Del("Server")
		h.Del("X-Powered-By")
	}
}
func Block(w http.ResponseWriter, c *reqctx.RequestCtx, status int, reason string) {
	respond(w, c, status, "Request blocked", reason)
}
func Challenge(w http.ResponseWriter, c *reqctx.RequestCtx) {
	respond(w, c, http.StatusForbidden, "Challenge required", "challenge")
}
func respond(w http.ResponseWriter, c *reqctx.RequestCtx, status int, title, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Request-ID", c.RequestID)
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><title>%s</title><h1>%s</h1><p>Request ID: <code>%s</code></p><small>%s</small>", html.EscapeString(title), html.EscapeString(title), html.EscapeString(c.RequestID), html.EscapeString(strconv.Quote(reason)))
}
