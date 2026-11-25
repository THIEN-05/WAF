package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/example/wafplatform/controlplane/internal/entitlement"
	"github.com/example/wafplatform/controlplane/internal/platform/problem"
	"github.com/example/wafplatform/controlplane/internal/site"
	"github.com/example/wafplatform/controlplane/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) siteService() site.Service {
	return site.Service{Pool: s.pool.Pool, Quota: s.entitlements}
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_tenant", "Invalid tenant", "Tenant identifier is invalid")
		return
	}
	if tenantID != p.tenantID {
		problem.Write(w, r, http.StatusNotFound, "not_found", "Not found", "Resource not found")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	created, err := s.siteService().Create(r.Context(), tenantID, p.userID, in.Name)
	if err != nil {
		code, detail := http.StatusBadRequest, "Site could not be created"
		if errors.Is(err, entitlement.ErrQuotaExceeded) {
			code, detail = http.StatusConflict, "The site quota for this plan has been reached"
		}
		if errors.Is(err, tenant.ErrForbidden) {
			code, detail = http.StatusForbidden, "Site management is not allowed"
		}
		problem.Write(w, r, code, "site_create_failed", "Unable to create site", detail)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	siteID, e := uuid.Parse(chi.URLParam(r, "site_id"))
	if err != nil || e != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_resource", "Invalid resource", "Tenant or site identifier is invalid")
		return
	}
	if tenantID != p.tenantID {
		problem.Write(w, r, http.StatusNotFound, "not_found", "Not found", "Resource not found")
		return
	}
	var in struct {
		Hostname string `json:"hostname"`
	}
	if !decode(w, r, &in) {
		return
	}
	proof, err := s.siteService().AddDomain(r.Context(), tenantID, p.userID, siteID, in.Hostname)
	if err != nil {
		code, detail := http.StatusInternalServerError, "Domain operation failed"
		if errors.Is(err, site.ErrHostnameUnavailable) {
			code, detail = http.StatusConflict, "Hostname is unavailable"
		}
		if errors.Is(err, site.ErrSiteNotFound) {
			code, detail = http.StatusNotFound, "Site not found"
		}
		if errors.Is(err, tenant.ErrForbidden) {
			code, detail = http.StatusForbidden, "Site management is not allowed"
		}
		problem.Write(w, r, code, "domain_add_failed", "Unable to add domain", detail)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(proof)
}

func (s *Server) addOrigin(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	siteID, e := uuid.Parse(chi.URLParam(r, "site_id"))
	if err != nil || e != nil {
		problem.Write(w, r, http.StatusBadRequest, "invalid_resource", "Invalid resource", "Tenant or site identifier is invalid")
		return
	}
	if tenantID != p.tenantID {
		problem.Write(w, r, http.StatusNotFound, "not_found", "Not found", "Resource not found")
		return
	}
	var in struct {
		URL string `json:"url"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, err := s.siteService().AddOrigin(r.Context(), tenantID, p.userID, siteID, in.URL, site.NetResolver{})
	if err != nil {
		code, detail := http.StatusBadRequest, "Origin is invalid or unavailable"
		if errors.Is(err, site.ErrSiteNotFound) {
			code, detail = http.StatusNotFound, "Site not found"
		}
		if errors.Is(err, tenant.ErrForbidden) {
			code, detail = http.StatusForbidden, "Site management is not allowed"
		}
		problem.Write(w, r, code, "origin_invalid", "Invalid origin", detail)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id.String()})
}
