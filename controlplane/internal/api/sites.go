package api

import (
	"encoding/json"
	"net/http"

	"github.com/example/wafplatform/controlplane/internal/platform/problem"
	"github.com/example/wafplatform/controlplane/internal/site"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) siteService() site.Service {
	return site.Service{Pool: s.pool.Pool, Quota: s.entitlements}
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil || tenantID != p.tenantID {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Forbidden", "Tenant access denied")
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
		problem.Write(w, r, http.StatusBadRequest, "site_create_failed", "Unable to create site", err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	siteID, e := uuid.Parse(chi.URLParam(r, "site_id"))
	if err != nil || e != nil || tenantID != p.tenantID {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Forbidden", "Tenant access denied")
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
		problem.Write(w, r, http.StatusBadRequest, "domain_add_failed", "Unable to add domain", err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(proof)
}

func (s *Server) addOrigin(w http.ResponseWriter, r *http.Request) {
	p := getPrincipal(r)
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	siteID, e := uuid.Parse(chi.URLParam(r, "site_id"))
	if err != nil || e != nil || tenantID != p.tenantID {
		problem.Write(w, r, http.StatusForbidden, "forbidden", "Forbidden", "Tenant access denied")
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
		problem.Write(w, r, http.StatusBadRequest, "origin_invalid", "Invalid origin", err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id.String()})
}
