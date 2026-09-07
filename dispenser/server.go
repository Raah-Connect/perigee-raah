package dispenser

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type ServerConfig struct {
	AdminToken string
	Service    PlanetService
}

type Server struct {
	adminToken string
	service    PlanetService
	router     *http.ServeMux
}

func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		adminToken: cfg.AdminToken,
		service:    cfg.Service,
		router:     http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) routes() {
	s.router.HandleFunc("/healthz", s.healthz)
	s.router.HandleFunc("/readyz", s.readyz)
	s.router.HandleFunc("/v1/planets/spawn", s.withAuth(s.spawnPlanet))
	s.router.HandleFunc("/v1/planets/", s.route)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.service == nil {
		http.Error(w, "service not configured", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken != "" {
			token := r.Header.Get("Admin-Token")
			if token != s.adminToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// route dispatches everything under /v1/planets/ by path segment count:
//
//	{planet}/{action}                       -> planetsSubresource (admin-authed)
//	{planet}/passport/{token}/download      -> downloadPassport (token-authed, no admin token)
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/v1/planets/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")

	switch len(parts) {
	case 2:
		s.withAuth(s.planetsSubresource)(w, r)
	case 4:
		if parts[1] == "passport" && parts[3] == "download" {
			s.downloadPassport(w, r, parts[0], parts[2])
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) spawnPlanet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.service == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	var req SpawnPlanetRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := s.service.SpawnPlanet(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) planetsSubresource(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/v1/planets/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	planet, action := parts[0], parts[1]

	switch action {
	case "transfer-reset":
		s.transferReset(w, r, planet)
	case "passport":
		s.generatePassport(w, r, planet)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) transferReset(w http.ResponseWriter, r *http.Request, planet string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.service == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	var req TransferResetRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.service.TransferAndReset(r.Context(), planet, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) generatePassport(w http.ResponseWriter, r *http.Request, planet string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.service == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	var req GeneratePassportRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.service.GeneratePassportZip(r.Context(), planet, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) downloadPassport(w http.ResponseWriter, r *http.Request, planet, token string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.service == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	path, err := s.service.ResolvePassportPath(r.Context(), planet, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "passport not found or expired", http.StatusNotFound)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		http.Error(w, "passport not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-passport.zip", strings.TrimPrefix(planet, "~")))
	http.ServeContent(w, r, filepath.Base(path), info.ModTime(), f)
}

func decodeJSON(r *http.Request, out any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
