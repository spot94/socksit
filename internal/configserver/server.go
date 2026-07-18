package configserver

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
)

//go:embed web/index.html
var indexHTML []byte

// Server wires the store, auth and audit log to HTTP routes.
type Server struct {
	store *Store
	auth  *Auth
	audit *Audit
	mux   *http.ServeMux
}

// New builds the router.
func New(store *Store, auth *Auth, audit *Audit) *Server {
	s := &Server{store: store, auth: auth, audit: audit, mux: http.NewServeMux()}
	// Public feed (integrity via signature, no auth).
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	s.mux.HandleFunc("GET /configs/{name}/socksit.yaml", s.serveConfig)
	s.mux.HandleFunc("GET /configs/{name}/socksit.yaml.sig", s.serveSig)
	s.mux.HandleFunc("GET /configs/{name}/migrate.yaml", s.serveMigrate)
	s.mux.HandleFunc("GET /configs/{name}/migrate.yaml.sig", s.serveMigrateSig)
	// Admin UI + auth flow.
	s.mux.HandleFunc("GET /{$}", s.serveUI)
	s.mux.HandleFunc("GET /api/session", s.handleSession)
	s.mux.HandleFunc("POST /api/setup", s.handleSetup)
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	// Admin API (auth + CSRF via requireAuth).
	s.mux.HandleFunc("GET /api/profiles", auth.requireAuth(s.handleListProfiles))
	s.mux.HandleFunc("GET /api/profiles/{name}", auth.requireAuth(s.handleGetProfile))
	s.mux.HandleFunc("POST /api/profiles/{name}", auth.requireAuth(s.handleSaveProfile))
	s.mux.HandleFunc("DELETE /api/profiles/{name}", auth.requireAuth(s.handleDeleteProfile))
	s.mux.HandleFunc("GET /api/key", auth.requireAuth(s.handleGetKey))
	s.mux.HandleFunc("POST /api/key/generate", auth.requireAuth(s.handleGenerateKey))
	s.mux.HandleFunc("POST /api/key/import", auth.requireAuth(s.handleImportKey))
	s.mux.HandleFunc("GET /api/audit", auth.requireAuth(s.handleAudit))
	return s
}

// Handler returns the top-level handler with security headers applied.
func (s *Server) Handler() http.Handler { return securityHeaders(s.mux) }

// securityHeaders sets conservative defaults. The admin UI is a self-contained
// single page, so the CSP only needs 'self' plus inline style/script.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-cache") // always revalidate — avoids stale UI after a rebuild
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// --- public feed ---

func (s *Server) serveConfig(w http.ResponseWriter, r *http.Request) {
	body, _, err := s.store.ServedBytes(r.PathValue("name"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Write(body)
}

func (s *Server) serveSig(w http.ResponseWriter, r *http.Request) {
	_, sig, err := s.store.ServedBytes(r.PathValue("name"))
	if err != nil || len(sig) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(sig)
}

func (s *Server) serveMigrate(w http.ResponseWriter, r *http.Request) {
	body, _, err := s.store.ServedMigrate(r.PathValue("name"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Write(body)
}

func (s *Server) serveMigrateSig(w http.ResponseWriter, r *http.Request) {
	_, sig, err := s.store.ServedMigrate(r.PathValue("name"))
	if err != nil || len(sig) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(sig)
}

// --- UI + auth flow ---

func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"hasAdmin": s.auth.HasAdmin(), "authenticated": false}
	if sess := s.auth.validate(r); sess != nil {
		resp["authenticated"] = true
		resp["csrf"] = sess.csrf
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.auth.HasAdmin() {
		http.Error(w, "admin already configured", http.StatusConflict)
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.auth.SetPassword(in.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token, csrf, err := s.auth.Login(clientIP(r), in.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auth.setSessionCookie(w, token)
	s.audit.Log("admin", "first-run: set admin password", "-", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"csrf": csrf})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	token, csrf, err := s.auth.Login(ip, in.Password)
	if err != nil {
		s.audit.Log("admin", "failed login", "-", ip)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	s.auth.setSessionCookie(w, token)
	s.audit.Log("admin", "login", "-", ip)
	writeJSON(w, http.StatusOK, map[string]any{"csrf": csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Logout(r)
	s.auth.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}
