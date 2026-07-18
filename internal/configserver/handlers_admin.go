package configserver

import (
	"net/http"
)

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"profiles": s.store.ListProfiles()})
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetProfile(r.PathValue("name"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSaveProfile(w http.ResponseWriter, r *http.Request) {
	var v ProfileView
	if !readJSON(w, r, &v) {
		return
	}
	v.Name = r.PathValue("name") // the URL segment is authoritative
	// Operators can edit routing but not migration: keep the profile's existing
	// migration regardless of what they submit.
	if s.auth.roleOf(r) == RoleOperator {
		if cur, err := s.store.GetProfile(v.Name); err == nil {
			v.Migrate = cur.Migrate
		} else {
			v.Migrate = nil
		}
	}
	if err := s.store.SaveProfile(&v); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.Log(s.auth.actor(r), "save profile", "profile \""+v.Name+"\"", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteProfile(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.Log(s.auth.actor(r), "delete profile", "profile \""+name+"\"", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"hasKey": s.store.HasKey(), "publicKey": s.store.PublicKeyB64()})
}

func (s *Server) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	pub, err := s.store.GenerateKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit.Log(s.auth.actor(r), "generate signing key", "public "+pub, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": pub})
}

func (s *Server) handleImportKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PrivateKey string `json:"privateKey"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	pub, err := s.store.ImportKey(in.PrivateKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.Log(s.auth.actor(r), "import signing key", "public "+pub, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": pub})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.audit.Tail(200)})
}

func (s *Server) handleGetLDAP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ldap.Config()) // bind password blanked
}

func (s *Server) handleSaveLDAP(w http.ResponseWriter, r *http.Request) {
	var cfg LDAPConfig
	if !readJSON(w, r, &cfg) {
		return
	}
	if err := s.ldap.Save(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit.Log(s.auth.actor(r), "save LDAP config (enabled="+boolStr(cfg.Enabled)+")", s.ldap.Config().URL, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleTestLDAP(w http.ResponseWriter, r *http.Request) {
	if err := s.ldap.Test(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
