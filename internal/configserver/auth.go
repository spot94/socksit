package configserver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie   = "socksit_cfg_sid"
	minPasswordLen  = 10
	maxLoginFails   = 5
	lockoutDuration = 5 * time.Minute
)

// Auth handles the single admin account, login sessions, brute-force lockout and
// CSRF for the admin surface. Sessions are in-memory (a restart logs admins out).
type Auth struct {
	dir      string
	secure   bool          // set the Secure cookie flag (true behind TLS)
	idle     time.Duration // inactivity timeout
	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string]*failInfo // keyed by client IP
}

type session struct {
	expiry  time.Time
	csrf    string
	role    string // RoleAdmin | RoleOperator
	display string // shown next to Log out
	kind    string // "local" | "ldap"
}

type failInfo struct {
	count int
	until time.Time
}

type adminFile struct {
	Hash string `json:"hash"`
}

// NewAuth loads the admin store. If no admin exists yet and envPassword is set,
// it bootstraps the admin from it (ADMIN_PASSWORD / docker secret).
func NewAuth(dir string, secure bool, idle time.Duration, envPassword string) (*Auth, error) {
	a := &Auth{dir: dir, secure: secure, idle: idle, sessions: map[string]*session{}, fails: map[string]*failInfo{}}
	if !a.HasAdmin() && strings.TrimSpace(envPassword) != "" {
		if err := a.SetPassword(envPassword); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *Auth) adminPath() string { return filepath.Join(a.dir, "admin.json") }

// HasAdmin reports whether the admin password has been set (first-run done).
func (a *Auth) HasAdmin() bool {
	_, err := os.Stat(a.adminPath())
	return err == nil
}

// SetPassword sets (or resets) the admin password after enforcing the policy.
func (a *Auth) SetPassword(pw string) error {
	if len([]rune(pw)) < minPasswordLen {
		return errors.New("password must be at least 10 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(adminFile{Hash: string(hash)})
	return os.WriteFile(a.adminPath(), b, 0o600)
}

func (a *Auth) verifyPassword(pw string) bool {
	b, err := os.ReadFile(a.adminPath())
	if err != nil {
		return false
	}
	var af adminFile
	if json.Unmarshal(b, &af) != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(af.Hash), []byte(pw)) == nil
}

// Login verifies the LOCAL admin password (subject to brute-force lockout) and
// starts an admin session, returning the session token and its CSRF token.
func (a *Auth) Login(ip, pw string) (token, csrf string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lockedLocked(ip) {
		return "", "", errors.New("too many attempts — try again later")
	}
	if !a.verifyPassword(pw) {
		a.failLocked(ip)
		return "", "", errors.New("wrong password")
	}
	delete(a.fails, ip)
	token, csrf = a.startLocked(RoleAdmin, "Local administrator", "local")
	return token, csrf, nil
}

// LockedOut reports whether ip is currently locked out (used before an LDAP bind).
func (a *Auth) LockedOut(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lockedLocked(ip)
}

// Fail records a failed login attempt (LDAP or local) for brute-force tracking.
func (a *Auth) Fail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failLocked(ip)
}

// StartSession creates a session for an already-authenticated principal (e.g. an
// LDAP user) and clears the IP's failure counter.
func (a *Auth) StartSession(ip, role, display, kind string) (token, csrf string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, ip)
	return a.startLocked(role, display, kind)
}

func (a *Auth) lockedLocked(ip string) bool {
	f := a.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

func (a *Auth) failLocked(ip string) {
	f := a.fails[ip]
	if f == nil {
		f = &failInfo{}
		a.fails[ip] = f
	}
	f.count++
	if f.count >= maxLoginFails {
		f.until = time.Now().Add(lockoutDuration)
		f.count = 0
	}
}

func (a *Auth) startLocked(role, display, kind string) (token, csrf string) {
	token, csrf = randToken(), randToken()
	a.sessions[token] = &session{expiry: time.Now().Add(a.idle), csrf: csrf, role: role, display: display, kind: kind}
	return token, csrf
}

// Logout invalidates the session behind the request.
func (a *Auth) Logout(r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return
	}
	a.mu.Lock()
	delete(a.sessions, c.Value)
	a.mu.Unlock()
}

// validate returns the live session for the request (refreshing its idle timer),
// or nil if unauthenticated/expired.
func (a *Auth) validate(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return nil
	}
	if time.Now().After(s.expiry) {
		delete(a.sessions, c.Value)
		return nil
	}
	s.expiry = time.Now().Add(a.idle) // sliding inactivity window
	return s
}

// setSessionCookie writes the session cookie on login.
func (a *Auth) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *Auth) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode})
}

// requireAuth guards an admin handler: a valid session is required, and mutating
// requests must carry the matching CSRF token.
func (a *Auth) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := a.validate(r)
		if s == nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrf)) != 1 {
				http.Error(w, "bad or missing CSRF token", http.StatusForbidden)
				return
			}
		}
		h(w, r)
	}
}

// requireAdmin is requireAuth plus an Administrator-role check (operators get 403).
func (a *Auth) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if s := a.validate(r); s == nil || s.role != RoleAdmin {
			http.Error(w, "administrator role required", http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

// roleOf returns the role for the request's session (empty if none).
func (a *Auth) roleOf(r *http.Request) string {
	if s := a.validate(r); s != nil {
		return s.role
	}
	return ""
}

// actor returns a human-readable audit actor for the request's session.
func (a *Auth) actor(r *http.Request) string {
	if s := a.validate(r); s != nil {
		if s.display != "" {
			return s.display
		}
		return s.role
	}
	return "?"
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// clientIP extracts a best-effort client IP for brute-force keying.
func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
