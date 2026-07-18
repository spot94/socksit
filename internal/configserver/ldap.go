package configserver

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

// Roles.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
)

// LDAPConfig is the operator-provisioned directory configuration (Active
// Directory / LDAP). BindPassword is a secret kept on the data volume and never
// returned to the browser.
type LDAPConfig struct {
	Enabled            bool   `json:"enabled"`
	URL                string `json:"url"`      // ldap://host:389 | ldaps://host:636
	StartTLS           bool   `json:"startTLS"` // upgrade a plain ldap:// connection
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	BindDN             string `json:"bindDN"`                 // service account used to search
	BindPassword       string `json:"bindPassword,omitempty"` // secret; blanked in GET responses
	BaseDN             string `json:"baseDN"`
	UserFilter         string `json:"userFilter"`     // {user} is replaced by the login name
	AdminFilter        string `json:"adminFilter"`    // matched against the user's own entry
	OperatorFilter     string `json:"operatorFilter"` // matched against the user's own entry
	DisplayAttr        string `json:"displayAttr"`    // e.g. displayName
}

// LDAP holds the directory config and performs authentication.
type LDAP struct {
	dir string
	mu  sync.RWMutex
	cfg LDAPConfig
}

// NewLDAP loads the stored LDAP config (if any) from dir.
func NewLDAP(dir string) (*LDAP, error) {
	l := &LDAP{dir: dir}
	if b, err := os.ReadFile(l.path()); err == nil {
		_ = json.Unmarshal(b, &l.cfg)
	}
	return l, nil
}

func (l *LDAP) path() string { return filepath.Join(l.dir, "ldap.json") }

// Enabled reports whether LDAP login is configured and turned on.
func (l *LDAP) Enabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg.Enabled
}

// Config returns the config for the admin UI with the bind password blanked.
func (l *LDAP) Config() LDAPConfig {
	l.mu.RLock()
	defer l.mu.RUnlock()
	c := l.cfg
	c.BindPassword = ""
	return c
}

func (l *LDAP) raw() LDAPConfig {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg
}

// Save validates and persists the config. An empty BindPassword keeps the stored
// one (the UI never sees the secret, so a blank field means "unchanged").
func (l *LDAP) Save(cfg LDAPConfig) error {
	cfg.URL = strings.TrimSpace(cfg.URL)
	if cfg.Enabled {
		if !strings.HasPrefix(cfg.URL, "ldap://") && !strings.HasPrefix(cfg.URL, "ldaps://") {
			return errors.New("url must start with ldap:// or ldaps://")
		}
		if strings.TrimSpace(cfg.BaseDN) == "" {
			return errors.New("base DN is required")
		}
		if !strings.Contains(cfg.UserFilter, "{user}") {
			return errors.New("user filter must contain the {user} placeholder")
		}
		if strings.TrimSpace(cfg.AdminFilter) == "" && strings.TrimSpace(cfg.OperatorFilter) == "" {
			return errors.New("set at least an admin or operator filter")
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if strings.TrimSpace(cfg.BindPassword) == "" {
		cfg.BindPassword = l.cfg.BindPassword // keep existing secret
	}
	if strings.TrimSpace(cfg.DisplayAttr) == "" {
		cfg.DisplayAttr = "displayName"
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(l.path(), b, 0o600); err != nil {
		return err
	}
	l.cfg = cfg
	return nil
}

// dial opens a connection honouring the URL scheme, StartTLS and skip-verify.
func (l *LDAP) dial(cfg LDAPConfig) (*ldap.Conn, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} // #nosec G402 — operator opt-in for self-signed
	if strings.HasPrefix(cfg.URL, "ldaps://") {
		return ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS: %w", err)
		}
	}
	return conn, nil
}

// bindService binds the service account (no-op if no bind DN is configured).
func bindService(conn *ldap.Conn, cfg LDAPConfig) error {
	if strings.TrimSpace(cfg.BindDN) == "" {
		return nil
	}
	return conn.Bind(cfg.BindDN, cfg.BindPassword)
}

// Test verifies the configuration can connect and bind the service account.
func (l *LDAP) Test() error {
	cfg := l.raw()
	if !cfg.Enabled {
		return errors.New("LDAP is not enabled")
	}
	conn, err := l.dial(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := bindService(conn, cfg); err != nil {
		return fmt.Errorf("service bind failed: %w", err)
	}
	return nil
}

// Authenticate verifies the user's credentials and returns their role and
// display name. Flow: bind the service account, find the user (userFilter),
// re-bind as the user to check the password, then decide the role by matching
// the admin/operator filter against the user's own entry.
func (l *LDAP) Authenticate(username, password string) (role, display string, err error) {
	cfg := l.raw()
	if !cfg.Enabled {
		return "", "", errors.New("LDAP is not enabled")
	}
	if strings.TrimSpace(password) == "" {
		return "", "", errors.New("password required") // never allow an anonymous/unauthenticated bind
	}
	conn, err := l.dial(cfg)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	if err := bindService(conn, cfg); err != nil {
		return "", "", fmt.Errorf("service bind failed: %w", err)
	}

	filter := strings.ReplaceAll(cfg.UserFilter, "{user}", ldap.EscapeFilter(username))
	sr, err := conn.Search(ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 10, false, filter, []string{cfg.DisplayAttr}, nil))
	if err != nil {
		return "", "", fmt.Errorf("user search: %w", err)
	}
	if len(sr.Entries) != 1 {
		return "", "", errors.New("user not found")
	}
	userDN := sr.Entries[0].DN
	display = sr.Entries[0].GetAttributeValue(cfg.DisplayAttr)
	if display == "" {
		display = username
	}

	if err := conn.Bind(userDN, password); err != nil {
		return "", "", errors.New("invalid credentials")
	}
	// The user bind may lack search rights; re-bind the service account for roles.
	if err := bindService(conn, cfg); err != nil {
		return "", "", err
	}
	switch {
	case cfg.AdminFilter != "" && matchesEntry(conn, userDN, cfg.AdminFilter):
		role = RoleAdmin
	case cfg.OperatorFilter != "" && matchesEntry(conn, userDN, cfg.OperatorFilter):
		role = RoleOperator
	default:
		return "", "", errors.New("this account has no Administrator or Operator role")
	}
	return role, display, nil
}

// matchesEntry reports whether the user's own entry satisfies filter (base scope).
func matchesEntry(conn *ldap.Conn, userDN, filter string) bool {
	sr, err := conn.Search(ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 5, false, filter, []string{"1.1"}, nil))
	return err == nil && len(sr.Entries) == 1
}
