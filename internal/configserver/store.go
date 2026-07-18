// Package configserver is the server half of SocksIt's managed-config channel: a
// small web service that hosts signed socksit.yaml feeds and an authenticated
// admin UI to edit them and manage the Ed25519 signing key. Clients point their
// config_source.url at a profile's URL and their config_source.pubkey at the
// key shown here. See docs/configserver.md.
package configserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"socksit/internal/config"
)

// Store persists the signing key and the named config profiles under a data dir
// (a mounted volume in Docker — never the image). It is safe for concurrent use.
type Store struct {
	dir  string
	mu   sync.RWMutex
	priv ed25519.PrivateKey // nil until a key is generated or imported
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// validName reports whether name is a safe profile/URL segment.
func validName(name string) bool { return nameRE.MatchString(name) }

// Open prepares the data dir layout and loads an existing signing key if present.
func Open(dir string) (*Store, error) {
	for _, d := range []string{dir, filepath.Join(dir, "profiles"), filepath.Join(dir, "keys")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", d, err)
		}
	}
	s := &Store{dir: dir}
	if b, err := os.ReadFile(s.keyPath()); err == nil {
		raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("stored signing key is corrupt")
		}
		s.priv = ed25519.PrivateKey(raw)
	}
	return s, nil
}

func (s *Store) keyPath() string { return filepath.Join(s.dir, "keys", "signing.key") }

// HasKey reports whether a signing key is available.
func (s *Store) HasKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.priv != nil
}

// PublicKeyB64 returns the base64 Ed25519 public key clients put in
// config_source.pubkey, or "" if no key exists yet.
func (s *Store) PublicKeyB64() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.priv == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(s.priv.Public().(ed25519.PublicKey))
}

// GenerateKey creates a new Ed25519 key, persists it, re-signs every profile, and
// returns the new public key. Existing clients must update their pubkey.
func (s *Store) GenerateKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return s.setKey(priv)
}

// ImportKey installs an operator-provided base64 Ed25519 private key (e.g. from
// `mksign genkey`), persists it, and re-signs every profile.
func (s *Store) ImportKey(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return "", errors.New("not a base64 Ed25519 private key (64 bytes)")
	}
	return s.setKey(ed25519.PrivateKey(raw))
}

func (s *Store) setKey(priv ed25519.PrivateKey) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	enc := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(s.keyPath(), []byte(enc), 0o600); err != nil {
		return "", fmt.Errorf("write signing key: %w", err)
	}
	s.priv = priv
	if err := s.resignAllLocked(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), nil
}

// ProfileView is the editable, JSON-friendly state of one profile: only the
// routing fields a managed feed carries (no proxy credentials, no client-local
// policy like config_source/update — those stay on the client).
type ProfileView struct {
	Name       string   `json:"name"`
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	UDP        bool     `json:"udp"`
	Mode       string   `json:"mode"`
	KillSwitch bool     `json:"killSwitch"`
	Apps       []string `json:"apps"`
	Subnets    []string `json:"subnets"`
}

// feedConfig is exactly what gets served and signed: the routing subset of the
// SocksIt config, with yaml tags matching internal/config so clients parse it.
// dns.fakeip_v4 is deliberately NOT carried — it is a client-side technical
// default (198.18.0.0/15) that operators never need to push.
type feedConfig struct {
	Proxy         feedProxy `yaml:"proxy"`
	Apps          []string  `yaml:"apps"`
	DirectSubnets []string  `yaml:"direct_subnets,omitempty"`
	Mode          string    `yaml:"mode"`
	KillSwitch    bool      `yaml:"kill_switch"`
}
type feedProxy struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	UDP     bool   `yaml:"udp"`
}

func (s *Store) profileDir(name string) string { return filepath.Join(s.dir, "profiles", name) }
func (s *Store) yamlPath(name string) string {
	return filepath.Join(s.profileDir(name), "socksit.yaml")
}
func (s *Store) sigPath(name string) string {
	return filepath.Join(s.profileDir(name), "socksit.yaml.sig")
}

// ListProfiles returns the profile names, sorted.
func (s *Store) ListProfiles() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, _ := os.ReadDir(filepath.Join(s.dir, "profiles"))
	var out []string
	for _, e := range entries {
		if e.IsDir() && validName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// GetProfile loads a profile's editable view.
func (s *Store) GetProfile(name string) (*ProfileView, error) {
	if !validName(name) {
		return nil, errors.New("invalid profile name")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := os.ReadFile(s.yamlPath(name))
	if err != nil {
		return nil, fmt.Errorf("profile %q not found", name)
	}
	c := config.ParseLenient(b)
	return &ProfileView{
		Name:       name,
		Address:    c.Proxy.Address,
		Port:       c.Proxy.Port,
		UDP:        c.UDPEnabled(),
		Mode:       c.Mode,
		KillSwitch: c.KillSwitchOn(),
		Apps:       c.Apps,
		Subnets:    c.DirectSubnets,
	}, nil
}

// SaveProfile validates the view (using the real client schema), writes the
// routing-only feed YAML, and signs it. Requires a signing key.
func (s *Store) SaveProfile(v *ProfileView) error {
	if !validName(v.Name) {
		return errors.New("profile name must be lowercase letters, digits or hyphens (max 40)")
	}
	c := v.toConfig()
	if err := c.Validate(); err != nil {
		return err
	}
	body, err := yaml.Marshal(feedFromConfig(c))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.priv == nil {
		return errors.New("no signing key yet — generate or import one first")
	}
	if err := os.MkdirAll(s.profileDir(v.Name), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(s.yamlPath(v.Name), body, 0o600); err != nil {
		return err
	}
	return os.WriteFile(s.sigPath(v.Name), s.signLocked(body), 0o600)
}

// DeleteProfile removes a profile and its files.
func (s *Store) DeleteProfile(name string) error {
	if !validName(name) {
		return errors.New("invalid profile name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.RemoveAll(s.profileDir(name))
}

// ServedBytes returns the stored YAML and signature for the public endpoint.
func (s *Store) ServedBytes(name string) (yamlBytes, sig []byte, err error) {
	if !validName(name) {
		return nil, nil, errors.New("invalid profile name")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	yamlBytes, err = os.ReadFile(s.yamlPath(name))
	if err != nil {
		return nil, nil, err
	}
	sig, _ = os.ReadFile(s.sigPath(name)) // may be absent if unsigned; caller handles
	return yamlBytes, sig, nil
}

// toConfig builds a full client config from the view so it can be validated with
// the exact same rules the client applies.
func (v *ProfileView) toConfig() *config.Config {
	c := config.Default()
	c.Proxy.Address = strings.TrimSpace(v.Address)
	if v.Port > 0 {
		c.Proxy.Port = v.Port
	}
	udp, ks := v.UDP, v.KillSwitch
	c.Proxy.UDP = &udp
	c.KillSwitch = &ks
	c.Mode = v.Mode
	c.Apps = cleanList(v.Apps)
	c.DirectSubnets = cleanList(v.Subnets)
	return c
}

func feedFromConfig(c *config.Config) feedConfig {
	return feedConfig{
		Proxy:         feedProxy{Address: c.Proxy.Address, Port: c.Proxy.Port, UDP: c.UDPEnabled()},
		Apps:          c.Apps,
		DirectSubnets: c.DirectSubnets,
		Mode:          c.Mode,
		KillSwitch:    c.KillSwitchOn(),
	}
}

// signLocked returns the base64 Ed25519 signature over data. Caller holds s.mu.
func (s *Store) signLocked(data []byte) []byte {
	sig := ed25519.Sign(s.priv, data)
	return []byte(base64.StdEncoding.EncodeToString(sig))
}

// resignAllLocked re-signs every profile with the current key. Caller holds s.mu.
func (s *Store) resignAllLocked() error {
	entries, _ := os.ReadDir(filepath.Join(s.dir, "profiles"))
	for _, e := range entries {
		if !e.IsDir() || !validName(e.Name()) {
			continue
		}
		body, err := os.ReadFile(s.yamlPath(e.Name()))
		if err != nil {
			continue
		}
		if err := os.WriteFile(s.sigPath(e.Name()), s.signLocked(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func cleanList(in []string) []string {
	var out []string
	for _, x := range in {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
