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
	"net/url"
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
	UDP        string   `json:"udp"` // "on" | "off" | "user"
	Mode       string   `json:"mode"`
	KillSwitch string   `json:"killSwitch"` // "on" | "off" | "user"
	Apps       []string `json:"apps"`
	Subnets    []string `json:"subnets"`
	// Migrate optionally proposes channel changes to clients (server moved, key
	// rotation) via the signed migrate.yaml sidecar. nil/empty = no migration.
	Migrate *MigrateView `json:"migrate,omitempty"`
}

// MigrateView is the operator-authored channel migration for a profile. Clients
// apply configUrl and the update.* fields automatically (still guarded by the
// pinned key / the baked update key); pubkey (trust-root rotation) is applied
// only after explicit local admin approval.
type MigrateView struct {
	ConfigURL      string `json:"configUrl"`
	Merge          string `json:"merge"` // "" unchanged | replace | override
	PubKey         string `json:"pubkey"`
	UpdateEndpoint string `json:"updateEndpoint"`
	UpdateChannel  string `json:"updateChannel"`
	UpdateMode     string `json:"updateMode"`
}

func (m *MigrateView) empty() bool {
	return m == nil || (strings.TrimSpace(m.ConfigURL) == "" && strings.TrimSpace(m.Merge) == "" && strings.TrimSpace(m.PubKey) == "" &&
		strings.TrimSpace(m.UpdateEndpoint) == "" && strings.TrimSpace(m.UpdateChannel) == "" && strings.TrimSpace(m.UpdateMode) == "")
}

// feedMigrate is the signed migrate.yaml served to clients.
type feedMigrate struct {
	ConfigURL      string `yaml:"config_url,omitempty"`
	Merge          string `yaml:"merge,omitempty"`
	PubKey         string `yaml:"pubkey,omitempty"`
	UpdateEndpoint string `yaml:"update_endpoint,omitempty"`
	UpdateChannel  string `yaml:"update_channel,omitempty"`
	UpdateMode     string `yaml:"update_mode,omitempty"`
}

// feedConfig is exactly what gets served and signed: the routing subset of the
// SocksIt config, with yaml tags matching internal/config so clients parse it.
// dns.fakeip_v4 is deliberately NOT carried — it is a client-side technical
// default (198.18.0.0/15) that operators never need to push.
type feedConfig struct {
	Proxy feedProxy `yaml:"proxy"`
	Apps  []string  `yaml:"apps"`
	// direct_subnets is emitted even when empty (no omitempty): a client in
	// override mode distinguishes "present but empty" (clear the channel's subnets)
	// from "absent" (keep them). Same as apps, so clearing the field on the server
	// actually clears the managed subnets on clients.
	DirectSubnets []string `yaml:"direct_subnets"`
	Mode          string   `yaml:"mode"`
	// kill_switch / udp are tri-state: present (true/false) = server forces it and
	// the client locks the toggle; absent (nil, via omitempty) = user-defined.
	KillSwitch *bool `yaml:"kill_switch,omitempty"`
}
type feedProxy struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	UDP     *bool  `yaml:"udp,omitempty"`
}

func (s *Store) profileDir(name string) string { return filepath.Join(s.dir, "profiles", name) }
func (s *Store) migrateYamlPath(name string) string {
	return filepath.Join(s.profileDir(name), "migrate.yaml")
}
func (s *Store) migrateSigPath(name string) string {
	return filepath.Join(s.profileDir(name), "migrate.yaml.sig")
}
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
	pv := &ProfileView{
		Name:       name,
		Address:    c.Proxy.Address,
		Port:       c.Proxy.Port,
		UDP:        triState(c.Proxy.UDP),
		Mode:       c.Mode,
		KillSwitch: triState(c.KillSwitch),
		Apps:       c.Apps,
		Subnets:    c.DirectSubnets,
	}
	if mb, err := os.ReadFile(s.migrateYamlPath(name)); err == nil {
		var fm feedMigrate
		if yaml.Unmarshal(mb, &fm) == nil {
			pv.Migrate = &MigrateView{ConfigURL: fm.ConfigURL, Merge: fm.Merge, PubKey: fm.PubKey,
				UpdateEndpoint: fm.UpdateEndpoint, UpdateChannel: fm.UpdateChannel, UpdateMode: fm.UpdateMode}
		}
	}
	return pv, nil
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
	feed := feedFromConfig(c)
	feed.KillSwitch = triBool(v.KillSwitch)
	feed.Proxy.UDP = triBool(v.UDP)
	body, err := yaml.Marshal(feed)
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
	if err := os.WriteFile(s.sigPath(v.Name), s.signLocked(body), 0o600); err != nil {
		return err
	}
	// Migration sidecar: write + sign when set, remove when cleared.
	if v.Migrate.empty() {
		_ = os.Remove(s.migrateYamlPath(v.Name))
		_ = os.Remove(s.migrateSigPath(v.Name))
		return nil
	}
	if err := validateMigrate(v.Migrate); err != nil {
		return err
	}
	mb, err := yaml.Marshal(feedMigrate{
		ConfigURL:      strings.TrimSpace(v.Migrate.ConfigURL),
		Merge:          strings.TrimSpace(v.Migrate.Merge),
		PubKey:         strings.TrimSpace(v.Migrate.PubKey),
		UpdateEndpoint: strings.TrimSpace(v.Migrate.UpdateEndpoint),
		UpdateChannel:  strings.TrimSpace(v.Migrate.UpdateChannel),
		UpdateMode:     strings.TrimSpace(v.Migrate.UpdateMode),
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.migrateYamlPath(v.Name), mb, 0o600); err != nil {
		return err
	}
	return os.WriteFile(s.migrateSigPath(v.Name), s.signLocked(mb), 0o600)
}

// validateMigrate checks operator-authored migration fields.
func validateMigrate(m *MigrateView) error {
	for field, u := range map[string]string{"configUrl": m.ConfigURL, "updateEndpoint": m.UpdateEndpoint} {
		if u = strings.TrimSpace(u); u != "" {
			if pu, err := url.Parse(u); err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
				return fmt.Errorf("migrate.%s must be an http(s) URL", field)
			}
		}
	}
	if pk := strings.TrimSpace(m.PubKey); pk != "" {
		if raw, err := base64.StdEncoding.DecodeString(pk); err != nil || len(raw) != 32 {
			return errors.New("migrate.pubkey must be a base64 32-byte Ed25519 public key")
		}
	}
	switch strings.TrimSpace(m.UpdateMode) {
	case "", "off", "notify", "auto":
	default:
		return errors.New("migrate.updateMode must be off, notify or auto")
	}
	switch strings.TrimSpace(m.Merge) {
	case "", "replace", "override":
	default:
		return errors.New("migrate.merge must be replace or override")
	}
	return nil
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
	// kill_switch / udp are tri-state and handled at feed-emit time; leave the
	// validation config at its defaults.
	c.Mode = v.Mode
	c.Apps = cleanList(v.Apps)
	c.DirectSubnets = cleanList(v.Subnets)
	return c
}

// triBool maps a tri-state ("on"/"off"/anything-else) to a feed value: on->true,
// off->false, user-defined->nil (omitted from the feed).
func triBool(s string) *bool {
	switch strings.TrimSpace(s) {
	case "on":
		t := true
		return &t
	case "off":
		f := false
		return &f
	}
	return nil
}

// triState is the inverse: nil->"user", true->"on", false->"off".
func triState(b *bool) string {
	if b == nil {
		return "user"
	}
	if *b {
		return "on"
	}
	return "off"
}

func feedFromConfig(c *config.Config) feedConfig {
	return feedConfig{
		Proxy:         feedProxy{Address: c.Proxy.Address, Port: c.Proxy.Port}, // UDP set by caller (tri-state)
		Apps:          c.Apps,
		DirectSubnets: c.DirectSubnets,
		Mode:          c.Mode,
		// KillSwitch set by caller (tri-state)
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
		if mb, err := os.ReadFile(s.migrateYamlPath(e.Name())); err == nil {
			if err := os.WriteFile(s.migrateSigPath(e.Name()), s.signLocked(mb), 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// ServedMigrate returns the stored migrate.yaml and signature for the public
// endpoint, or an error if the profile has no migration set.
func (s *Store) ServedMigrate(name string) (yamlBytes, sig []byte, err error) {
	if !validName(name) {
		return nil, nil, errors.New("invalid profile name")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	yamlBytes, err = os.ReadFile(s.migrateYamlPath(name))
	if err != nil {
		return nil, nil, err
	}
	sig, _ = os.ReadFile(s.migrateSigPath(name))
	return yamlBytes, sig, nil
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
