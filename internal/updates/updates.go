// Package updates checks a signed release manifest and reports whether a newer
// version is available. Trust is anchored on an Ed25519 signature over the exact
// manifest bytes (public key compiled into the binary), so the endpoint and
// transport are untrusted — a hostile server/CDN can block or serve stale data
// but cannot forge an update. See docs/update-design.md. (Phase 1: check only;
// downloading/applying is a later phase.)
package updates

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// PublicKeyB64 is the base64 (std) Ed25519 public key trusted to sign manifests.
// Set at build time: -ldflags "-X socksit/internal/updates.PublicKeyB64=<b64>".
// bakedKeys holds additional compiled-in keys (for rotation).
var (
	PublicKeyB64 string
	// bakedKeys are the compiled-in trusted signing keys (base64 Ed25519). The
	// matching private key lives only in the CI secret SOCKSIT_SIGN_KEY. Add a new
	// key here before rotating, then retire the old one in a later release.
	bakedKeys = []string{
		"gEC+gNU8IOl9/q26xF3eCRVDwcN2FpWPpdboTfvp/hA=", // spot94/socksit release key
	}
)

const schemaVersion = 1

// Manifest is the release descriptor served at <endpoint>/<manifest name>.
type Manifest struct {
	Schema       int    `json:"schema"`
	Product      string `json:"product"`
	Channel      string `json:"channel"`
	Version      string `json:"version"`
	Released     string `json:"released"`
	MinSupported string `json:"min_supported"`
	NotesEN      string `json:"notes_en"`
	NotesRU      string `json:"notes_ru"`
	App          struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"app"`
	Engine struct {
		Version string `json:"version"`
		URL     string `json:"url"`
		SHA256  string `json:"sha256"`
	} `json:"engine"`
}

// Result is the JSON-friendly outcome of a check (for IPC/UI).
type Result struct {
	Current   string `json:"current"`
	Available string `json:"available"`
	NotesEN   string `json:"notesEn"`
	NotesRU   string `json:"notesRu"`
	HasUpdate bool   `json:"hasUpdate"`
	Error     string `json:"error"`
}

// Fetch downloads and verifies the manifest (Ed25519 signature + schema/product),
// returning it. client is prepared by the caller (proxy/transport); endpoint is
// the release base URL.
func Fetch(ctx context.Context, client *http.Client, endpoint, channel string) (Manifest, error) {
	var m Manifest
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if endpoint == "" {
		return m, errors.New("update endpoint not configured")
	}
	keys := trustedKeys()
	if len(keys) == 0 {
		return m, errors.New("no trusted update key is compiled into this build")
	}
	base := endpoint + "/" + manifestName(channel)
	body, err := get(ctx, client, base)
	if err != nil {
		return m, err
	}
	sigRaw, err := get(ctx, client, base+".sig")
	if err != nil {
		return m, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return m, fmt.Errorf("bad signature encoding: %w", err)
	}
	if !verify(keys, body, sig) {
		return m, errors.New("manifest signature is not valid")
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return m, fmt.Errorf("bad manifest: %w", err)
	}
	if m.Schema != schemaVersion {
		return m, fmt.Errorf("unsupported manifest schema %d", m.Schema)
	}
	if m.Product != "socksit" {
		return m, fmt.Errorf("manifest is for %q, not socksit", m.Product)
	}
	return m, nil
}

// Check fetches+verifies the manifest and compares versions.
func Check(ctx context.Context, client *http.Client, endpoint, channel, current string) (Result, error) {
	res := Result{Current: current}
	m, err := Fetch(ctx, client, endpoint, channel)
	if err != nil {
		return res, err
	}
	res.Available = m.Version
	res.NotesEN, res.NotesRU = m.NotesEN, m.NotesRU
	res.HasUpdate = compareVersions(m.Version, current) > 0
	return res, nil
}

// Newer reports whether version a is strictly newer than b.
func Newer(a, b string) bool { return compareVersions(a, b) > 0 }

// Verify checks a detached base64 Ed25519 signature over body against the baked
// trusted keys (same keys as the update manifest). Used for the managed-config
// feed. Returns an error if no key is compiled in or the signature is invalid.
func Verify(body []byte, sigB64 string) error {
	keys := trustedKeys()
	if len(keys) == 0 {
		return errors.New("no trusted key is compiled into this build")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	if !verify(keys, body, sig) {
		return errors.New("signature is not valid")
	}
	return nil
}

// DownloadVerified downloads url and checks its SHA-256 against the (signed-
// manifest) expected hex digest. The bytes are safe to execute only if err is nil.
func DownloadVerified(ctx context.Context, client *http.Client, url, sha256hex string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20)) // 256 MiB cap
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(sha256hex)) {
		return nil, errors.New("downloaded file does not match the signed checksum")
	}
	return b, nil
}

func trustedKeys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	for _, b := range append([]string{PublicKeyB64}, bakedKeys...) {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys
}

func verify(keys []ed25519.PublicKey, msg, sig []byte) bool {
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}

func manifestName(channel string) string {
	channel = strings.TrimSpace(channel)
	if channel == "" || channel == "stable" {
		return "manifest.json"
	}
	return "manifest-" + channel + ".json"
}

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap for manifest/sig
}

// compareVersions compares dotted numeric versions (leading 'v' and any
// pre-release/build suffix ignored). Returns -1, 0 or 1.
func compareVersions(a, b string) int {
	pa, pb := splitVer(a), splitVer(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVer(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// Use only the leading digits of each component, so a non-numeric suffix
		// ("1b" -> 1, "beta" -> 0) doesn't silently collapse the whole version.
		j := 0
		for j < len(p) && p[j] >= '0' && p[j] <= '9' {
			j++
		}
		n, _ := strconv.Atoi(p[:j])
		out = append(out, n)
	}
	return out
}
