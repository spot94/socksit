package updates

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func serveManifest(t *testing.T, manifest, sig []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifest) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(sig)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func withKey(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	old := PublicKeyB64
	PublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { PublicKeyB64 = old })
}

func TestCheckSignedManifest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	manifest := []byte(`{"schema":1,"product":"socksit","channel":"stable","version":"0.2.0","notes_en":"notes","notes_ru":"заметки"}`)
	srv := serveManifest(t, manifest, ed25519.Sign(priv, manifest))
	withKey(t, pub)

	res, err := Check(context.Background(), srv.Client(), srv.URL, "stable", "0.1.0")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !res.HasUpdate || res.Available != "0.2.0" || res.NotesRU != "заметки" {
		t.Fatalf("expected update to 0.2.0 with notes, got %+v", res)
	}
	res2, err := Check(context.Background(), srv.Client(), srv.URL, "stable", "0.2.0")
	if err != nil {
		t.Fatalf("check(same): %v", err)
	}
	if res2.HasUpdate {
		t.Fatalf("expected no update at the same version, got %+v", res2)
	}
}

func TestCheckBadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)   // trusted key
	_, priv2, _ := ed25519.GenerateKey(nil) // a DIFFERENT key signs the manifest
	manifest := []byte(`{"schema":1,"product":"socksit","version":"0.2.0"}`)
	srv := serveManifest(t, manifest, ed25519.Sign(priv2, manifest))
	withKey(t, pub)

	if _, err := Check(context.Background(), srv.Client(), srv.URL, "stable", "0.1.0"); err == nil {
		t.Fatal("expected signature verification to fail")
	}
}

func TestCheckNoKey(t *testing.T) {
	old := PublicKeyB64
	PublicKeyB64 = ""
	t.Cleanup(func() { PublicKeyB64 = old })
	if _, err := Check(context.Background(), http.DefaultClient, "https://example.invalid", "stable", "0.1.0"); err == nil {
		t.Fatal("expected error when no trusted key is configured")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.2.0", "0.1.0", 1},
		{"0.1.0", "0.2.0", -1},
		{"1.0.0", "1.0.0", 0},
		{"v0.2.0", "0.1.9", 1},
		{"0.2.0-beta", "0.2.0", 0},
		{"0.10.0", "0.9.0", 1},
		{"0.1.1b", "0.1.0", 1},    // non-numeric suffix still compares by 0.1.1
		{"0.1.1b", "0.1.1", 0},    // "1b" -> 1
		{"0.1.2", "0.1.0-dev", 1}, // real release vs the unbaked default
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
