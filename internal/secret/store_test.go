//go:build windows

package secret

import (
	"path/filepath"
	"testing"
)

func TestRoundTripWithEntropy(t *testing.T) {
	s := New("socksit-app-entropy-v1")
	const secret = "sup3r-s3cret-proxy-pass"
	enc, err := s.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc == secret || enc == "" {
		t.Fatal("ciphertext should differ from plaintext and be non-empty")
	}
	got, err := s.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != secret {
		t.Errorf("round-trip mismatch: got %q, want %q", got, secret)
	}
}

func TestWrongEntropyFails(t *testing.T) {
	enc, err := New("entropy-A").Encrypt("hello")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := New("entropy-B").Decrypt(enc); err == nil {
		t.Error("decrypt with a different entropy should fail")
	}
}

func TestRoundTripNoEntropy(t *testing.T) {
	s := New("")
	enc, err := s.Encrypt("plain-secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := s.Decrypt(enc)
	if err != nil || got != "plain-secret" {
		t.Errorf("no-entropy round-trip failed: got %q err %v", got, err)
	}
}

func TestSaveLoadFile(t *testing.T) {
	s := New("file-entropy")
	path := filepath.Join(t.TempDir(), "creds.dpapi")
	if err := s.SaveTo(path, "file-secret"); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	got, err := s.LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if got != "file-secret" {
		t.Errorf("file round-trip mismatch: got %q", got)
	}
}
