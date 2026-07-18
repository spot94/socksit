//go:build windows

// Package secret encrypts SocksIt secrets (the SOCKS5 credentials) at rest with
// Windows DPAPI. The LocalSystem service is the sole owner of this crypto — the
// user-session GUI never touches ciphertext; it sends plaintext over the secured
// pipe and the service encrypts. An app-specific entropy adds defense in depth.
// Machine-local scope is deliberately NOT used (any local process could read it).
// See plan U7/KTD7.
package secret

import (
	"fmt"
	"os"

	"github.com/billgraziano/dpapi"
)

// Store performs DPAPI encrypt/decrypt bound to the current account (SYSTEM in
// production), optionally salted with entropy.
type Store struct{ entropy string }

// New returns a Store. entropy may be empty (no extra salt).
func New(entropy string) *Store { return &Store{entropy: entropy} }

// Encrypt returns a base64 DPAPI blob for plain.
func (s *Store) Encrypt(plain string) (string, error) {
	var out string
	var err error
	if s.entropy == "" {
		out, err = dpapi.Encrypt(plain)
	} else {
		out, err = dpapi.EncryptEntropy(plain, s.entropy)
	}
	if err != nil {
		return "", fmt.Errorf("dpapi encrypt: %w", err)
	}
	return out, nil
}

// Decrypt recovers the plaintext from a base64 DPAPI blob.
func (s *Store) Decrypt(enc string) (string, error) {
	var out string
	var err error
	if s.entropy == "" {
		out, err = dpapi.Decrypt(enc)
	} else {
		out, err = dpapi.DecryptEntropy(enc, s.entropy)
	}
	if err != nil {
		return "", fmt.Errorf("dpapi decrypt: %w", err)
	}
	return out, nil
}

// SaveTo encrypts plain and writes the blob to path (0600). TODO(U8/hardening):
// tighten the on-disk ACL to SYSTEM+Administrators via a Windows security
// descriptor; os file mode is coarse on Windows.
func (s *Store) SaveTo(path, plain string) error {
	enc, err := s.Encrypt(plain)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return fmt.Errorf("write secret blob: %w", err)
	}
	return nil
}

// LoadFrom reads and decrypts the blob at path.
func (s *Store) LoadFrom(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret blob: %w", err)
	}
	return s.Decrypt(string(data))
}
