// Package enginedl downloads the sing-box engine on demand so a bare socksit.exe
// is self-sufficient (no need to ship sing-box.exe alongside). The download is
// verified against a pinned SHA-256 compiled into the binary, so an untrusted
// server/CDN cannot make us run a tampered engine. It tries the official sing-box
// release first, then the SocksIt release as a fallback (same binary, same hash).
package enginedl

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Version and SHA256 must match assets/bin/VERSION and the shipped engine. Bump
// both together when updating the pinned sing-box.
const (
	Version = "1.13.14"
	SHA256  = "db0d779948214cf761011d154c3a5da36df20394fa01a9fc798f1dc39fe9d183"

	OfficialZipURL = "https://github.com/SagerNet/sing-box/releases/download/v" + Version +
		"/sing-box-" + Version + "-windows-amd64.zip"
	FallbackExeURL = "https://github.com/spot94/socksit/releases/latest/download/sing-box.exe"

	maxRead = 120 << 20 // 120 MiB cap (engine ~45 MiB, zip ~20 MiB)
)

// Ensure writes a verified sing-box.exe to dest. If dest already exists and its
// hash matches, it does nothing. Otherwise it downloads (official first, then the
// SocksIt fallback) and verifies before writing.
func Ensure(ctx context.Context, client *http.Client, dest string) error {
	if verifyFile(dest) == nil {
		return nil // already present and correct
	}
	if client == nil {
		client = http.DefaultClient
	}
	var errs []string

	if b, err := download(ctx, client, OfficialZipURL); err != nil {
		errs = append(errs, "official: "+err.Error())
	} else if exe, err := extractExe(b); err != nil {
		errs = append(errs, "official zip: "+err.Error())
	} else if err := verifyBytes(exe); err != nil {
		errs = append(errs, "official: "+err.Error())
	} else {
		return write(dest, exe)
	}

	if b, err := download(ctx, client, FallbackExeURL); err != nil {
		errs = append(errs, "fallback: "+err.Error())
	} else if err := verifyBytes(b); err != nil {
		errs = append(errs, "fallback: "+err.Error())
	} else {
		return write(dest, b)
	}

	return fmt.Errorf("could not obtain a verified sing-box.exe %s: %s", Version, strings.Join(errs, "; "))
}

func verifyFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return verifyBytes(b)
}

func verifyBytes(b []byte) error {
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != SHA256 {
		return errors.New("sha256 mismatch")
	}
	return nil
}

func download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
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
	return io.ReadAll(io.LimitReader(resp.Body, maxRead))
}

func extractExe(zipBytes []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if strings.EqualFold(filepath.Base(f.Name), "sing-box.exe") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxRead))
		}
	}
	return nil, errors.New("sing-box.exe not found in archive")
}

func write(dest string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, b, 0o755)
}
