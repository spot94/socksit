// Command mksign is a build-time helper for the update channel. It has two modes:
//
//	mksign genkey
//	    Prints a fresh Ed25519 keypair (PUB=… / PRIV=…, base64). The PUB goes into
//	    internal/updates (compiled-in trust); the PRIV goes into the GitHub Actions
//	    secret SOCKSIT_SIGN_KEY and is never committed.
//
//	mksign build -app socksit.exe -engine sing-box.exe -version X.Y.Z \
//	             -base-url https://github.com/<owner>/<repo>/releases/download/vX.Y.Z [flags]
//	    Builds manifest.json (with sha256 of the artifacts) and signs it with the
//	    private key from $SOCKSIT_SIGN_KEY, writing manifest.json + manifest.json.sig.
//
// See docs/update-design.md.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: mksign genkey | mksign build [flags]")
	}
	switch os.Args[1] {
	case "genkey":
		genkey()
	case "build":
		build(os.Args[2:])
	default:
		fail("unknown subcommand %q", os.Args[1])
	}
}

func genkey() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	fmt.Println("PUB=" + base64.StdEncoding.EncodeToString(pub))
	fmt.Println("PRIV=" + base64.StdEncoding.EncodeToString(priv))
}

func build(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	app := fs.String("app", "", "path to socksit.exe (required)")
	engine := fs.String("engine", "", "path to sing-box.exe")
	version := fs.String("version", "", "app version, e.g. 0.2.0 (required)")
	channel := fs.String("channel", "stable", "release channel")
	baseURL := fs.String("base-url", "", "release asset download base URL (required)")
	notesEN := fs.String("notes-en", "", "release notes (English)")
	notesRU := fs.String("notes-ru", "", "release notes (Russian)")
	engineVer := fs.String("engine-version", "", "bundled engine version")
	minSup := fs.String("min-supported", "", "minimum client version that can self-update")
	out := fs.String("out", ".", "output directory")
	_ = fs.Parse(args)

	if *app == "" || *version == "" || *baseURL == "" {
		fail("-app, -version and -base-url are required")
	}
	keyB64 := strings.TrimSpace(os.Getenv("SOCKSIT_SIGN_KEY"))
	if keyB64 == "" {
		fail("SOCKSIT_SIGN_KEY env is empty (base64 Ed25519 private key)")
	}
	privRaw, err := base64.StdEncoding.DecodeString(keyB64)
	must(err)
	if len(privRaw) != ed25519.PrivateKeySize {
		fail("SOCKSIT_SIGN_KEY must decode to %d bytes, got %d", ed25519.PrivateKeySize, len(privRaw))
	}
	priv := ed25519.PrivateKey(privRaw)

	base := strings.TrimRight(*baseURL, "/")
	m := map[string]any{
		"schema":        1,
		"product":       "socksit",
		"channel":       *channel,
		"version":       *version,
		"released":      time.Now().UTC().Format(time.RFC3339),
		"min_supported": *minSup,
		"notes_en":      *notesEN,
		"notes_ru":      *notesRU,
		"app": map[string]any{
			"url":    base + "/socksit.exe",
			"sha256": sha256file(*app),
			"size":   size(*app),
		},
	}
	if *engine != "" {
		m["engine"] = map[string]any{
			"version": *engineVer,
			"url":     base + "/sing-box.exe",
			"sha256":  sha256file(*engine),
		}
	}
	body, err := json.MarshalIndent(m, "", "  ")
	must(err)
	body = append(body, '\n')

	sig := ed25519.Sign(priv, body) // sign the exact bytes we write

	must(os.MkdirAll(*out, 0o755))
	must(os.WriteFile(filepath.Join(*out, "manifest.json"), body, 0o644))
	must(os.WriteFile(filepath.Join(*out, "manifest.json.sig"),
		[]byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644))
	fmt.Printf("wrote manifest.json (+ .sig) for v%s to %s\n", *version, *out)
}

func sha256file(path string) string {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	must(err)
	return hex.EncodeToString(h.Sum(nil))
}

func size(path string) int64 {
	fi, err := os.Stat(path)
	must(err)
	return fi.Size()
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "mksign: "+format+"\n", a...)
	os.Exit(1)
}
