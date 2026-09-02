package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"socksit/internal/updates"
)

// verify checks a PUBLISHED release the way an installed client does: it fetches
// the manifest over the network and validates its signature against the public
// keys baked into this build.
//
// Cutting a release is the one moment where the signing key and the baked key
// can silently drift apart, and the failure mode is invisible — clients simply
// go quiet and never see the update, with nothing in anyone's logs. Signing an
// artifact after publishing has the same effect: the manifest carries SHA-256
// hashes, so a file replaced afterwards no longer matches and every download is
// rejected. This command is the check for both.
func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "release base URL, e.g. https://github.com/<owner>/<repo>/releases/latest/download (required)")
	channel := fs.String("channel", "stable", "release channel")
	proxy := fs.String("proxy", "", "proxy for the fetch, e.g. socks5h://127.0.0.1:1080 (the release host is not reachable directly everywhere)")
	current := fs.String("current", "0.0.0", "pretend to be a client running this version")
	_ = fs.Parse(args)
	if *endpoint == "" {
		fail("-endpoint is required")
	}

	client := &http.Client{Timeout: 60 * time.Second}
	if *proxy != "" {
		pu, err := url.Parse(*proxy)
		must(err)
		client.Transport = &http.Transport{Proxy: http.ProxyURL(pu)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	m, err := updates.Fetch(ctx, client, *endpoint, *channel)
	if err != nil {
		fail("manifest rejected: %v", err) // signature, schema, product or transport
	}
	fmt.Printf("manifest verified: %s %s (channel %s, released %s)\n", m.Product, m.Version, m.Channel, m.Released)
	fmt.Printf("  app  %s\n       sha256 %s\n", m.App.URL, m.App.SHA256)
	if m.MSI.URL != "" {
		fmt.Printf("  msi  %s\n       sha256 %s\n", m.MSI.URL, m.MSI.SHA256)
	} else {
		fmt.Println("  msi  (absent — clients keep using the exe-swap update path)")
	}

	res, err := updates.Check(ctx, client, *endpoint, *channel, *current)
	if err != nil {
		fail("check failed: %v", err)
	}
	fmt.Printf("  a client on %s sees: update=%v -> %q\n", *current, res.HasUpdate, res.Available)
}
