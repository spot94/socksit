// Command configserver hosts signed SocksIt config feeds and an authenticated
// admin UI to edit them and manage the Ed25519 signing key. It is meant to run in
// a container behind a reverse proxy (which terminates TLS). See
// docs/configserver.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"socksit/internal/configserver"
)

func main() {
	addr := env("LISTEN", ":8080")
	dataDir := env("DATA_DIR", "data")
	idle := parseDuration(env("IDLE_TIMEOUT", "30m"), 30*time.Minute)
	secure := truthy(env("SECURE_COOKIES", ""))
	adminPw := os.Getenv("ADMIN_PASSWORD")

	store, err := configserver.Open(dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	auth, err := configserver.NewAuth(dataDir, secure, idle, adminPw)
	if err != nil {
		log.Fatalf("init auth: %v", err)
	}
	audit := configserver.NewAudit(dataDir)
	ldap, err := configserver.NewLDAP(dataDir)
	if err != nil {
		log.Fatalf("init ldap: %v", err)
	}
	srv := configserver.New(store, auth, audit, ldap)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("configserver listening on %s (data=%s, secure-cookies=%v)", addr, dataDir, secure)
	log.Printf("admin configured: %v; signing key present: %v", auth.HasAdmin(), store.HasKey())
	if pub := store.PublicKeyB64(); pub != "" {
		log.Printf("signing public key (config_source.pubkey): %s", pub)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	case <-stop:
		log.Print("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func parseDuration(v string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}
