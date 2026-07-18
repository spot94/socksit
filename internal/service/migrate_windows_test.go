//go:build windows

package service

import (
	"testing"

	"socksit/internal/config"
)

func TestApplyMigrate(t *testing.T) {
	local := config.Default()
	local.Proxy.Address = "10.0.0.1"
	local.ConfigSource.URL = "http://old/configs/x/socksit.yaml"
	local.ConfigSource.PubKey = "OLDKEY"

	c := config.Default()
	c.ConfigSource = local.ConfigSource
	c.Update = local.Update
	applyMigrate(c, migrateInstr{ConfigURL: "http://new/x/socksit.yaml", UpdateEndpoint: "http://new/rel", UpdateMode: "auto", PubKey: "NEWKEY"}, local)
	if c.ConfigSource.URL != "http://new/x/socksit.yaml" {
		t.Errorf("config url should migrate, got %q", c.ConfigSource.URL)
	}
	if c.Update.Endpoint != "http://new/rel" || c.Update.Mode != "auto" {
		t.Errorf("update.* should migrate, got %+v", c.Update)
	}
	if c.ConfigSource.PubKey != "OLDKEY" {
		t.Errorf("pubkey must NOT auto-apply, got %q", c.ConfigSource.PubKey)
	}
	if c.ConfigSource.PendingPubKey != "NEWKEY" {
		t.Errorf("pubkey rotation should be pending, got %q", c.ConfigSource.PendingPubKey)
	}

	// A declined key is not re-proposed.
	local.ConfigSource.DeclinedPubKey = "NEWKEY"
	c2 := config.Default()
	c2.ConfigSource = local.ConfigSource
	applyMigrate(c2, migrateInstr{PubKey: "NEWKEY"}, local)
	if c2.ConfigSource.PendingPubKey != "" {
		t.Errorf("declined key must not re-pend, got %q", c2.ConfigSource.PendingPubKey)
	}
}

func TestMigrateURLFrom(t *testing.T) {
	if got := migrateURLFrom("https://h/configs/x/socksit.yaml"); got != "https://h/configs/x/migrate.yaml" {
		t.Errorf("migrateURLFrom: got %q", got)
	}
}
