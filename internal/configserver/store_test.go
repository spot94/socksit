package configserver

import (
	"testing"

	"socksit/internal/config"
	"socksit/internal/updates"
)

func TestValidName(t *testing.T) {
	ok := []string{"team-a", "a", "team1", "0-9-x"}
	bad := []string{"", "-lead", "UPPER", "has space", "dot.name", "slash/name", "toolongnametoolongnametoolongnametoolongname"}
	for _, n := range ok {
		if !validName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range bad {
		if validName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func sampleProfile(name string) *ProfileView {
	return &ProfileView{Name: name, Address: "10.0.0.1", Port: 1080, Mode: "allowlist",
		UDP: "on", KillSwitch: "on", Apps: []string{"chrome.exe", "Telegram.exe"}}
}

func TestStoreSignRoundtrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Saving before a key exists must fail.
	if err := s.SaveProfile(sampleProfile("team-a")); err == nil {
		t.Fatal("expected an error saving with no signing key")
	}
	pub, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveProfile(sampleProfile("team-a")); err != nil {
		t.Fatalf("save: %v", err)
	}

	body, sig, err := s.ServedBytes("team-a")
	if err != nil {
		t.Fatalf("served: %v", err)
	}
	// The served feed must verify through the CLIENT's real verifier and parse
	// under the client's strict schema.
	if err := updates.VerifyWithKeyB64(body, string(sig), pub); err != nil {
		t.Fatalf("client signature verify failed: %v", err)
	}
	c, err := config.Parse(body)
	if err != nil {
		t.Fatalf("client parse failed: %v", err)
	}
	if c.Proxy.Address != "10.0.0.1" || len(c.Apps) != 2 || c.Mode != "allowlist" {
		t.Fatalf("parsed wrong: %+v apps=%v", c.Proxy, c.Apps)
	}
	// The feed must never carry proxy credentials.
	if c.Proxy.Username != "" || c.Proxy.Password != "" {
		t.Fatal("served config must not contain credentials")
	}

	// Invalid config is rejected by the shared validator.
	if err := s.SaveProfile(&ProfileView{Name: "bad", Address: "", Port: 1080, Mode: "allowlist"}); err == nil {
		t.Fatal("empty proxy.address should fail validation")
	}

	// Rotating the key re-signs every profile; the old key must stop verifying.
	pub2, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	body2, sig2, _ := s.ServedBytes("team-a")
	if err := updates.VerifyWithKeyB64(body2, string(sig2), pub2); err != nil {
		t.Fatalf("verify after rotate with new key: %v", err)
	}
	if err := updates.VerifyWithKeyB64(body2, string(sig2), pub); err == nil {
		t.Fatal("old key must not verify after rotation")
	}
}

func TestImportKeyMatchesMksign(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A generated key can be exported and re-imported to the same public key.
	pub, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.PublicKeyB64(); got != pub {
		t.Fatalf("public key mismatch: %q vs %q", got, pub)
	}
	if _, err := s.ImportKey("not-base64!!"); err == nil {
		t.Fatal("garbage key should be rejected")
	}
}

func TestMigrateSidecarRoundtrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := sampleProfile("team-a")
	p.Migrate = &MigrateView{ConfigURL: "https://new/configs/team-a/socksit.yaml", UpdateMode: "notify", PubKey: pub}
	if err := s.SaveProfile(p); err != nil {
		t.Fatalf("save with migrate: %v", err)
	}
	body, sig, err := s.ServedMigrate("team-a")
	if err != nil {
		t.Fatalf("served migrate: %v", err)
	}
	if err := updates.VerifyWithKeyB64(body, string(sig), pub); err != nil {
		t.Fatalf("migrate signature verify failed: %v", err)
	}
	got, _ := s.GetProfile("team-a")
	if got.Migrate == nil || got.Migrate.ConfigURL != "https://new/configs/team-a/socksit.yaml" || got.Migrate.UpdateMode != "notify" {
		t.Fatalf("migrate not read back: %+v", got.Migrate)
	}
	// Clearing the migration removes the sidecar.
	got.Migrate = nil
	if err := s.SaveProfile(got); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ServedMigrate("team-a"); err == nil {
		t.Fatal("migrate sidecar should be gone after clearing")
	}
	// Invalid migration is rejected.
	bad := sampleProfile("team-b")
	bad.Migrate = &MigrateView{ConfigURL: "not-a-url"}
	if err := s.SaveProfile(bad); err == nil {
		t.Fatal("invalid migrate.configUrl should be rejected")
	}
}
