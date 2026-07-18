package configserver

import (
	"testing"
	"time"
)

func TestAuthPasswordPolicyAndLockout(t *testing.T) {
	a, err := NewAuth(t.TempDir(), false, 30*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.HasAdmin() {
		t.Fatal("no admin should exist yet")
	}
	if err := a.SetPassword("short"); err == nil {
		t.Fatal("short password should be rejected")
	}
	if err := a.SetPassword("a-good-password"); err != nil {
		t.Fatalf("valid password: %v", err)
	}
	if !a.HasAdmin() {
		t.Fatal("admin should exist after SetPassword")
	}

	// Correct password logs in and issues distinct session + csrf tokens.
	tok, csrf, err := a.Login("1.2.3.4", "a-good-password")
	if err != nil || tok == "" || csrf == "" || tok == csrf {
		t.Fatalf("login: tok=%q csrf=%q err=%v", tok, csrf, err)
	}

	// Brute-force: repeated wrong passwords eventually lock the IP out.
	locked := false
	for i := 0; i < maxLoginFails+1; i++ {
		if _, _, err := a.Login("9.9.9.9", "wrong"); err != nil && err.Error() == "too many attempts — try again later" {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatal("expected a lockout after repeated failures")
	}
}

func TestBootstrapFromEnv(t *testing.T) {
	a, err := NewAuth(t.TempDir(), false, time.Minute, "env-provided-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasAdmin() {
		t.Fatal("ADMIN_PASSWORD should bootstrap the admin")
	}
	if _, _, err := a.Login("1.1.1.1", "env-provided-pass"); err != nil {
		t.Fatalf("login with env password: %v", err)
	}
}
