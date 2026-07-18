package configserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequireAdminBlocksOperator(t *testing.T) {
	a, err := NewAuth(t.TempDir(), false, time.Minute, "a-good-password")
	if err != nil {
		t.Fatal(err)
	}
	admTok, _ := a.StartSession("1.1.1.1", RoleAdmin, "Admin", "local")
	opTok, _ := a.StartSession("1.1.1.1", RoleOperator, "Op", "ldap")
	h := a.requireAdmin(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, c := range []struct {
		tok  string
		want int
	}{{admTok, 200}, {opTok, 403}} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.tok})
		h(rec, req)
		if rec.Code != c.want {
			t.Errorf("token role gate: got %d, want %d", rec.Code, c.want)
		}
	}
}

func TestLDAPStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	l, _ := NewLDAP(dir)
	if l.Enabled() {
		t.Fatal("should start disabled")
	}
	cfg := LDAPConfig{Enabled: true, URL: "ldaps://dc:636", BaseDN: "DC=x", UserFilter: "(sAMAccountName={user})",
		AdminFilter: "(memberOf=CN=A)", BindDN: "CN=svc", BindPassword: "secret"}
	if err := l.Save(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	if !l.Enabled() {
		t.Fatal("should be enabled")
	}
	if l.Config().BindPassword != "" {
		t.Fatal("Config() must blank the bind password")
	}
	if l.raw().BindPassword != "secret" {
		t.Fatal("raw() should keep the password")
	}
	// Blank password on save keeps the stored one; other fields update.
	c2 := cfg
	c2.BindPassword = ""
	c2.URL = "ldaps://dc2:636"
	if err := l.Save(c2); err != nil {
		t.Fatal(err)
	}
	if l.raw().BindPassword != "secret" || l.raw().URL != "ldaps://dc2:636" {
		t.Fatalf("blank pw should keep secret + update url, got %q %q", l.raw().BindPassword, l.raw().URL)
	}
	// Validation.
	if err := l.Save(LDAPConfig{Enabled: true, URL: "ldaps://x"}); err == nil {
		t.Fatal("enabled without base DN should be rejected")
	}
	if err := l.Save(LDAPConfig{Enabled: true, URL: "ldaps://x", BaseDN: "DC=x", UserFilter: "no-placeholder", AdminFilter: "(x)"}); err == nil {
		t.Fatal("user filter without {user} should be rejected")
	}
	// Persist across reload.
	l2, _ := NewLDAP(dir)
	if !l2.Enabled() || l2.raw().BindPassword != "secret" {
		t.Fatal("config should persist on disk")
	}
}
