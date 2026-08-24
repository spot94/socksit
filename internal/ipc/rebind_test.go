//go:build windows

package ipc

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestRebindKeepsServing covers the fix for "the panel only works when elevated":
// the service starts before anyone logs in, so the pipe DACL cannot name a user
// yet and must be replaced later. Serve has to survive that swap.
func TestRebindKeepsServing(t *testing.T) {
	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatalf("CurrentUserSID: %v", err)
	}
	srv := NewServer(&fakeHandler{}, nil, "test")
	pipe := fmt.Sprintf(`\\.\pipe\socksit-rebind-%d`, os.Getpid())

	// Both binds grant this user: a SYSTEM+Admins-only DACL (the real pre-logon
	// state) cannot be created by an unelevated test process, and what matters here
	// is that Serve survives the listener being swapped underneath it.
	if err := srv.Rebind(pipe, BuildSDDL(sid)); err != nil {
		t.Fatalf("initial Rebind: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	call := func(what string) {
		t.Helper()
		resp, err := Call(pipe, Request{Op: OpStatus}, 3*time.Second)
		if err != nil {
			t.Fatalf("%s: call failed: %v", what, err)
		}
		if !resp.OK {
			t.Fatalf("%s: response not OK: %s", what, resp.Error)
		}
	}
	call("before rebind")

	// Now a user logs in: rebind granting them. Serving must continue.
	if err := srv.Rebind(pipe, BuildSDDL(sid)); err != nil {
		t.Fatalf("Rebind for the user: %v", err)
	}
	call("after rebind")

	// And again (fast user switching / repeated checks must be harmless).
	if err := srv.Rebind(pipe, BuildSDDL(sid)); err != nil {
		t.Fatalf("second Rebind: %v", err)
	}
	call("after second rebind")

	cancel()
	if _, err := Call(pipe, Request{Op: OpStatus}, 500*time.Millisecond); err == nil {
		t.Error("the pipe must be gone once the context is cancelled")
	}
}
