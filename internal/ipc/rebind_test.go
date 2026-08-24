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

	// Now a user logs in: rebind granting them, then again (fast user switching and
	// the supervisor's repeated checks must both be harmless). What is asserted is
	// the contract that matters: the pipe keeps serving. A rebind may legitimately
	// fail when the previous listener refuses to close (see Rebind) — it then keeps
	// the old listener, which is exactly why serving must continue either way.
	rebind := func(what string) {
		t.Helper()
		if err := srv.Rebind(pipe, BuildSDDL(sid)); err != nil {
			t.Logf("%s reported %v — the previous listener must still serve", what, err)
		}
	}
	rebind("Rebind for the user")
	call("after rebind")
	rebind("second Rebind")
	call("after second rebind")

	cancel()
	// Serve tears the listener down asynchronously, and a call that races the cancel
	// can still land on a pipe instance that was already accepted — so poll instead
	// of assuming the very next call fails. The assertion still holds: it must stop
	// serving, and quickly.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := Call(pipe, Request{Op: OpStatus}, 300*time.Millisecond); err != nil {
			break // gone, as it must be
		}
		if time.Now().After(deadline) {
			t.Error("the pipe must stop serving once the context is cancelled")
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRebindKeepsThePipeWhenTheNewOneFails: a rebind that cannot create the new
// listener must leave the old one serving. Losing the pipe is unrecoverable in
// practice — the panel talks to the service through it and nothing else — while
// an out-of-date DACL only means the rebind has to be retried.
func TestRebindKeepsThePipeWhenTheNewOneFails(t *testing.T) {
	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatalf("CurrentUserSID: %v", err)
	}
	srv := NewServer(&fakeHandler{}, nil, "test")
	pipe := fmt.Sprintf(`\\.\pipe\socksit-rebind-fail-%d`, os.Getpid())
	if err := srv.Rebind(pipe, BuildSDDL(sid)); err != nil {
		t.Fatalf("initial Rebind: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	if _, err := Call(pipe, Request{Op: OpStatus}, 3*time.Second); err != nil {
		t.Fatalf("call before the failed rebind: %v", err)
	}
	if err := srv.Rebind(pipe, "not-a-security-descriptor"); err == nil {
		t.Fatal("an invalid DACL must be reported, not accepted")
	}
	if _, err := Call(pipe, Request{Op: OpStatus}, 3*time.Second); err != nil {
		t.Errorf("the pipe must still serve after a failed rebind: %v", err)
	}
}
