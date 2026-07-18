//go:build windows

package ipc

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"socksit/internal/audit"
)

type fakeHandler struct {
	setConfig            string
	credsUser, credsPass string
	toggledOn            *bool
	reloaded             bool
}

func (h *fakeHandler) Status() (any, error)       { return map[string]string{"state": "running"}, nil }
func (h *fakeHandler) GetConfig() (string, error) { return "proxy:\n  address: 1.2.3.4\n", nil }
func (h *fakeHandler) SetConfig(y string) error   { h.setConfig = y; return nil }
func (h *fakeHandler) SetCredentials(u, p string) error {
	h.credsUser, h.credsPass = u, p
	return nil
}
func (h *fakeHandler) Toggle(on bool) error       { h.toggledOn = &on; return nil }
func (h *fakeHandler) Reload() error              { h.reloaded = true; return nil }
func (h *fakeHandler) Stats() (any, error)        { return []string{}, nil }
func (h *fakeHandler) UpdateStatus() (any, error) { return map[string]string{}, nil }
func (h *fakeHandler) UpdateCheck() (any, error)  { return map[string]string{}, nil }
func (h *fakeHandler) UpdateApply() (any, error)  { return map[string]string{}, nil }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestServerClientRoundTrip(t *testing.T) {
	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatalf("CurrentUserSID: %v", err)
	}
	h := &fakeHandler{}
	var auditBuf syncBuf
	srv := NewServer(h, audit.New(&auditBuf), "TESTUSER")

	pipe := fmt.Sprintf(`\\.\pipe\socksit-test-%d`, os.Getpid())
	if err := srv.Listen(pipe, BuildSDDL(sid)); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	call := func(req Request) Response {
		t.Helper()
		resp, err := Call(pipe, req, 3*time.Second)
		if err != nil {
			t.Fatalf("Call(%s): %v", req.Op, err)
		}
		return resp
	}

	// read op
	if r := call(Request{Op: OpStatus}); !r.OK || !strings.Contains(string(r.Data), "running") {
		t.Errorf("status: ok=%v data=%s", r.OK, r.Data)
	}

	// mutating ops
	if r := call(Request{Op: OpSetConfig, Args: map[string]string{"yaml": "proxy: {}"}}); !r.OK {
		t.Errorf("set_config not ok: %s", r.Error)
	}
	if h.setConfig != "proxy: {}" {
		t.Errorf("handler.SetConfig got %q", h.setConfig)
	}

	if r := call(Request{Op: OpSetCreds, Args: map[string]string{"user": "u", "pass": "hunter2"}}); !r.OK {
		t.Errorf("set_credentials not ok: %s", r.Error)
	}
	if h.credsUser != "u" || h.credsPass != "hunter2" {
		t.Errorf("handler.SetCredentials got %q/%q", h.credsUser, h.credsPass)
	}

	if r := call(Request{Op: OpToggle, Args: map[string]string{"on": "true"}}); !r.OK {
		t.Errorf("toggle not ok: %s", r.Error)
	}
	if h.toggledOn == nil || !*h.toggledOn {
		t.Error("handler.Toggle(true) not recorded")
	}

	if r := call(Request{Op: OpReload}); !r.OK {
		t.Errorf("reload not ok: %s", r.Error)
	}
	if !h.reloaded {
		t.Error("handler.Reload not called")
	}

	// audit: mutating ops recorded, secret NOT leaked
	log := auditBuf.String()
	for _, want := range []string{"updated configuration", "updated SOCKS5 credentials", "enabled proxying", "reloaded configuration", "TESTUSER"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %q\n---\n%s", want, log)
		}
	}
	if strings.Contains(log, "hunter2") {
		t.Fatalf("audit log leaked the credential value:\n%s", log)
	}
}

func TestUnknownOp(t *testing.T) {
	sid, _ := CurrentUserSID()
	srv := NewServer(&fakeHandler{}, audit.New(&syncBuf{}), "T")
	pipe := fmt.Sprintf(`\\.\pipe\socksit-test-unk-%d`, os.Getpid())
	if err := srv.Listen(pipe, BuildSDDL(sid)); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	r, err := Call(pipe, Request{Op: "bogus"}, 3*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if r.OK || !strings.Contains(r.Error, "unknown op") {
		t.Errorf("expected unknown-op error, got ok=%v err=%q", r.OK, r.Error)
	}
}
