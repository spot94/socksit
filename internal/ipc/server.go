//go:build windows

package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"socksit/internal/audit"
)

// Server serves control requests over a secured named pipe and audits mutating
// operations.
type Server struct {
	h     Handler
	log   *audit.Logger
	actor string
	mu    sync.Mutex
	ln    net.Listener
	// The binding currently serving, kept so a failed Rebind can restore it. A
	// service with no control pipe is unreachable until it restarts — nothing can
	// ask it to try again — so Rebind must never end with nothing listening.
	pipeName string
	sddl     string
}

// closeGrace bounds how long Rebind waits for the previous listener to close.
// Generous on purpose: a healthy close is immediate, so anything near this is the
// go-winio deadlock described in Rebind, not slowness.
const closeGrace = 2 * time.Second

// NewServer builds a Server. actor is the identity recorded in the audit log
// (e.g. the local username).
func NewServer(h Handler, log *audit.Logger, actor string) *Server {
	return &Server{h: h, log: log, actor: actor}
}

// Listen creates the pipe with the given SDDL DACL.
// Listen binds the control pipe with the given DACL.
func (s *Server) Listen(pipeName, sddl string) error { return s.Rebind(pipeName, sddl) }

// Rebind re-creates the pipe with a new DACL and hands it to a running Serve
// loop. It exists because the DACL must grant the CURRENT interactive user: the
// service starts before anyone logs in, so the first DACL cannot name a user and
// has to be replaced once one appears. In-flight requests are short RPCs; the old
// listener is closed after the new one is in place so there is no window without
// a pipe.
func (s *Server) Rebind(pipeName, sddl string) error {
	// Windows refuses to create another instance of an existing pipe with a
	// DIFFERENT security descriptor (ERROR_ACCESS_DENIED), so the old listener has
	// to go first. Serve notices and waits for the replacement; the gap is
	// sub-millisecond and the panel polls, so a missed RPC is retried.
	s.mu.Lock()
	old, prevName, prevSDDL := s.ln, s.pipeName, s.sddl
	s.ln = nil
	s.mu.Unlock()

	closeStuck := false
	if old != nil {
		// Never block on the close. go-winio's listener Close() waits for its
		// listener goroutine, and that goroutine can be left waiting for a client
		// who will never arrive: when a short RPC disconnects at the same instant as
		// the close, the connect fails with ERROR_NO_DATA and the retry re-enters the
		// wait — but the close signal was already consumed, so nothing wakes it.
		// Reproduced roughly once per 20 rebinds under a hammering client. This runs
		// from the pipe supervisor, so waiting here would wedge the control channel
		// for the rest of the service's life: the panel would never reach it again.
		done := make(chan struct{})
		go func() { old.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(closeGrace):
			closeStuck = true
		}
	}

	if ln, err := winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: sddl}); err == nil {
		s.setListener(ln, pipeName, sddl)
		return nil
	} else if closeStuck {
		// The old listener never closed, so its pipe is still up and still serving:
		// keep it. The DACL stays more restrictive than intended (which is why the
		// new bind was refused — Windows will not accept a different descriptor
		// while that handle is open), but a reachable pipe beats none.
		s.setListener(old, prevName, prevSDDL)
		return fmt.Errorf("listen pipe %s: %w (the previous listener did not close within %s; still serving with the previous DACL)", pipeName, err, closeGrace)
	} else {
		// The old pipe is genuinely gone. Put the previous binding back so the
		// service stays reachable, and report why the new one was refused.
		if prevSDDL != "" {
			if back, rerr := winio.ListenPipe(prevName, &winio.PipeConfig{SecurityDescriptor: prevSDDL}); rerr == nil {
				s.setListener(back, prevName, prevSDDL)
				return fmt.Errorf("listen pipe %s: %w (restored the previous binding)", pipeName, err)
			}
		}
		return fmt.Errorf("listen pipe %s: %w", pipeName, err)
	}
}

// setListener publishes the listener now serving, together with the binding that
// produced it.
func (s *Server) setListener(ln net.Listener, pipeName, sddl string) {
	s.mu.Lock()
	s.ln, s.pipeName, s.sddl = ln, pipeName, sddl
	s.mu.Unlock()
}

// listener returns the current listener.
func (s *Server) listener() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ln
}

// Serve accepts connections until ctx is cancelled or the listener closes.
// Serve accepts requests until ctx ends. It survives Rebind: when the listener
// it was accepting on is replaced, it continues on the new one.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		ln := s.listener()
		if ln == nil {
			// Mid-rebind: the old listener is closed and the new one is not up yet.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Rebind closed this listener: nil means the replacement is still being
			// created, a different one means it is already up. Either way keep serving.
			if s.listener() != ln {
				continue
			}
			return err
		}
		go s.handleConn(conn)
	}
}

// Close stops the listener.
func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResp(conn, Response{Error: "malformed request"})
		return
	}
	writeResp(conn, s.dispatch(req))
}

func (s *Server) dispatch(req Request) Response {
	switch req.Op {
	case OpStatus:
		return dataResp(s.h.Status())
	case OpGetConfig:
		v, err := s.h.GetConfig()
		if err != nil {
			return errResp(err)
		}
		return dataResp(v, nil)
	case OpStats:
		return dataResp(s.h.Stats())
	case OpUpdateStatus:
		return dataResp(s.h.UpdateStatus())
	case OpUpdateCheck:
		return dataResp(s.h.UpdateCheck())
	case OpUpdateApply:
		resp := dataResp(s.h.UpdateApply())
		s.audit("applied an update", "socksit.exe")
		return resp
	case OpConfigStatus:
		return dataResp(s.h.ConfigStatus())
	case OpConfigFetch:
		resp := dataResp(s.h.ConfigFetch())
		s.audit("fetched the managed config", "socksit.yaml")
		return resp

	case OpSetConfig:
		if err := s.h.SetConfig(req.Args["yaml"]); err != nil {
			return errResp(err)
		}
		s.audit("updated configuration", "socksit.yaml")
		return okResp()
	case OpSetCreds:
		// Plaintext arrives here and is handed to the service to encrypt; the
		// value is never logged.
		if err := s.h.SetCredentials(req.Args["user"], req.Args["pass"]); err != nil {
			return errResp(err)
		}
		s.audit("updated SOCKS5 credentials", "proxy")
		return okResp()
	case OpToggle:
		on, _ := strconv.ParseBool(req.Args["on"])
		if err := s.h.Toggle(on); err != nil {
			return errResp(err)
		}
		action := "disabled proxying"
		if on {
			action = "enabled proxying"
		}
		s.audit(action, "")
		return okResp()
	case OpReload:
		if err := s.h.Reload(); err != nil {
			return errResp(err)
		}
		s.audit("reloaded configuration", "socksit.yaml")
		return okResp()
	default:
		return Response{Error: "unknown op: " + req.Op}
	}
}

func (s *Server) audit(action, object string) {
	if s.log != nil {
		s.log.Log(s.actor, action, object)
	}
}

func writeResp(conn net.Conn, r Response) {
	b, _ := json.Marshal(r)
	conn.Write(append(b, '\n'))
}

func okResp() Response { return Response{OK: true} }

func errResp(err error) Response { return Response{Error: err.Error()} }

func dataResp(v any, err error) Response {
	if err != nil {
		return errResp(err)
	}
	b, mErr := json.Marshal(v)
	if mErr != nil {
		return errResp(mErr)
	}
	return Response{OK: true, Data: b}
}
