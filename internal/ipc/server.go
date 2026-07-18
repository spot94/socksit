//go:build windows

package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/Microsoft/go-winio"
	"socksit/internal/audit"
)

// Server serves control requests over a secured named pipe and audits mutating
// operations.
type Server struct {
	h     Handler
	log   *audit.Logger
	actor string
	ln    net.Listener
}

// NewServer builds a Server. actor is the identity recorded in the audit log
// (e.g. the local username).
func NewServer(h Handler, log *audit.Logger, actor string) *Server {
	return &Server{h: h, log: log, actor: actor}
}

// Listen creates the pipe with the given SDDL DACL.
func (s *Server) Listen(pipeName, sddl string) error {
	ln, err := winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		return fmt.Errorf("listen pipe %s: %w", pipeName, err)
	}
	s.ln = ln
	return nil
}

// Serve accepts connections until ctx is cancelled or the listener closes.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.ln.Close()
	}()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.handleConn(conn)
	}
}

// Close stops the listener.
func (s *Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
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
