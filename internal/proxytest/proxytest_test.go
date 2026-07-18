package proxytest

import (
	"errors"
	"io"
	"net"
	"testing"
)

func faultCode(err error) string {
	var f *Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

// fakeSocks starts a minimal SOCKS5 server on loopback. When requireAuth is set
// it accepts only user/pass (method 0x02) and replies 0xFF to a client that
// offers no acceptable method; otherwise it accepts no-auth (0x00). It answers one
// CONNECT with connectRep. Returns host, port.
func fakeSocks(t *testing.T, requireAuth bool, connectRep byte) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		hdr := make([]byte, 2) // ver, nmethods
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		methods := make([]byte, hdr[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		offersUserPass := false
		for _, m := range methods {
			if m == 0x02 {
				offersUserPass = true
			}
		}
		switch {
		case requireAuth && !offersUserPass:
			conn.Write([]byte{0x05, 0xFF}) // no acceptable methods
			return
		case requireAuth:
			conn.Write([]byte{0x05, 0x02})
			a := make([]byte, 2) // ver, ulen
			if _, err := io.ReadFull(conn, a); err != nil {
				return
			}
			io.ReadFull(conn, make([]byte, a[1])) // username
			p := make([]byte, 1)                  // plen
			io.ReadFull(conn, p)
			io.ReadFull(conn, make([]byte, p[0])) // password
			conn.Write([]byte{0x01, 0x00})        // auth OK
		default:
			conn.Write([]byte{0x05, 0x00}) // no-auth
		}

		req := make([]byte, 4) // ver cmd rsv atyp
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		io.ReadFull(conn, make([]byte, 4+2)) // IPv4 addr + port
		conn.Write([]byte{0x05, connectRep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()

	ta := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", ta.Port
}

func TestCheckNoAuthSuccess(t *testing.T) {
	host, port := fakeSocks(t, false, 0x00)
	o, err := Check(host, port, "", "")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if o.Auth != "none" || o.Egress != "ok" {
		t.Errorf("expected auth=none egress=ok, got %+v", o)
	}
}

func TestCheckUserPassAccepted(t *testing.T) {
	host, port := fakeSocks(t, true, 0x00)
	o, err := Check(host, port, "alice", "secret")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if o.Auth != "userpass" {
		t.Errorf("expected auth=userpass, got %+v", o)
	}
}

func TestCheckAuthRequiredButNoCreds(t *testing.T) {
	host, port := fakeSocks(t, true, 0x00)
	_, err := Check(host, port, "", "")
	if code := faultCode(err); code != "no_auth_rejected" {
		t.Fatalf("expected fault no_auth_rejected, got %v (%q)", err, code)
	}
}

func TestCheckUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listens here now
	_, err := Check("127.0.0.1", port, "", "")
	if code := faultCode(err); code != "connect" {
		t.Fatalf("expected fault connect, got %v (%q)", err, code)
	}
}

func TestCheckConnectRefused(t *testing.T) {
	host, port := fakeSocks(t, false, 0x05) // egress refused
	o, err := Check(host, port, "", "")
	if err != nil {
		t.Fatalf("handshake should still succeed, got %v", err)
	}
	if o.Egress != "refused" || o.RepCode != 5 {
		t.Errorf("expected egress=refused code=5, got %+v", o)
	}
}
