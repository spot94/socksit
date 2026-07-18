// Package proxytest performs a lightweight reachability + SOCKS5 handshake check
// against an upstream SOCKS5 proxy. It backs the "Test proxy" action and the
// diagnostics report. It never routes real app traffic — it only verifies that
// the proxy is reachable, speaks SOCKS5, accepts the given credentials, and (best
// effort) can open an outbound connection.
//
// It returns machine-readable results (an Outcome, or a typed *Fault with a
// stable Code) rather than UI prose, so callers can localize the messages.
package proxytest

import (
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const dialTimeout = 5 * time.Second

// Outcome is a successful handshake result.
type Outcome struct {
	Target  string // addr:port
	Auth    string // "none" | "userpass"
	Egress  string // "ok" | "refused" | "senderr" | "noreply"
	RepCode int    // SOCKS5 reply code when Egress == "refused"
}

// Fault is a hard failure with a stable Code (for localization) and optional
// dynamic Detail (an OS error string, a byte value, …).
type Fault struct {
	Code   string
	Detail string
}

func (f *Fault) Error() string {
	if f.Detail != "" {
		return f.Code + ": " + f.Detail
	}
	return f.Code
}

// Check connects to the SOCKS5 proxy at address:port, negotiates authentication
// (using user/pass when provided), and attempts a test CONNECT. It returns an
// Outcome on a successful handshake+auth, or a *Fault describing the first hard
// failure.
func Check(address string, port int, user, pass string) (Outcome, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return Outcome{}, &Fault{Code: "empty_address"}
	}
	if port < 1 || port > 65535 {
		return Outcome{}, &Fault{Code: "bad_port", Detail: strconv.Itoa(port)}
	}
	target := net.JoinHostPort(address, strconv.Itoa(port))
	o := Outcome{Target: target}

	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		return o, &Fault{Code: "connect", Detail: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))

	// Method negotiation: offer user/pass (0x02) first when we have credentials,
	// always allow no-auth (0x00).
	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x02, 0x00}
	}
	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greet); err != nil {
		return o, &Fault{Code: "handshake_write", Detail: err.Error()}
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return o, &Fault{Code: "no_reply", Detail: err.Error()}
	}
	if sel[0] != 0x05 {
		return o, &Fault{Code: "not_socks5", Detail: "0x" + strconv.FormatInt(int64(sel[0]), 16)}
	}

	switch sel[1] {
	case 0x00:
		o.Auth = "none"
	case 0x02:
		if user == "" {
			return o, &Fault{Code: "need_creds"}
		}
		if err := userPassAuth(conn, user, pass); err != nil {
			return o, err
		}
		o.Auth = "userpass"
	case 0xFF:
		if user == "" {
			return o, &Fault{Code: "no_auth_rejected"}
		}
		return o, &Fault{Code: "all_rejected"}
	default:
		return o, &Fault{Code: "unsupported_method", Detail: "0x" + strconv.FormatInt(int64(sel[1]), 16)}
	}

	o.Egress, o.RepCode = connectTest(conn)
	return o, nil
}

// userPassAuth runs the RFC 1929 username/password sub-negotiation.
func userPassAuth(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return &Fault{Code: "creds_too_long"}
	}
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return &Fault{Code: "auth_write", Detail: err.Error()}
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return &Fault{Code: "auth_no_reply", Detail: err.Error()}
	}
	if resp[1] != 0x00 {
		return &Fault{Code: "auth_rejected"}
	}
	return nil
}

// connectTest issues a CONNECT to a well-known public IP to confirm the proxy can
// open outbound connections. Returns an egress state and, when refused, the SOCKS5
// reply code. A refusal is not a hard failure (the proxy may restrict dests).
func connectTest(conn net.Conn) (string, int) {
	ip := net.ParseIP("1.1.1.1").To4()
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, 0x01, 0xBB) // port 443
	if _, err := conn.Write(req); err != nil {
		return "senderr", 0
	}
	head := make([]byte, 4) // VER REP RSV ATYP
	if _, err := io.ReadFull(conn, head); err != nil {
		return "noreply", 0
	}
	// Drain BND.ADDR + BND.PORT for a clean read (we close the conn regardless).
	switch head[3] {
	case 0x01:
		_, _ = io.ReadFull(conn, make([]byte, 4+2))
	case 0x04:
		_, _ = io.ReadFull(conn, make([]byte, 16+2))
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err == nil {
			_, _ = io.ReadFull(conn, make([]byte, int(l[0])+2))
		}
	}
	if head[1] == 0x00 {
		return "ok", 0
	}
	return "refused", int(head[1])
}
