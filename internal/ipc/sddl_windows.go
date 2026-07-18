//go:build windows

package ipc

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// BuildSDDL returns a protected DACL granting SYSTEM and Administrators full
// access and the given user SID read/write. Omitting every other principal is
// the deny-by-default (AUTH-2). An empty userSID yields SYSTEM+Admins only
// (used when no interactive user is present).
func BuildSDDL(userSID string) string {
	if userSID == "" {
		return "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	}
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;%s)", userSID)
}

// CurrentUserSID returns the SID of the process's own user. Used as a fallback
// and by tests (client and server share one identity).
func CurrentUserSID() (string, error) {
	var t windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t); err != nil {
		return "", fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer t.Close()
	return tokenUserSID(t)
}

// ResolveConsoleUserSID returns the SID of the user logged into the active
// console session. This is the production path (plan U8, variant B): the
// LocalSystem service resolves the interactive user and rebuilds the pipe DACL
// on session change. Requires SYSTEM privileges to query another session's token.
func ResolveConsoleUserSID() (string, error) {
	sess := windows.WTSGetActiveConsoleSessionId()
	if sess == 0xFFFFFFFF {
		return "", errors.New("no active console session")
	}
	var t windows.Token
	if err := windows.WTSQueryUserToken(sess, &t); err != nil {
		return "", fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer t.Close()
	return tokenUserSID(t)
}

func tokenUserSID(t windows.Token) (string, error) {
	tu, err := t.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser: %w", err)
	}
	return tu.User.Sid.String(), nil
}
