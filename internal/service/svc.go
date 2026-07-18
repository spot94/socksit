//go:build windows

package service

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"

	"socksit/internal/ipc"
	"socksit/internal/secret"
)

// ServiceName is the Windows service identifier.
const ServiceName = "SocksIt"

func secretStore() *secret.Store { return secret.New(credentialEntropy) }

// consoleUserSID resolves the user to grant on the pipe DACL (plan U8, variant B).
// As a LocalSystem service it uses WTS to find the interactive console user. When
// run interactively (e.g. `socksit run`), WTSQueryUserToken needs SeTcbPrivilege
// (SYSTEM only), so we fall back to the current process user — which IS the
// operator in that mode. Only if both fail is the pipe limited to SYSTEM+Admins.
func consoleUserSID(log io.Writer) string {
	if sid, err := ipc.ResolveConsoleUserSID(); err == nil {
		return sid
	}
	if sid, err := ipc.CurrentUserSID(); err == nil {
		return sid
	}
	fmt.Fprintln(log, "could not resolve a user SID; pipe limited to SYSTEM+Admins")
	return ""
}

// handler adapts Runtime to the SCM lifecycle.
type handler struct{ rt *Runtime }

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- h.rt.Run(ctx) }() // heavy init runs async so we report Running fast

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-errc
				return false, 0
			}
		case <-errc:
			// Runtime exited on its own (fatal, e.g. crash-loop breaker).
			return false, 1
		}
	}
}

// Run starts SocksIt under the Windows Service Control Manager.
func Run(rt *Runtime) error { return svc.Run(ServiceName, &handler{rt: rt}) }

// RunInteractive runs the identical handler on the console for development.
func RunInteractive(rt *Runtime) error { return debug.Run(ServiceName, &handler{rt: rt}) }
