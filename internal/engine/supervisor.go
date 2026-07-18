//go:build windows

// Package engine supervises the sing-box child process: it runs under a Windows
// Job Object (kill-on-close), auto-restarts on crash with capped backoff, and
// tears down deterministically on shutdown. See plan U4/KTD6.
package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// State is the supervised engine's lifecycle state (surfaced to the UI).
type State int

const (
	StateStopped State = iota
	StateStarting
	StateRunning
	StateRestarting
	StateFaulted
)

func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateRestarting:
		return "restarting"
	case StateFaulted:
		return "faulted"
	default:
		return "stopped"
	}
}

// Options configures a Supervisor.
type Options struct {
	EnginePath   string        // path to sing-box.exe
	ConfigPath   string        // path to the generated config.json
	ReadyAddr    string        // host:port to poll for engine readiness (e.g. clash_api)
	Stdout       io.Writer     // engine stdout/stderr sink (optional)
	MinBackoff   time.Duration // initial restart delay (default 200ms)
	MaxBackoff   time.Duration // cap (default 30s)
	HealthyFor   time.Duration // a run longer than this resets backoff (default 15s)
	MaxFastFails int           // consecutive fast failures before Faulted (default 6)
	OnState      func(State)   // optional state change callback
}

func (o *Options) applyDefaults() {
	if o.MinBackoff == 0 {
		o.MinBackoff = 200 * time.Millisecond
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.HealthyFor == 0 {
		o.HealthyFor = 15 * time.Second
	}
	if o.MaxFastFails == 0 {
		o.MaxFastFails = 6
	}
}

// Supervisor runs and restarts the engine.
type Supervisor struct {
	opts  Options
	pid   atomic.Int64
	state atomic.Int32
	mu    sync.Mutex
}

// New builds a Supervisor.
func New(opts Options) *Supervisor {
	opts.applyDefaults()
	return &Supervisor{opts: opts}
}

// CurrentPID returns the running engine PID (0 if not running).
func (s *Supervisor) CurrentPID() int { return int(s.pid.Load()) }

// State returns the current lifecycle state.
func (s *Supervisor) State() State { return State(s.state.Load()) }

func (s *Supervisor) setState(st State) {
	s.state.Store(int32(st))
	if s.opts.OnState != nil {
		s.opts.OnState(st)
	}
}

// Run supervises the engine until ctx is cancelled. It returns ctx.Err() on
// clean shutdown, or a non-nil error if the crash-loop breaker trips.
func (s *Supervisor) Run(ctx context.Context) error {
	job, err := newKillOnCloseJob()
	if err != nil {
		s.setState(StateFaulted)
		return err
	}
	defer job.close() // kill-on-close guarantees no orphan if we exit abnormally

	// Kill the engine promptly when the context is cancelled so cmd.Wait returns.
	go func() {
		<-ctx.Done()
		job.terminate()
	}()

	backoff := s.opts.MinBackoff
	fastFails := 0
	for {
		if ctx.Err() != nil {
			s.setState(StateStopped)
			return ctx.Err()
		}
		s.setState(StateStarting)
		start := time.Now()
		cmd := exec.Command(s.opts.EnginePath, "run", "-c", s.opts.ConfigPath)
		if s.opts.Stdout != nil {
			cmd.Stdout = s.opts.Stdout
			cmd.Stderr = s.opts.Stdout
		}
		if err := cmd.Start(); err != nil {
			s.pid.Store(0)
		} else {
			s.pid.Store(int64(cmd.Process.Pid))
			if err := job.assignPID(cmd.Process.Pid); err != nil {
				// Not fatal to routing, but log-worthy: without assignment the
				// kill-on-close guarantee is lost for this child.
				fmt.Fprintf(discard(s.opts.Stdout), "supervisor: assign to job failed: %v\n", err)
			}
			go s.watchReady(ctx, start)
			_ = cmd.Wait()
		}
		s.pid.Store(0)

		if ctx.Err() != nil {
			s.setState(StateStopped)
			return ctx.Err()
		}

		// Crashed unexpectedly. Reset backoff after a healthy run; otherwise grow.
		if time.Since(start) >= s.opts.HealthyFor {
			backoff = s.opts.MinBackoff
			fastFails = 0
		} else {
			fastFails++
			if fastFails >= s.opts.MaxFastFails {
				s.setState(StateFaulted)
				return fmt.Errorf("engine crash-looped: %d consecutive fast failures", fastFails)
			}
		}
		s.setState(StateRestarting)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			s.setState(StateStopped)
			return ctx.Err()
		}
		if backoff *= 2; backoff > s.opts.MaxBackoff {
			backoff = s.opts.MaxBackoff
		}
	}
}

// watchReady polls ReadyAddr until it accepts a connection, then marks Running.
func (s *Supervisor) watchReady(ctx context.Context, since time.Time) {
	if s.opts.ReadyAddr == "" {
		s.setState(StateRunning)
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := net.DialTimeout("tcp", s.opts.ReadyAddr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			if s.State() == StateStarting {
				s.setState(StateRunning)
			}
			return
		}
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			return
		}
	}
}

// discard returns w or a no-op writer so logging never nil-panics.
func discard(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return io.Discard
}
