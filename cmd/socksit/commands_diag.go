package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"socksit/internal/config"
	"socksit/internal/ipc"
	"socksit/internal/proxytest"
	"socksit/internal/service"
)

// cmdDoctor prints a one-shot health summary of the local install: engine
// binary, service state, config validity and control-pipe reachability.
func cmdDoctor(path string, args []string) error {
	fs := newFlagSet(path, "[--json]", "print an environment health summary")
	asJSON := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)

	rep := map[string]any{
		"version":        Version,
		"engine_version": engineVersion,
		"data_dir":       defaultDataDir(),
		"config_path":    configFilePath(),
	}
	eng := defaultEngine()
	_, engErr := os.Stat(eng)
	rep["engine_path"] = eng
	rep["engine_present"] = engErr == nil

	installed, running, sErr := service.Status()
	rep["service_installed"] = installed
	rep["service_running"] = running
	if sErr != nil {
		rep["service_error"] = sErr.Error()
	}

	if b, err := os.ReadFile(configFilePath()); err != nil {
		rep["config_present"] = false
	} else {
		rep["config_present"] = true
		if _, err := config.Parse(b); err != nil {
			rep["config_valid"] = false
			rep["config_error"] = err.Error()
		} else {
			rep["config_valid"] = true
		}
	}

	if resp, err := ipcCall(ipc.OpStatus, nil, callTimeout); err == nil && resp.OK {
		rep["ipc_reachable"] = true
		var tunnel map[string]any
		if json.Unmarshal(resp.Data, &tunnel) == nil {
			rep["tunnel"] = tunnel
		}
	} else {
		rep["ipc_reachable"] = false
	}

	if *asJSON {
		return printJSON(os.Stdout, rep)
	}

	fmt.Println("SocksIt doctor")
	fmt.Printf("  version        %s (engine %s)\n", Version, engineVersion)
	fmt.Printf("  engine         %s  %s\n", mark(rep["engine_present"] == true), eng)
	fmt.Printf("  service        %s  installed=%v running=%v\n", mark(installed), installed, running)
	fmt.Printf("  config         %s  %s\n", mark(rep["config_valid"] == true), configFilePath())
	if msg, ok := rep["config_error"].(string); ok {
		fmt.Printf("                    %s\n", msg)
	}
	fmt.Printf("  control pipe   %s  %s\n", mark(rep["ipc_reachable"] == true),
		boolWord(rep["ipc_reachable"] == true, "reachable", "unreachable"))
	if t, ok := rep["tunnel"].(map[string]any); ok {
		fmt.Printf("  tunnel state   %v (proxy %v, %v apps, %v mode)\n", t["state"], t["proxy"], t["apps"], t["mode"])
	}
	return nil
}

// cmdProxytest runs a SOCKS5 reachability + handshake check against the
// configured upstream proxy. Note: the SOCKS password normally lives in the
// service's DPAPI store, not the YAML, so an auth-required proxy may report
// "auth required" here even when the panel's test (which uses the stored
// credentials) succeeds — the reachability/handshake result is still meaningful.
func cmdProxytest(path string, args []string) error {
	fs := newFlagSet(path, "[--json] [-c file]", "test the configured upstream SOCKS5 proxy")
	asJSON := fs.Bool("json", false, "machine-readable output")
	in := fs.String("c", "", "config file to read the proxy from (default: the installed config)")
	_ = fs.Parse(args)

	var b []byte
	var err error
	if *in != "" {
		b, err = os.ReadFile(*in)
	} else {
		b, _, err = loadConfigText()
	}
	if err != nil {
		return err
	}
	c := config.ParseLenient(b)
	o, ferr := proxytest.Check(c.Proxy.Address, c.Proxy.Port, c.Proxy.Username, c.Proxy.Password)

	if *asJSON {
		out := map[string]any{"target": o.Target, "auth": o.Auth, "egress": o.Egress, "ok": ferr == nil}
		if ferr != nil {
			var f *proxytest.Fault
			if errors.As(ferr, &f) {
				out["fault"] = f.Code
				if f.Detail != "" {
					out["detail"] = f.Detail
				}
			} else {
				out["error"] = ferr.Error()
			}
		}
		return printJSON(os.Stdout, out)
	}
	if ferr != nil {
		return fmt.Errorf("proxy test failed: %s", ferr.Error())
	}
	fmt.Printf("proxy %s: SOCKS5 OK (auth=%s, egress=%s)\n", o.Target, o.Auth, o.Egress)
	return nil
}

// cmdLogs prints the tail of the runtime log (or the audit log with --audit),
// optionally following it.
func cmdLogs(path string, args []string) error {
	fs := newFlagSet(path, "[-n N] [-f] [--audit]", "print (and optionally follow) the service logs")
	n := fs.Int("n", 200, "number of lines to show from the end")
	follow := fs.Bool("f", false, "follow the log; Ctrl+C to stop")
	audit := fs.Bool("audit", false, "show the audit log instead of the runtime log")
	_ = fs.Parse(args)

	name := "socksit.log"
	if *audit {
		name = "audit.log"
	}
	p := filepath.Join(defaultDataDir(), name)
	lines, err := tailFile(p, *n)
	if err != nil {
		return err
	}
	for _, ln := range lines {
		fmt.Println(ln)
	}
	if *follow {
		return followFile(p)
	}
	return nil
}

// tailFile returns the last n lines of the file at p.
func tailFile(p string, n int) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no log yet at %s (has the service run?)", p)
		}
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:] // keep only the last n (ring)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// followFile streams bytes appended to p after the current end, until the
// process is interrupted.
func followFile(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	off, _ := f.Seek(0, io.SeekEnd)
	buf := make([]byte, 8192)
	for {
		n, err := f.ReadAt(buf, off)
		if n > 0 {
			os.Stdout.Write(buf[:n])
			off += int64(n)
		}
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// mark returns a compact OK/!! status marker.
func mark(ok bool) string {
	if ok {
		return "[ok]"
	}
	return "[!!]"
}
