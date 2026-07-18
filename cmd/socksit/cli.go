package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"socksit/internal/ipc"
	"socksit/ui/panel"
	"socksit/ui/tray"
)

// engineVersion is the pinned sing-box engine version, shown by `version`.
const engineVersion = "v1.13.14"

// rootName is the program name used as the root of the command tree.
const rootName = "socksit"

// callTimeout bounds a single IPC round-trip to the service.
const callTimeout = 5 * time.Second

// errSilent tells main to exit non-zero without printing anything more — the
// command already emitted its own message or usage.
var errSilent = errors.New("")

// command is one node of the CLI tree. A node is a leaf (Run set) or a group
// (Children set); a group dispatches its first argument to a matching child.
type command struct {
	Name     string
	Summary  string   // one-line description shown in help listings
	Section  string   // groups the command under a heading in the parent's help
	Hidden   bool     // machine-only command or back-compat alias; omitted from help
	Aliases  []string // alternative names (e.g. -v, --version)
	Run      func(path string, args []string) error
	Children []*command
}

// dispatch runs command c, whose invocation path so far is `path`, over args.
func dispatch(path string, c *command, args []string) error {
	full := c.Name
	if path != "" {
		full = path + " " + c.Name
	}
	if len(c.Children) == 0 {
		return c.Run(full, args)
	}
	// Group: the first arg selects a child; -h/--help/help print the group help.
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		if len(args) > 1 { // `<group> help <sub>` → show that sub's usage
			if child := findChild(c, args[1]); child != nil {
				return dispatch(full, child, []string{"-h"})
			}
		}
		printGroupHelp(full, c, os.Stdout)
		return nil
	}
	child := findChild(c, args[0])
	if child == nil {
		fmt.Fprintf(os.Stderr, "unknown command: %s %s\n\n", full, args[0])
		printGroupHelp(full, c, os.Stderr)
		return errSilent
	}
	return dispatch(full, child, args[1:])
}

func findChild(c *command, name string) *command {
	for _, ch := range c.Children {
		if ch.Name == name {
			return ch
		}
		for _, a := range ch.Aliases {
			if a == name {
				return ch
			}
		}
	}
	return nil
}

// newFlagSet builds a leaf's flag set with a uniform usage message.
func newFlagSet(path, argSpec, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet(path, flag.ExitOnError)
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, "%s — %s\n\nusage:\n  %s", path, summary, path)
		if argSpec != "" {
			fmt.Fprintf(w, " %s", argSpec)
		}
		fmt.Fprintln(w)
		n := 0
		fs.VisitAll(func(*flag.Flag) { n++ })
		if n > 0 {
			fmt.Fprint(w, "\nflags:\n")
			fs.PrintDefaults()
		}
	}
	return fs
}

// printGroupHelp lists a group's visible children, grouped by Section.
func printGroupHelp(path string, c *command, w io.Writer) {
	if c.Summary != "" {
		fmt.Fprintf(w, "%s — %s\n\n", path, c.Summary)
	}
	fmt.Fprintf(w, "usage:\n  %s <command> [flags]\n", path)
	if c.Name == rootName {
		fmt.Fprintf(w, "  %-34s open the control panel (no command)\n", rootName)
	}
	fmt.Fprint(w, "\ncommands:\n")
	var order []string
	seen := map[string]bool{}
	for _, ch := range c.Children {
		if ch.Hidden {
			continue
		}
		if !seen[ch.Section] {
			seen[ch.Section] = true
			order = append(order, ch.Section)
		}
	}
	for _, sec := range order {
		if sec != "" {
			fmt.Fprintf(w, "\n  %s:\n", sec)
		}
		for _, ch := range c.Children {
			if ch.Hidden || ch.Section != sec {
				continue
			}
			fmt.Fprintf(w, "  %-16s %s\n", ch.Name, ch.Summary)
		}
	}
	fmt.Fprintf(w, "\nrun \"%s help <command>\" for a command's flags.\n", path)
}

// buildCLI constructs the command tree. Machine-invoked entrypoints (service,
// update-restart) and back-compat aliases (gen, check) are Hidden — do NOT rename
// service/update-restart: the SCM registration and the updater invoke them by name.
func buildCLI() *command {
	return &command{
		Name:    rootName,
		Summary: "per-app SOCKS5 proxifier",
		Children: []*command{
			{Name: "version", Aliases: []string{"-v", "--version"}, Summary: "show the SocksIt and engine version", Run: cmdVersion},
			{Name: "help", Summary: "show this help", Run: func(string, []string) error { printGroupHelp(rootName, buildCLI(), os.Stdout); return nil }},

			{Name: "install", Section: "Service", Summary: "register the Windows service", Run: cmdInstall},
			{Name: "uninstall", Section: "Service", Summary: "remove the Windows service", Run: cmdUninstall},
			{Name: "start", Section: "Service", Summary: "start the service", Run: cmdStart},
			{Name: "stop", Section: "Service", Summary: "stop the service", Run: cmdStop},
			{Name: "restart", Section: "Service", Summary: "restart the service", Run: cmdRestart},
			{Name: "status", Section: "Service", Summary: "service + tunnel status", Run: cmdStatus},
			{Name: "setup", Section: "Service", Summary: "turnkey install + preset + start (admin)", Run: cmdSetup},

			configCmd(),

			{Name: "doctor", Section: "Diagnostics", Summary: "environment health summary", Run: cmdDoctor},
			{Name: "proxytest", Section: "Diagnostics", Summary: "test the upstream SOCKS5 proxy", Run: cmdProxytest},
			{Name: "logs", Section: "Diagnostics", Summary: "print the tail of the service logs", Run: cmdLogs},

			{Name: "gui", Section: "UI", Summary: "app-list editor + statistics window", Run: cmdGUI},
			{Name: "tray", Section: "UI", Summary: "user-session tray icon", Run: cmdTray},

			// Hidden back-compat aliases for the old flat commands.
			{Name: "gen", Hidden: true, Run: cmdConfigGen},
			{Name: "check", Hidden: true, Run: cmdConfigValidate},
			// Hidden machine entrypoints — invoked by the SCM and the updater.
			{Name: "service", Hidden: true, Run: cmdService},
			{Name: "run", Hidden: true, Run: cmdRun},
			{Name: "update-restart", Hidden: true, Run: cmdUpdateRestart},
		},
	}
}

// --- small commands ---

func cmdVersion(path string, args []string) error {
	fs := newFlagSet(path, "[--json]", "show the SocksIt and engine version")
	asJSON := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)
	if *asJSON {
		return printJSON(os.Stdout, map[string]string{"version": Version, "engine": engineVersion})
	}
	fmt.Printf("socksit %s (engine sing-box %s)\n", Version, engineVersion)
	return nil
}

func cmdGUI(path string, args []string) error {
	_ = newFlagSet(path, "", "open the app-list editor + statistics window").Parse(args)
	dd := defaultDataDir()
	return panel.Run(ipc.DefaultPipeName, filepath.Join(dd, "socksit.yaml"), dd, Version, "settings")
}

func cmdTray(path string, args []string) error {
	_ = newFlagSet(path, "", "run the user-session tray icon").Parse(args)
	tray.Run(ipc.DefaultPipeName, Version)
	return nil
}

// --- shared helpers ---

// ipcCall sends one request to the service control pipe.
func ipcCall(op string, args map[string]string, timeout time.Duration) (ipc.Response, error) {
	return ipc.Call(ipc.DefaultPipeName, ipc.Request{Op: op, Args: args}, timeout)
}

// printJSON writes v as indented JSON.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// configFilePath is the installed config's path (%ProgramData%\SocksIt\socksit.yaml).
func configFilePath() string { return filepath.Join(defaultDataDir(), "socksit.yaml") }

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
