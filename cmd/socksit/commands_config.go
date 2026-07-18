package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"socksit/internal/config"
	"socksit/internal/ipc"
	"socksit/internal/singbox"
)

// configCmd is the `config` group: view and edit the routing configuration.
func configCmd() *command {
	return &command{
		Name:    "config",
		Section: "Config",
		Summary: "view and edit the configuration",
		Children: []*command{
			{Name: "show", Summary: "print the current config", Run: cmdConfigShow},
			{Name: "validate", Aliases: []string{"check"}, Summary: "validate the config with sing-box", Run: cmdConfigValidate},
			{Name: "gen", Summary: "generate a sing-box config.json", Run: cmdConfigGen},
			{Name: "apply", Summary: "load a config file into the service", Run: cmdConfigApply},
			{Name: "app", Summary: "add/remove/list routed apps", Children: []*command{
				{Name: "add", Summary: "add one or more apps", Run: cmdConfigAppAdd},
				{Name: "rm", Aliases: []string{"remove"}, Summary: "remove an app", Run: cmdConfigAppRm},
				{Name: "list", Aliases: []string{"ls"}, Summary: "list routed apps", Run: cmdConfigAppList},
			}},
			{Name: "subnet", Summary: "add/remove/list direct-bypass subnets", Children: []*command{
				{Name: "add", Summary: "add a direct-bypass CIDR", Run: cmdConfigSubnetAdd},
				{Name: "rm", Aliases: []string{"remove"}, Summary: "remove a CIDR", Run: cmdConfigSubnetRm},
				{Name: "list", Aliases: []string{"ls"}, Summary: "list direct subnets", Run: cmdConfigSubnetList},
			}},
		},
	}
}

// --- show / validate / gen / apply ---

func cmdConfigShow(path string, args []string) error {
	fs := newFlagSet(path, "[--json] [--effective]", "print the current config")
	asJSON := fs.Bool("json", false, "machine-readable output")
	eff := fs.Bool("effective", false, "resolve apps/subnets against the managed feed (override mode)")
	_ = fs.Parse(args)

	b, src, err := loadConfigText()
	if err != nil {
		return err
	}
	c := config.ParseLenient(b)
	// Never print the SOCKS password (it normally lives in the DPAPI blob, not the
	// file, but redact defensively in case it was written into the YAML).
	if c.Proxy.Password != "" {
		c.Proxy.Password = "***"
	}
	if *asJSON {
		out := map[string]any{
			"source":         src,
			"proxy":          c.Proxy.Address,
			"port":           c.Proxy.Port,
			"mode":           c.Mode,
			"apps":           c.Apps,
			"direct_subnets": c.DirectSubnets,
			"kill_switch":    c.KillSwitchOn(),
			"managed":        c.ConfigManaged(),
		}
		if *eff {
			out["effective_apps"] = c.EffectiveApps()
			out["effective_subnets"] = c.EffectiveSubnets()
		}
		return printJSON(os.Stdout, out)
	}
	fmt.Printf("# source: %s\n", src)
	if *eff {
		fmt.Printf("mode: %s\n", c.Mode)
		fmt.Println("effective apps:")
		for _, a := range c.EffectiveApps() {
			fmt.Println("  -", a)
		}
		fmt.Println("effective direct_subnets:")
		for _, s := range c.EffectiveSubnets() {
			fmt.Println("  -", s)
		}
		return nil
	}
	yamlOut, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	os.Stdout.Write(yamlOut)
	return nil
}

func cmdConfigValidate(path string, args []string) error {
	fs := newFlagSet(path, "[-c socksit.yaml] [-engine sing-box.exe]", "generate + validate the config with sing-box")
	in := fs.String("c", "socksit.yaml", "path to socksit.yaml")
	engine := fs.String("engine", defaultEngine(), "path to sing-box.exe")
	_ = fs.Parse(args)

	c, err := config.Load(*in)
	if err != nil {
		return err
	}
	js, err := singbox.GenerateJSON(c)
	if err != nil {
		return err
	}
	if err := singbox.CheckBytes(*engine, js); err != nil {
		return err
	}
	fmt.Println("OK: generated config passes sing-box check")
	return nil
}

func cmdConfigGen(path string, args []string) error {
	fs := newFlagSet(path, "[-c socksit.yaml] [-o config.json]", "generate a sing-box config.json")
	in := fs.String("c", "socksit.yaml", "path to socksit.yaml")
	out := fs.String("o", "", "output path (default: stdout)")
	_ = fs.Parse(args)

	c, err := config.Load(*in)
	if err != nil {
		return err
	}
	js, err := singbox.GenerateJSON(c)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(js)
		return err
	}
	return os.WriteFile(*out, js, 0o600)
}

func cmdConfigApply(path string, args []string) error {
	fs := newFlagSet(path, "-c <file.yaml>", "validate a config file and load it into the service")
	in := fs.String("c", "", "path to a socksit.yaml to apply")
	_ = fs.Parse(args)
	if *in == "" {
		fs.Usage()
		return errSilent
	}
	b, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	if _, err := config.Parse(b); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	where, err := saveConfig(b)
	if err != nil {
		return err
	}
	fmt.Printf("applied %s → %s\n", *in, where)
	return nil
}

// --- app add/rm/list ---

func cmdConfigAppAdd(path string, args []string) error {
	fs := newFlagSet(path, "<app.exe> [more.exe ...]", "add one or more apps to the routed set")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fs.Usage()
		return errSilent
	}
	return editConfig(func(c *config.Config) (string, error) {
		added := 0
		for _, a := range fs.Args() {
			a = strings.TrimSpace(a)
			if a == "" || containsFold(c.Apps, a) {
				continue
			}
			c.Apps = append(c.Apps, a)
			added++
		}
		if added == 0 {
			return "", errNoChange
		}
		return fmt.Sprintf("added %d app(s)", added), nil
	})
}

func cmdConfigAppRm(path string, args []string) error {
	fs := newFlagSet(path, "<app.exe> [more.exe ...]", "remove one or more apps from the routed set")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fs.Usage()
		return errSilent
	}
	return editConfig(func(c *config.Config) (string, error) {
		removed := 0
		for _, a := range fs.Args() {
			next := removeFold(c.Apps, strings.TrimSpace(a))
			if len(next) != len(c.Apps) {
				removed++
			}
			c.Apps = next
		}
		if removed == 0 {
			return "", errNoChange
		}
		return fmt.Sprintf("removed %d app(s)", removed), nil
	})
}

func cmdConfigAppList(path string, args []string) error {
	fs := newFlagSet(path, "[--json] [--effective]", "list routed apps")
	asJSON := fs.Bool("json", false, "machine-readable output")
	eff := fs.Bool("effective", false, "include apps contributed by the managed feed (override mode)")
	_ = fs.Parse(args)
	c, err := loadConfig()
	if err != nil {
		return err
	}
	list := c.Apps
	if *eff {
		list = c.EffectiveApps()
	}
	if *asJSON {
		return printJSON(os.Stdout, list)
	}
	if len(list) == 0 {
		fmt.Println("(no apps)")
		return nil
	}
	for _, a := range list {
		fmt.Println(a)
	}
	return nil
}

// --- subnet add/rm/list ---

func cmdConfigSubnetAdd(path string, args []string) error {
	fs := newFlagSet(path, "<cidr> [more ...]", "add one or more direct-bypass CIDRs")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fs.Usage()
		return errSilent
	}
	// Validate every CIDR up front so a bad arg changes nothing.
	for _, s := range fs.Args() {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
	}
	return editConfig(func(c *config.Config) (string, error) {
		added := 0
		for _, s := range fs.Args() {
			s = strings.TrimSpace(s)
			if containsFold(c.DirectSubnets, s) {
				continue
			}
			c.DirectSubnets = append(c.DirectSubnets, s)
			added++
		}
		if added == 0 {
			return "", errNoChange
		}
		return fmt.Sprintf("added %d subnet(s)", added), nil
	})
}

func cmdConfigSubnetRm(path string, args []string) error {
	fs := newFlagSet(path, "<cidr> [more ...]", "remove one or more direct-bypass CIDRs")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fs.Usage()
		return errSilent
	}
	return editConfig(func(c *config.Config) (string, error) {
		removed := 0
		for _, s := range fs.Args() {
			next := removeFold(c.DirectSubnets, strings.TrimSpace(s))
			if len(next) != len(c.DirectSubnets) {
				removed++
			}
			c.DirectSubnets = next
		}
		if removed == 0 {
			return "", errNoChange
		}
		return fmt.Sprintf("removed %d subnet(s)", removed), nil
	})
}

func cmdConfigSubnetList(path string, args []string) error {
	fs := newFlagSet(path, "[--json] [--effective]", "list direct-bypass subnets")
	asJSON := fs.Bool("json", false, "machine-readable output")
	eff := fs.Bool("effective", false, "include subnets contributed by the managed feed (override mode)")
	_ = fs.Parse(args)
	c, err := loadConfig()
	if err != nil {
		return err
	}
	list := c.DirectSubnets
	if *eff {
		list = c.EffectiveSubnets()
	}
	if *asJSON {
		return printJSON(os.Stdout, list)
	}
	if len(list) == 0 {
		fmt.Println("(no direct subnets)")
		return nil
	}
	for _, s := range list {
		fmt.Println(s)
	}
	return nil
}

// --- config load/save plumbing ---

var errNoChange = errors.New("no change")

// loadConfigText returns the current config YAML, preferring the running
// service's copy (canonical) and falling back to the on-disk file.
func loadConfigText() (data []byte, source string, err error) {
	if resp, e := ipcCall(ipc.OpGetConfig, nil, callTimeout); e == nil && resp.OK {
		var text string
		if json.Unmarshal(resp.Data, &text) == nil && strings.TrimSpace(text) != "" {
			return []byte(text), "service", nil
		}
	}
	b, e := os.ReadFile(configFilePath())
	if e != nil {
		return nil, "", fmt.Errorf("read config %s: %w", configFilePath(), e)
	}
	return b, "file", nil
}

// loadConfig loads and leniently parses the current config for read-only use.
func loadConfig() (*config.Config, error) {
	b, _, err := loadConfigText()
	if err != nil {
		return nil, err
	}
	return config.ParseLenient(b), nil
}

// saveConfig persists new YAML: push it to the running service (which validates
// and reloads), falling back to writing the file directly when the service is
// unreachable. A service that is reachable but rejects the config is surfaced as
// an error rather than clobbering the file. Mirrors the panel's save path.
func saveConfig(b []byte) (where string, err error) {
	resp, e := ipcCall(ipc.OpSetConfig, map[string]string{"yaml": string(b)}, callTimeout)
	switch {
	case e == nil && resp.OK:
		return "service (reloaded)", nil
	case e == nil && !resp.OK:
		msg := resp.Error
		if msg == "" {
			msg = "rejected by service"
		}
		return "", fmt.Errorf("service rejected the config: %s", msg)
	}
	// Service unreachable — edit the on-disk file so the next start picks it up.
	if err := os.WriteFile(configFilePath(), b, 0o600); err != nil {
		return "", fmt.Errorf("write config file: %w", err)
	}
	return "file (service not running)", nil
}

// editConfig loads the current config, applies mut, then validates and persists
// the result. mut returns a short summary or errNoChange when nothing changed.
func editConfig(mut func(*config.Config) (string, error)) error {
	b, _, err := loadConfigText()
	if err != nil {
		return err
	}
	c := config.ParseLenient(b) // tolerate an incomplete file; the result is validated below
	managed := c.ConfigManaged()
	msg, err := mut(c)
	if errors.Is(err, errNoChange) {
		fmt.Println("no change")
		return nil
	}
	if err != nil {
		return err
	}
	out, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if _, err := config.Parse(out); err != nil {
		return fmt.Errorf("the edit would make the config invalid: %w", err)
	}
	where, err := saveConfig(out)
	if err != nil {
		return err
	}
	fmt.Printf("%s → %s\n", msg, where)
	if managed && c.MergeMode() == config.MergeReplace {
		fmt.Println("note: this config is managed (replace mode) — local edits may be overwritten on the next fetch")
	}
	return nil
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}

func removeFold(list []string, v string) []string {
	out := list[:0:0]
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			continue
		}
		out = append(out, x)
	}
	return out
}
