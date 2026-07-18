package main

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"socksit/internal/config"
)

// TestBuildCLIWellFormed checks the command tree is structurally sound: every
// node is a leaf xor a group, sibling names/aliases are unique, and the hidden
// machine entrypoints and back-compat aliases are present.
func TestBuildCLIWellFormed(t *testing.T) {
	root := buildCLI()
	var walk func(path string, c *command)
	walk = func(path string, c *command) {
		leaf := c.Run != nil
		group := len(c.Children) > 0
		if leaf == group {
			t.Errorf("%s%s: must be exactly one of leaf(Run) or group(Children)", path, c.Name)
		}
		seen := map[string]string{}
		for _, ch := range c.Children {
			for _, name := range append([]string{ch.Name}, ch.Aliases...) {
				if prev, ok := seen[name]; ok {
					t.Errorf("%s%s: duplicate child name/alias %q (also on %q)", path, c.Name, name, prev)
				}
				seen[name] = ch.Name
			}
			walk(path+c.Name+" ", ch)
		}
	}
	walk("", root)

	for _, name := range []string{"service", "update-restart", "gen", "check"} {
		ch := findChild(root, name)
		if ch == nil {
			t.Errorf("expected hidden command %q to exist", name)
			continue
		}
		if !ch.Hidden {
			t.Errorf("command %q should be Hidden", name)
		}
	}
}

func TestFindChildAliases(t *testing.T) {
	root := buildCLI()
	for _, tc := range []struct{ query, want string }{
		{"version", "version"},
		{"-v", "version"},
		{"--version", "version"},
		{"status", "status"},
		{"check", "check"}, // hidden alias still resolvable
	} {
		if got := findChild(root, tc.query); got == nil || got.Name != tc.want {
			t.Errorf("findChild(%q) = %v, want %q", tc.query, got, tc.want)
		}
	}
	if findChild(root, "nope") != nil {
		t.Error("findChild(nope) should be nil")
	}
}

func TestGroupHelpOmitsHidden(t *testing.T) {
	var buf bytes.Buffer
	printGroupHelp(rootName, buildCLI(), &buf)
	out := buf.String()
	if !strings.Contains(out, "install") || !strings.Contains(out, "doctor") {
		t.Error("help should list visible commands")
	}
	// "update-restart" is a unique token that must not appear in the listing.
	if strings.Contains(out, "update-restart") {
		t.Error("help must not list the hidden update-restart command")
	}
}

func TestFoldHelpers(t *testing.T) {
	list := []string{"Firefox.exe", "chrome.exe"}
	if !containsFold(list, "firefox.exe") {
		t.Error("containsFold should be case-insensitive")
	}
	if containsFold(list, "edge.exe") {
		t.Error("containsFold false positive")
	}
	got := removeFold(list, "CHROME.EXE")
	if len(got) != 1 || got[0] != "Firefox.exe" {
		t.Errorf("removeFold = %v, want [Firefox.exe]", got)
	}
	if len(removeFold(list, "missing")) != 2 {
		t.Error("removeFold of a missing item should keep the list")
	}
}

// TestConfigEditRoundTrip guards the core of editConfig: a valid config that is
// parsed, mutated, re-marshalled and re-parsed must stay valid and carry the edit.
func TestConfigEditRoundTrip(t *testing.T) {
	src := "proxy: {address: 10.0.0.1, port: 1080}\napps: [a.exe]\nmode: allowlist\n"
	c, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	c.Apps = append(c.Apps, "b.exe")
	out, err := yaml.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := config.Parse(out)
	if err != nil {
		t.Fatalf("re-parse edited config: %v", err)
	}
	if !containsFold(got.Apps, "a.exe") || !containsFold(got.Apps, "b.exe") {
		t.Errorf("round-trip lost apps: %v", got.Apps)
	}
}
