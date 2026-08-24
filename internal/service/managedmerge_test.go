//go:build windows

package service

import (
	"testing"

	"socksit/internal/config"
)

// TestOverrideMergeMirrorsFeedDomains: in override mode the feed's names land in
// managed_domains and the user's own list is untouched — the same contract apps
// and subnets already have.
func TestOverrideMergeMirrorsFeedDomains(t *testing.T) {
	local := config.Default()
	local.Proxy.Address = "10.0.0.1"
	local.DirectDomains = []string{"agent-gw.example.com"}
	local.ConfigSource.URL = "https://cfg.example/socksit.yaml"
	local.ConfigSource.Merge = config.MergeOverride

	feed := []byte("proxy:\n  address: 10.9.9.9\n  port: 1080\nmode: allowlist\napps: [claude.exe]\ndirect_domains: [.corp.example]\n")
	merged, err := mergeManagedConfig(local, feed)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(merged.DirectDomains) != 1 || merged.DirectDomains[0] != "agent-gw.example.com" {
		t.Errorf("the user's own names must survive the merge, got %v", merged.DirectDomains)
	}
	if len(merged.ManagedDomains) != 1 || merged.ManagedDomains[0] != ".corp.example" {
		t.Errorf("the feed's names must land in managed_domains, got %v", merged.ManagedDomains)
	}

	// A feed that says nothing about names must not clear what it contributed
	// before — an older server simply has no opinion.
	local.ManagedDomains = []string{".corp.example"}
	silent := []byte("proxy:\n  address: 10.9.9.9\n  port: 1080\nmode: allowlist\napps: [claude.exe]\n")
	merged, err = mergeManagedConfig(local, silent)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(merged.ManagedDomains) != 1 {
		t.Errorf("a silent feed must not drop the names it contributed, got %v", merged.ManagedDomains)
	}
}

// TestReplaceModeKeepsLocalNetworkFacts covers the failure that cost real
// downtime: replace mode rebuilds the config from the feed, so anything the feed
// does not carry falls back to defaults. For these two that is not a reset, it is
// an outage — bypass_cidrs describes the router in front of THIS machine, and
// direct_domains is where the endpoint that refuses the proxy lives.
func TestReplaceModeKeepsLocalNetworkFacts(t *testing.T) {
	local := config.Default()
	local.BypassCIDRs = []string{"198.18.0.0/15"} // a FakeIP router in front of us
	local.DirectDomains = []string{"agent-gw.example.com"}

	feed := []byte("proxy:\n  address: 10.9.9.9\n  port: 1080\nmode: allowlist\napps: [claude.exe]\n")
	fresh := config.Default()
	keepLocalNetworkFacts(fresh, local, feed)
	if len(fresh.BypassCIDRs) != 1 || fresh.BypassCIDRs[0] != "198.18.0.0/15" {
		t.Errorf("bypass_cidrs must survive a refresh, got %v", fresh.BypassCIDRs)
	}
	if len(fresh.DirectDomains) != 1 || fresh.DirectDomains[0] != "agent-gw.example.com" {
		t.Errorf("a silent feed must leave the local names alone, got %v", fresh.DirectDomains)
	}

	// When the feed DOES carry names, replace mode means replace.
	withDomains := []byte("proxy:\n  address: 10.9.9.9\n  port: 1080\nmode: allowlist\ndirect_domains: [.corp.example]\n")
	fresh = config.Default()
	fresh.DirectDomains = []string{".corp.example"} // as parsed from the feed
	keepLocalNetworkFacts(fresh, local, withDomains)
	if len(fresh.DirectDomains) != 1 || fresh.DirectDomains[0] != ".corp.example" {
		t.Errorf("the feed's names must win when it sets them, got %v", fresh.DirectDomains)
	}
}
