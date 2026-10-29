package main

import (
	"github.com/cedar2025/xboard-node/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStandardServiceManagedInputAndOptOut(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		unit := renderServiceFile(enabled)
		parsed, err := managedInputFromUnit(unit)
		if err != nil || parsed != enabled {
			t.Fatalf("unit policy roundtrip: %v %v", parsed, err)
		}
		for _, required := range []string{"KillMode=control-group", "TimeoutStopSec=30", "NoNewPrivileges=true"} {
			if !strings.Contains(unit, required) {
				t.Fatalf("missing %s", required)
			}
		}
	}
	if enabled, err := managedInputFromUnit("[Service]\nExecStart=fixture\n"); err != nil || !enabled {
		t.Fatal("old standard unit did not migrate to managed INPUT")
	}
	for _, unit := range []string{"Environment=XBOARD_NODE_MANAGED_INPUT=2", "Environment=XBOARD_NODE_MANAGED_INPUT=0\nEnvironment=XBOARD_NODE_MANAGED_INPUT=1"} {
		if _, err := managedInputFromUnit(unit); err == nil {
			t.Fatal("ambiguous policy accepted")
		}
	}
}

func TestBindingRewritePreservesLocalFirewallOptOut(t *testing.T) {
	value := false
	root := &config.RootConfig{Config: config.Config{Firewall: config.FirewallConfig{ManagedInput: &value}},
		Instances: []config.Config{{InstanceID: "fixture", Panel: config.PanelConfig{URL: "https://panel.example.com", Token: "fixture", NodeID: 1},
			Firewall: config.FirewallConfig{ManagedInput: &value}}}}
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "managed_input: false") != 2 {
		t.Fatal("local opt-out lost during binding rewrite")
	}
}
