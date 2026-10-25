package model

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestPortHoppingPanelRoundTripAndIsolation(t *testing.T) {
	input := &panel.NodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 443, PortHopping: &panel.PortHopping{Start: 20000, End: 20100}}
	spec, err := NodeSpecFromPanelValidated(input, config.KernelConfig{Type: "singbox"})
	if err != nil {
		t.Fatal(err)
	}
	input.PortHopping.Start = 1
	if spec.PortHopping.Start != 20000 {
		t.Fatal("panel and model share mutable hopping config")
	}
	output := spec.ToPanel()
	output.PortHopping.End = 1
	if spec.PortHopping.End != 20100 {
		t.Fatal("model and output share mutable hopping config")
	}
	if NodeSpecFromPanel(&panel.NodeConfig{}).PortHopping != nil {
		t.Fatal("old panel config enables forwarding")
	}
}

func TestPortHoppingStandaloneAndValidation(t *testing.T) {
	cfg := &config.Config{Standalone: &config.StandaloneConfig{Node: config.StandaloneNodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 443, PortHopping: &config.PortHopping{Start: 20000, End: 20100}}}}
	spec := NodeSpecFromStandalone(cfg)
	if err := ValidatePortHopping(spec); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*NodeSpec){
		"protocol": func(n *NodeSpec) { n.Protocol = "vless" },
		"version":  func(n *NodeSpec) { n.Version = 1 },
		"zero":     func(n *NodeSpec) { n.PortHopping.Start = 0 },
		"overflow": func(n *NodeSpec) { n.PortHopping.End = 65536 },
		"reversed": func(n *NodeSpec) { n.PortHopping.Start = 20200 },
		"listener": func(n *NodeSpec) { n.ServerPort = -1 },
		"address":  func(n *NodeSpec) { n.ListenIP = "127.0.0.1;flush ruleset" },
	} {
		t.Run(name, func(t *testing.T) {
			n := *spec
			n.PortHopping = spec.PortHopping.Clone()
			change(&n)
			if ValidatePortHopping(&n) == nil {
				t.Fatal("invalid privileged forwarding request accepted")
			}
		})
	}
}
