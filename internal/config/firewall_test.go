package config

import "testing"

func TestManagedInputRequiresLocalEnvironmentGrant(t *testing.T) {
	for _, env := range []string{"", "0", "true", " 1", "1"} {
		for _, local := range []*bool{nil, firewallBool(false), firewallBool(true)} {
			t.Setenv("XBOARD_NODE_MANAGED_INPUT", env)
			cfg := &Config{Firewall: FirewallConfig{ManagedInput: local}}
			want := env == "1" && (local == nil || *local)
			if got := cfg.ManagedInputEnabled(); got != want {
				t.Fatalf("env=%q local=%v enabled=%v want=%v", env, local, got, want)
			}
		}
	}
}

func firewallBool(v bool) *bool { return &v }

func TestFirewallOptOutInheritsLocallyAndSurvivesNodeExpansion(t *testing.T) {
	t.Setenv("XBOARD_NODE_MANAGED_INPUT", "1")
	path := writeTemp(t, `firewall: {managed_input: false}
instances:
  - id: first
    panel: {url: "https://panel.example.com", token: fixture, node_id: 1}
    nodes: [{node_id: 1}, {node_id: 2}]
  - id: second
    panel: {url: "https://panel.example.com", token: fixture, node_id: 3}
    firewall: {managed_input: true}
`)
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range instances[0].ExpandNodes() {
		if node.ManagedInputEnabled() {
			t.Fatal("expanded node lost local opt-out")
		}
	}
	if !instances[1].ManagedInputEnabled() {
		t.Fatal("explicit local instance setting not retained")
	}
	instances[0].Machine = &MachineConfig{MachineID: 1, Token: "fixture"}
	machine := instances[0].ExpandMachineNode(9, "hysteria")
	if machine.ManagedInputEnabled() {
		t.Fatal("machine node lost local opt-out")
	}
}

func TestYAMLTrueAloneCannotEnableManagedInput(t *testing.T) {
	t.Setenv("XBOARD_NODE_MANAGED_INPUT", "")
	cfg, err := Load(writeTemp(t, `panel: {url: "https://panel.example.com", token: fixture, node_id: 1}
firewall: {managed_input: true}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ManagedInputEnabled() {
		t.Fatal("configuration granted firewall privileges without unit opt-in")
	}
}
