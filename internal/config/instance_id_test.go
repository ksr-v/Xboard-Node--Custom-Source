package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitBindingIdentitySurvivesPanelAddressChange(t *testing.T) {
	for _, multi := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yml")
		text := "id: stable-binding\npanel: {url: https://new.example, node_id: 7, token: synthetic-config-token}\nkernel: {type: singbox}\n"
		if multi {
			text = "instances:\n  - id: stable-binding\n    panel: {url: https://new.example, node_id: 7, token: synthetic-config-token}\n    kernel: {type: singbox}\n"
		}
		if e := os.WriteFile(path, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		root, e := LoadRoot(path)
		if e != nil {
			t.Fatal(e)
		}
		instances, e := root.NormalizeInstances()
		if e != nil || instances[0].InstanceID != "stable-binding" {
			t.Fatal("explicit identity was recomputed after URL change")
		}
	}
}

func TestExplicitBindingIdentityRejectsDirectoryTraversal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	text := "id: ../outside\npanel: {url: https://example.test, node_id: 7, token: synthetic-config-token}\nkernel: {type: singbox}\n"
	if e := os.WriteFile(path, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadRoot(path); e == nil {
		t.Fatal("unsafe explicit data-directory identity accepted")
	}
}
