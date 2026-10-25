package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func fixtureFile(t *testing.T, dir, name, text string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if e := os.WriteFile(p, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func captureManaged(t *testing.T, run func() error) (string, error) {
	t.Helper()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	old := os.Stdout
	os.Stdout = w
	err := run()
	w.Close()
	os.Stdout = old
	data, _ := io.ReadAll(r)
	r.Close()
	return string(data), err
}
func retargetArgs(t *testing.T, dir, cfg, env, id, panel, token string) []string {
	t.Helper()
	request, _ := json.Marshal(map[string]string{"panel_url": panel, "api_token": token})
	input := fixtureFile(t, dir, "request.json", string(request))
	return []string{"--config", cfg, "--credentials-file", env, "--instance", id, "--input-file", input, "--out-config", filepath.Join(dir, "staged.yml"), "--out-credentials", filepath.Join(dir, "staged.env")}
}
func TestManagedRetargetPreservesOtherBindingsUnknownFieldsAndSharedToken(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "")
	dir := t.TempDir()
	oldToken := "synthetic-old-token"
	newToken := "synthetic-new-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			MachineID int    `json:"machine_id"`
			Token     string `json:"token"`
		}
		if json.NewDecoder(r.Body).Decode(&payload) != nil || r.Method != "POST" || r.URL.Path != "/api/v2/server/machine/nodes" || payload.MachineID != 7 || payload.Token != newToken {
			w.WriteHeader(403)
			return
		}
		io.WriteString(w, `{"nodes":[],"base_config":{}}`)
	}))
	defer srv.Close()
	cfg := fixtureFile(t, dir, "active.yml", `health_port: 0
custom_extension: {keep: untouched}
instances:
  - id: chosen
    panel: {url: 'https://old.example'}
    machine: {machine_id: 7, token_env: SHARED_TOKEN}
    kernel: {type: singbox, config_dir: /private/keep, custom_route: [{action: reject}]}
    custom_setting: preserved
  - id: other
    panel: {url: 'https://other.example', node_id: 5, token_env: SHARED_TOKEN}
`)
	env := fixtureFile(t, dir, "active.env", "# preserved\nSHARED_TOKEN="+oldToken+"\nOTHER_KEY=literal\n")
	args := retargetArgs(t, dir, cfg, env, "chosen", srv.URL, newToken)
	text, e := captureManaged(t, func() error { return runConfigRetarget(args) })
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(text, newToken) || strings.Contains(text, oldToken) {
		t.Fatal("token leaked through command output")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "staged.yml"))
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid staged YAML")
	}
	top := doc.Content[0]
	if yamlField(top, "custom_extension") == nil {
		t.Fatal("unknown root settings lost")
	}
	items := yamlField(top, "instances").Content
	if yamlText(items[0], "id") != "chosen" || yamlText(items[0], "custom_setting") != "preserved" || yamlText(yamlField(items[0], "kernel"), "config_dir") != "/private/keep" {
		t.Fatal("selected identity/data/unknown settings changed")
	}
	if yamlText(yamlField(items[1], "panel"), "url") != "https://other.example" || yamlText(yamlField(items[1], "panel"), "token_env") != "SHARED_TOKEN" {
		t.Fatal("other panel binding changed")
	}
	key := yamlText(yamlField(items[0], "machine"), "token_env")
	data, _ := os.ReadFile(filepath.Join(dir, "staged.env"))
	if key == "SHARED_TOKEN" || !strings.Contains(string(data), "SHARED_TOKEN="+oldToken) || !strings.Contains(string(data), key+"=\""+newToken+"\"") {
		t.Fatal("shared environment key was overwritten")
	}
	active, _ := os.ReadFile(cfg)
	if strings.Contains(string(active), srv.URL) {
		t.Fatal("staging wrote active config")
	}
}
func TestRetargetPrivateCAAndKeptCredential(t *testing.T) {
	dir := t.TempDir()
	token := "synthetic-keep-token"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != token || r.URL.Query().Get("node_id") != "9" || r.URL.Query().Get("node_type") != "hysteria" {
			w.WriteHeader(403)
			return
		}
		io.WriteString(w, `{"protocol":"hysteria","server_port":443}`)
	}))
	defer srv.Close()
	cert, e := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	ca := fixtureFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	t.Setenv("SSL_CERT_FILE", ca)
	cfg := fixtureFile(t, dir, "active.yml", "panel: {url: 'https://old.example', node_id: 9, node_type: hysteria, token_env: NODE_TOKEN}\nkernel: {type: singbox, config_dir: /keep}\n")
	envText := "# retain exactly\nNODE_TOKEN='" + token + "'\n"
	env := fixtureFile(t, dir, "active.env", envText)
	d, e := loadBindings(cfg)
	if e != nil {
		t.Fatal(e)
	}
	args := retargetArgs(t, dir, cfg, env, d.Instances[0].ID, srv.URL, "")
	_, e = captureManaged(t, func() error { return runConfigRetarget(args) })
	if e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "staged.env"))
	if string(data) != envText {
		t.Fatal("unchanged credential file was rewritten")
	}
	after, e := loadBindings(filepath.Join(dir, "staged.yml"))
	if e != nil || after.Instances[0].ID != d.Instances[0].ID {
		t.Fatal("URL edit changed effective instance ID")
	}
}
func TestRetargetAuthFailureAndRedirectNeverCommitOrLeak(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(map[bool]string{false: "auth", true: "redirect"}[redirect], func(t *testing.T) {
			t.Setenv("SSL_CERT_FILE", "")
			dir := t.TempDir()
			token := "synthetic-secret-no-output"
			hits := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; io.WriteString(w, `{"nodes":[]}`) }))
			defer target.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if redirect {
					http.Redirect(w, r, target.URL, 302)
				} else {
					w.WriteHeader(403)
					io.WriteString(w, "private server response "+token)
				}
			}))
			defer srv.Close()
			cfg := fixtureFile(t, dir, "active.yml", "panel: {url: 'https://old.example'}\nmachine: {machine_id: 7, token_env: TOKEN}\n")
			env := fixtureFile(t, dir, "active.env", "TOKEN=old\n")
			d, _ := loadBindings(cfg)
			args := retargetArgs(t, dir, cfg, env, d.Instances[0].ID, srv.URL, token)
			text, e := captureManaged(t, func() error { return runConfigRetarget(args) })
			if e == nil || strings.Contains(e.Error()+text, token) || strings.Contains(e.Error(), "private server response") || hits != 0 {
				t.Fatal("invalid response accepted, redirected credentials, or leaked error body")
			}
			if _, e := os.Stat(filepath.Join(dir, "staged.yml")); !os.IsNotExist(e) {
				t.Fatal("failed preflight produced staged config")
			}
		})
	}
}
func TestRetargetRejectsUnsafeURLsAndAmbiguousYAML(t *testing.T) {
	for _, raw := range []string{"http://external.example", "https://user:password@panel.example", "https://panel.example?token=secret", "https://panel.example/#fragment", "https://panel.example:99999", "https://panel.example\n"} {
		if _, e := safeConfigURL(raw); e == nil {
			t.Fatalf("unsafe URL accepted: %q", raw)
		}
	}
	dir := t.TempDir()
	for _, data := range []string{
		"panel: {url: 'https://x', url: 'https://y', node_id: 1}",
		"template: &p {url: 'https://x', node_id: 1}\npanel: *p",
		"identity: &identity stable-binding\nid: *identity\npanel: {url: 'https://x', node_id: 1}",
		"template: &p {url: 'https://x', node_id: 1}\npanel: {<<: *p}",
		"panel: {url: 'https://x', node_id: 1}\n---\ncustom: preserve-me",
		"instances: []",
	} {
		p := fixtureFile(t, dir, "bad.yml", data)
		if _, e := loadBindings(p); e == nil {
			t.Fatal("ambiguous config accepted")
		}
	}
}
func TestInspectDoesNotExposeInlineCredentials(t *testing.T) {
	dir := t.TempDir()
	cfg := fixtureFile(t, dir, "active.yml", "panel: {url: 'https://panel.example', token: never-print-this-value, node_id: 1}\n")
	text, e := captureManaged(t, func() error { return runConfigInspect([]string{"--config", cfg}) })
	if e != nil || strings.Contains(text, "never-print-this-value") {
		t.Fatal("inspect exposed credential")
	}
}
