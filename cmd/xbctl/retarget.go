package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"gopkg.in/yaml.v3"
)

// This editor stages a surgical YAML change. It never stops a service or writes
// the active files; the installer owns the locked backup/commit/rollback.
type managedBinding struct {
	ID            string `json:"id"`
	PanelURL      string `json:"panel_url"`
	Mode          string `json:"mode"`
	NodeID        int    `json:"node_id,omitempty"`
	MachineID     int    `json:"machine_id,omitempty"`
	NodeIDs       []int  `json:"node_ids,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	node          *yaml.Node
	inline        string
}
type bindingDocument struct {
	Instances  []managedBinding `json:"instances"`
	HealthPort int              `json:"health_port"`
	root       yaml.Node
}

func yamlField(n *yaml.Node, name string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			return n.Content[i+1]
		}
	}
	return nil
}
func yamlText(n *yaml.Node, name string) string {
	v := yamlField(n, name)
	if v == nil {
		return ""
	}
	return v.Value
}
func yamlSet(n *yaml.Node, name, value string) {
	if v := yamlField(n, name); v != nil {
		v.Kind = yaml.ScalarNode
		v.Tag = "!!str"
		v.Value = value
		v.Content = nil
		return
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}
func yamlDelete(n *yaml.Node, name string) {
	if n == nil {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return
		}
	}
}
func yamlMapping(n *yaml.Node, key string) (*yaml.Node, error) {
	v := yamlField(n, key)
	if v == nil {
		v = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
	}
	if v.Kind != yaml.MappingNode {
		return nil, errors.New("aliased or non-mapping binding fields require manual configuration")
	}
	return v, nil
}
func checkYAML(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode {
		return errors.New("YAML aliases require manual configuration")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" || k.Value == "<<" || seen[k.Value] {
				return errors.New("duplicate or complex YAML mapping keys require manual configuration")
			}
			seen[k.Value] = true
		}
	}
	for _, v := range n.Content {
		if err := checkYAML(v); err != nil {
			return err
		}
	}
	return nil
}
func safeConfigURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\x00") {
		return "", errors.New("panel URL must be an HTTPS base URL without credentials, query or fragment")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return "", errors.New("panel authentication requires HTTPS; HTTP is allowed only on loopback")
		}
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return "", errors.New("invalid panel port")
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}
func readManagedFile(path string, secret bool, optional bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && optional {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("required managed file is unavailable")
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return nil, errors.New("managed input must be a regular file no larger than 4 MiB")
	}
	if runtime.GOOS != "windows" && ((secret && info.Mode().Perm()&0077 != 0) || info.Mode().Perm()&0022 != 0) {
		return nil, errors.New("managed credentials/input must be private 0600 and config must not be writable by other users")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read managed input")
	}
	return data, nil
}
func loadBindings(path string) (*bindingDocument, error) {
	data, err := readManagedFile(path, false, false)
	if err != nil {
		return nil, err
	}
	d := &bindingDocument{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&d.root) != nil || len(d.root.Content) != 1 || d.root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("invalid managed YAML configuration")
	}
	if decoder.Decode(new(yaml.Node)) != io.EOF {
		return nil, errors.New("multiple YAML documents require manual configuration")
	}
	if err := checkYAML(&d.root); err != nil {
		return nil, err
	}
	top := d.root.Content[0]
	if h := yamlField(top, "health_port"); h != nil {
		d.HealthPort, _ = strconv.Atoi(h.Value)
	}
	items := []*yaml.Node{top}
	if list := yamlField(top, "instances"); list != nil {
		if list.Kind != yaml.SequenceNode || len(list.Content) == 0 {
			return nil, errors.New("instances must be a non-empty list")
		}
		items = list.Content
	}
	seen := map[string]bool{}
	for _, n := range items {
		if n.Kind != yaml.MappingNode {
			return nil, errors.New("aliased instances require manual configuration")
		}
		panel := yamlField(n, "panel")
		if panel == nil || panel.Kind != yaml.MappingNode {
			return nil, errors.New("panel binding is missing or aliased")
		}
		b := managedBinding{PanelURL: yamlText(panel, "url"), Mode: "node", node: n, CredentialRef: yamlText(panel, "token_env"), inline: yamlText(panel, "token")}
		// Existing HTTP installations may be inspected without changing policy.
		if u, e := url.Parse(b.PanelURL); e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
			return nil, errors.New("existing panel URL contains unsafe/ambiguous fields")
		}
		if s := yamlField(n, "standalone"); s != nil && yamlText(s, "enabled") == "true" {
			return nil, errors.New("standalone nodes have no panel binding to edit")
		}
		cfg := config.Config{Panel: config.PanelConfig{URL: b.PanelURL}}
		if machine := yamlField(n, "machine"); machine != nil {
			if machine.Kind != yaml.MappingNode {
				return nil, errors.New("aliased machine binding requires manual configuration")
			}
			b.Mode = "machine"
			b.MachineID, _ = strconv.Atoi(yamlText(machine, "machine_id"))
			b.CredentialRef = yamlText(machine, "token_env")
			b.inline = yamlText(machine, "token")
			cfg.Machine = &config.MachineConfig{MachineID: b.MachineID}
			if b.MachineID <= 0 {
				return nil, errors.New("invalid machine ID")
			}
		} else if nodes := yamlField(n, "nodes"); nodes != nil {
			if nodes.Kind != yaml.SequenceNode {
				return nil, errors.New("invalid node list")
			}
			for _, row := range nodes.Content {
				id, e := strconv.Atoi(yamlText(row, "node_id"))
				if e != nil || id < 1 {
					return nil, errors.New("invalid node ID")
				}
				b.NodeIDs = append(b.NodeIDs, id)
				cfg.Nodes = append(cfg.Nodes, config.NodeEntry{NodeID: id})
			}
		} else {
			b.NodeID, _ = strconv.Atoi(yamlText(panel, "node_id"))
			cfg.Panel.NodeID = b.NodeID
			if b.NodeID < 1 {
				return nil, errors.New("invalid node ID")
			}
		}
		b.ID = yamlText(n, "id")
		if b.ID == "" {
			b.ID, err = cfg.AutoInstanceID()
			if err != nil {
				return nil, errors.New("cannot identify panel binding")
			}
		}
		if seen[b.ID] {
			return nil, errors.New("duplicate binding IDs require manual configuration")
		}
		if len(b.ID) > 240 || b.ID == "." || b.ID == ".." {
			return nil, errors.New("unsafe instance ID requires manual configuration")
		}
		for _, ch := range b.ID {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-') {
				return nil, errors.New("unsafe instance ID requires manual configuration")
			}
		}
		seen[b.ID] = true
		d.Instances = append(d.Instances, b)
	}
	return d, nil
}

func managedFlags(name string, args []string) (*flag.FlagSet, *string, *string) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	cfg := f.String("config", defaultConfigPath, "")
	creds := f.String("credentials-file", defaultCredentialsPath, "")
	return f, cfg, creds
}
func runConfigInspect(args []string) error {
	f, path, _ := managedFlags("inspect", args)
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("usage: xbctl config inspect --config PATH [--credentials-file PATH]")
	}
	d, e := loadBindings(*path)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(d)
}
func credentialValue(data []byte, key string) (string, error) {
	var found string
	seen := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		if seen {
			return "", errors.New("duplicate credential key requires manual configuration")
		}
		seen = true
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "\"") {
			s, e := strconv.Unquote(v)
			if e != nil {
				return "", errors.New("unsupported quoted credential")
			}
			v = s
		} else if strings.HasPrefix(v, "'") {
			if len(v) < 2 || !strings.HasSuffix(v, "'") {
				return "", errors.New("unsupported quoted credential")
			}
			v = v[1 : len(v)-1]
		}
		found = v
	}
	if !seen {
		return "", errors.New("selected token environment reference is missing from credentials.env")
	}
	return found, nil
}
func validToken(token string) bool {
	if len(token) == 0 || len(token) > 4096 {
		return false
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func nextCredential(data []byte, id string) string {
	h := sha256.Sum256([]byte(id))
	stem := "XBOARD_NODE_TOKEN_" + strings.ToUpper(hex.EncodeToString(h[:8]))
	keys := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			keys[strings.TrimSpace(k)] = true
		}
	}
	for i := 0; ; i++ {
		key := stem
		if i > 0 {
			key += "_" + strconv.Itoa(i)
		}
		if !keys[key] {
			return key
		}
	}
}
func writeManagedStage(path string, data []byte) error {
	if path == "" {
		return errors.New("all staging output paths are required")
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("staging output already exists or cannot be created")
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, e = f.Write(data); e != nil {
		return errors.New("cannot write private staging output")
	}
	if e = f.Sync(); e != nil {
		return errors.New("cannot sync staging output")
	}
	if e = f.Close(); e != nil {
		return errors.New("cannot close staging output")
	}
	ok = true
	return nil
}
func runConfigRetarget(args []string) error {
	f, path, credentialFile := managedFlags("retarget", args)
	instance := f.String("instance", "", "")
	input := f.String("input-file", "", "")
	out := f.String("out-config", "", "")
	envOut := f.String("out-credentials", "", "")
	meta := f.String("meta-file", "", "")
	metaOut := f.String("out-meta", "", "")
	if f.Parse(args) != nil || f.NArg() != 0 || *instance == "" || *input == "" || *out == "" || *envOut == "" {
		return errors.New("retarget requires instance, private input and distinct staging output paths")
	}
	d, err := loadBindings(*path)
	if err != nil {
		return err
	}
	selected := -1
	for i, b := range d.Instances {
		if b.ID == *instance {
			selected = i
		}
	}
	if selected < 0 {
		return errors.New("selected binding no longer exists")
	}
	private, err := readManagedFile(*input, true, false)
	if err != nil {
		return err
	}
	var request struct {
		PanelURL string `json:"panel_url"`
		Token    string `json:"api_token"`
	}
	dec := json.NewDecoder(bytes.NewReader(private))
	dec.DisallowUnknownFields()
	if dec.Decode(&request) != nil {
		return errors.New("invalid private change request")
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("trailing private request data")
	}
	credentials, err := readManagedFile(*credentialFile, true, true)
	if err != nil {
		return err
	}
	b := &d.Instances[selected]
	newURL := strings.TrimSpace(request.PanelURL)
	if newURL == "" {
		newURL = b.PanelURL
	}
	newURL, err = safeConfigURL(newURL)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(request.Token)
	if request.Token != "" && token == "" {
		return errors.New("a whitespace-only token is invalid; leave the input empty to preserve it")
	}
	if token == "" {
		token = b.inline
		if token == "" && b.CredentialRef != "" {
			token, err = credentialValue(credentials, b.CredentialRef)
			if err != nil {
				return err
			}
		}
	}
	if !validToken(token) {
		return errors.New("token must be a non-empty printable value without whitespace")
	}
	if err := preflightBinding(context.Background(), newURL, token, *b); err != nil {
		return err
	}
	panel, err := yamlMapping(b.node, "panel")
	if err != nil {
		return err
	}
	yamlSet(panel, "url", newURL)
	// Persist the previous effective identity so URL edits cannot relocate data
	// directories or change ownership of automatic UDP rules.
	yamlSet(b.node, "id", b.ID)
	if request.Token != "" {
		key := nextCredential(credentials, b.ID)
		active := panel
		if b.Mode == "machine" {
			active, err = yamlMapping(b.node, "machine")
			if err != nil {
				return err
			}
		}
		yamlDelete(active, "token")
		yamlSet(active, "token_env", key)
		b.CredentialRef = key
		credentials = append(bytes.TrimRight(credentials, "\n"), '\n')
		credentials = append(credentials, []byte(key+"="+strconv.Quote(token)+"\n")...)
	}
	b.PanelURL = newURL
	encoded, err := yaml.Marshal(&d.root)
	if err != nil {
		return errors.New("cannot encode staged configuration")
	}
	// All artifacts are written only after successful authentication. They must
	// be new files in the caller's private transaction directory.
	paths := []string{*out, *envOut}
	if *metaOut != "" {
		paths = append(paths, *metaOut)
	}
	seen := map[string]bool{}
	for _, p := range append(paths, *path, *credentialFile, *input) {
		a, e := filepath.Abs(p)
		if e != nil || seen[a] {
			return errors.New("staging paths must be distinct from all active inputs")
		}
		seen[a] = true
	}
	if err := writeManagedStage(*out, encoded); err != nil {
		return err
	}
	if err := writeManagedStage(*envOut, credentials); err != nil {
		os.Remove(*out)
		return err
	}
	if *metaOut != "" {
		m := map[string]any{}
		if *meta != "" {
			raw, e := readManagedFile(*meta, false, true)
			if e != nil {
				return e
			}
			if len(raw) > 0 && json.Unmarshal(raw, &m) != nil {
				return errors.New("invalid install metadata")
			}
		}
		items := []map[string]any{}
		for _, row := range d.Instances {
			items = append(items, map[string]any{"id": row.ID, "panel_url": row.PanelURL, "mode": row.Mode, "node_id": row.NodeID, "machine_id": row.MachineID})
		}
		m["instances"] = items
		m["instance_count"] = len(items)
		m["latest_instance_id"] = b.ID
		m["updated_at"] = time.Now().UTC().Format(time.RFC3339)
		raw, _ := json.MarshalIndent(m, "", "  ")
		if err := writeManagedStage(*metaOut, append(raw, '\n')); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "staged", "instance_id": b.ID, "panel_url": b.PanelURL, "mode": b.Mode, "credential_ref": b.CredentialRef})
}

func preflightBinding(ctx context.Context, base, token string, b managedBinding) error {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return errors.New("system/private certificate trust is unavailable")
	}
	if file := os.Getenv("SSL_CERT_FILE"); file != "" {
		pem, e := os.ReadFile(file)
		if e != nil || !roots.AppendCertsFromPEM(pem) {
			return errors.New("stored private/public CA bundle cannot be loaded; existing configuration was not changed")
		}
	}
	client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Proxy: http.ProxyFromEnvironment}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	request := func(method, path string, body any) (map[string]json.RawMessage, int, error) {
		var r io.Reader
		if body != nil {
			data, _ := json.Marshal(body)
			r = bytes.NewReader(data)
		}
		req, e := http.NewRequestWithContext(ctx, method, base+path, r)
		if e != nil {
			return nil, 0, errors.New("invalid panel preflight request")
		}
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			return nil, 0, errors.New("new panel connection/TLS verification failed; existing configuration was not changed")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, res.StatusCode, nil
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, 1<<20+1))
		if e != nil || len(raw) > 1<<20 {
			return nil, 200, errors.New("invalid panel response size")
		}
		var data map[string]json.RawMessage
		if json.Unmarshal(raw, &data) != nil || data == nil {
			return nil, 200, errors.New("new address did not return a panel API response")
		}
		return data, 200, nil
	}
	if b.Mode == "machine" {
		data, status, e := request("POST", "/api/v2/server/machine/nodes", map[string]any{"machine_id": b.MachineID, "token": token})
		if e != nil {
			return e
		}
		if status != 200 {
			return fmt.Errorf("new panel machine authentication failed (HTTP %d); existing configuration was not changed", status)
		}
		var nodes []json.RawMessage
		if json.Unmarshal(data["nodes"], &nodes) != nil {
			return errors.New("new panel did not return a valid machine node list")
		}
		return nil
	}
	ids := b.NodeIDs
	if len(ids) == 0 {
		ids = []int{b.NodeID}
	}
	for _, id := range ids {
		q := url.Values{"node_id": {strconv.Itoa(id)}, "token": {token}}
		if typ := yamlText(yamlField(b.node, "panel"), "node_type"); typ != "" {
			q.Set("node_type", typ)
		}
		data, status, e := request("GET", "/api/v1/server/UniProxy/config?"+q.Encode(), nil)
		if e != nil {
			return e
		}
		if status != 200 {
			return fmt.Errorf("new panel node authentication failed (HTTP %d); existing configuration was not changed", status)
		}
		var protocol string
		if json.Unmarshal(data["protocol"], &protocol) != nil || protocol == "" {
			return errors.New("new panel did not return a valid node configuration")
		}
	}
	return nil
}
