package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
)

type addressTransport func(*http.Request) (*http.Response, error)

func init() { hostIPv4.lookup = func() string { return "" } } // Unit tests never contact IP.SB implicitly.

func TestIPv4LiveProvider(t *testing.T) {
	if os.Getenv("FLOWSCOPE_TEST_LIVE_IP") != "1" {
		t.Skip("live workstation IP.SB test is opt-in")
	}
	if !publicIPv4(lookupIPv4()) {
		t.Fatal("live direct IPv4 lookup did not return a public address")
	}
}

func (f addressTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPublicIPv4(t *testing.T) {
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"} {
		if !publicIPv4(value) {
			t.Errorf("public address rejected: %s", value)
		}
	}
	for _, value := range []string{"", "garbage", "1.2.3.4\n1.2.3.5", "01.2.3.4", "::ffff:8.8.8.8", "::1", "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.168.1.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255"} {
		if publicIPv4(value) {
			t.Errorf("nonpublic/malformed address accepted: %s", value)
		}
	}
}

func TestHostIPv4SharedCacheFailureExpiryRecovery(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	result := "8.8.8.8"
	host := &ipv4Cache{lookup: func() string { calls.Add(1); return result }}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ip, age := host.get(now); ip != "8.8.8.8" || age != 0 {
				t.Error("shared result mismatch")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("parallel instances probed %d times", calls.Load())
	}
	result = ""
	if ip, _ := host.get(now.Add(12 * time.Hour)); ip != "8.8.8.8" {
		t.Fatal("transient failure erased cached success")
	}
	host.get(now.Add(12*time.Hour + time.Minute))
	if calls.Load() != 2 {
		t.Fatal("failed probe retried too frequently")
	}
	if ip, _ := host.get(now.Add(24 * time.Hour)); ip != "" {
		t.Fatal("expired result still reportable")
	}
	result = "1.1.1.1"
	if ip, age := host.get(now.Add(24*time.Hour + 5*time.Minute)); ip != "1.1.1.1" || age != 0 {
		t.Fatal("lookup did not recover")
	}
}

func TestLookupIPv4RequestAndValidation(t *testing.T) {
	old := ipClient
	defer func() { ipClient = old }()
	for _, tc := range []struct {
		status     int
		body, want string
	}{
		{200, "8.8.4.4\n", "8.8.4.4"}, {200, "192.168.0.1", ""}, {200, "2001:db8::1", ""},
		{200, "8.8.8.8<script>", ""}, {200, strings.Repeat("x", 66), ""}, {302, "8.8.8.8", ""}, {500, "8.8.8.8", ""},
	} {
		ipClient = &http.Client{Transport: addressTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://api-ipv4.ip.sb/ip" || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" || r.Body != nil {
				t.Error("detector request leaked identity or changed target")
			}
			if r.Header.Get("User-Agent") == "" {
				t.Error("missing detector UA")
			}
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
		})}
		if got := lookupIPv4(); got != tc.want {
			t.Errorf("lookup(%d,%q)=%q", tc.status, tc.body, got)
		}
	}
}

func TestIPv4TransportSecurity(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	c := ipv4HTTPClient()
	tr := c.Transport.(*http.Transport)
	if tr.Proxy != nil || c.Timeout != 3*time.Second || tr.TLSClientConfig != nil {
		t.Fatal("proxy/TLS/timeout defaults changed")
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("8.8.8.8")) }))
	defer ts.Close()
	if _, err := c.Get(ts.URL); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	// The production tcp4 dialer refuses an IPv6-only destination.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := tr.DialContext(ctx, "tcp", "[::1]:1"); err == nil {
		conn.Close()
		t.Fatal("IPv6 dial accepted")
	}
	if err := c.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatal("redirect allowed")
	}
	tr.CloseIdleConnections()
}

func cachedHost() *ipv4Cache {
	now := time.Now()
	return &ipv4Cache{ip: "8.8.4.4", observed: now.Add(-time.Minute), next: now.Add(time.Hour), lookup: func() string { return "" }}
}

func TestAddressStatusClassificationAndExistingAuth(t *testing.T) {
	for _, mode := range []string{"node", "machine"} {
		for _, tc := range []struct {
			status int
			delay  time.Duration
			failed bool
		}{
			{200, time.Hour, false}, {404, 10 * time.Minute, false}, {405, 10 * time.Minute, false},
			{401, 15 * time.Minute, false}, {403, 15 * time.Minute, false}, {429, 2 * time.Minute, false}, {503, 0, true},
		} {
			t.Run(mode+"/"+http.StatusText(tc.status), func(t *testing.T) {
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "POST" || r.URL.Path != addressPath || r.URL.RawQuery != "" {
						t.Error("wrong optional endpoint")
					}
					var p map[string]interface{}
					json.NewDecoder(r.Body).Decode(&p)
					if p["token"] != "bound-secret" || p["ipv4"] != "8.8.4.4" || p["age_seconds"].(float64) < 60 {
						t.Error("auth/observation not reused")
					}
					if mode == "machine" {
						if p["machine_id"] != float64(41) || p["node_id"] != nil {
							t.Error("wrong machine identity")
						}
					} else {
						if p["node_id"] != float64(7) || p["machine_id"] != nil {
							t.Error("node claimed machine")
						}
					}
					w.Header().Set("Retry-After", "120")
					w.WriteHeader(tc.status)
					w.Write([]byte(`{"data":{"accepted":true,"protocol":1}}`))
				}))
				defer ts.Close()
				cfg := config.PanelConfig{URL: ts.URL, Token: "bound-secret", NodeID: 7}
				if mode == "machine" {
					cfg.NodeID = 0
					cfg.MachineID = 41
				}
				c := NewClient(cfg)
				c.httpClient = ts.Client()
				delay, failed := c.reportAddress(cachedHost())
				if delay != tc.delay || failed != tc.failed {
					t.Fatalf("got delay=%v failed=%v", delay, failed)
				}
			})
		}
	}
}

func TestAddressRedirectNeverForwardsCredential(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	c := NewClient(config.PanelConfig{URL: source.URL, Token: "secret", NodeID: 7})
	c.httpClient = source.Client()
	c.reportAddress(cachedHost())
	if forwarded.Load() != 0 {
		t.Fatal("credential forwarded to redirect")
	}
}

func TestAddressAbsentPluginUpgradeAndMultiPanel(t *testing.T) {
	// All normal authenticated success paths automatically schedule reporting.
	// Share only the host observation, never panel capability/backoff/credentials.
	hostIPv4.mu.Lock()
	oldLookup, oldIP, oldObserved, oldNext := hostIPv4.lookup, hostIPv4.ip, hostIPv4.observed, hostIPv4.next
	hostIPv4.ip, hostIPv4.observed, hostIPv4.next = "8.8.4.4", time.Now(), time.Now().Add(time.Hour)
	hostIPv4.mu.Unlock()
	defer func() {
		hostIPv4.mu.Lock()
		hostIPv4.lookup, hostIPv4.ip, hostIPv4.observed, hostIPv4.next = oldLookup, oldIP, oldObserved, oldNext
		hostIPv4.mu.Unlock()
	}()
	var available atomic.Bool
	var reports atomic.Int32
	server := func(token string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var p map[string]interface{}
			json.NewDecoder(r.Body).Decode(&p)
			if p["token"] != token {
				t.Error("cross-panel credential leak")
			}
			if r.URL.Path == addressPath {
				reports.Add(1)
				if !available.Load() {
					w.WriteHeader(404)
					return
				}
				w.Write([]byte(`{"data":{"accepted":true,"protocol":1}}`))
				return
			}
			w.Write([]byte(`{}`))
		}))
	}
	one, two := server("one"), server("two")
	defer one.Close()
	defer two.Close()
	clients := []*Client{NewClient(config.PanelConfig{URL: one.URL, Token: "one", NodeID: 7}), NewClient(config.PanelConfig{URL: two.URL, Token: "two", MachineID: 41})}
	clients[0].httpClient, clients[1].httpClient = one.Client(), two.Client()
	wait := func(c *Client) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			c.address.mu.Lock()
			busy := c.address.busy
			c.address.mu.Unlock()
			if !busy {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("optional report did not finish")
	}
	for _, c := range clients {
		r, err := c.doRequest("POST", "/normal", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		drainAndClose(r.Body)
		wait(c)
	}
	if reports.Load() != 2 {
		t.Fatal("existing bindings not reported on first success")
	}
	for _, c := range clients {
		for i := 0; i < 20; i++ {
			c.maybeReportAddress()
		}
		wait(c)
	}
	if reports.Load() != 2 {
		t.Fatal("absent plugin retried on every heartbeat")
	}
	available.Store(true)
	for _, c := range clients {
		c.address.mu.Lock()
		c.address.next = time.Time{}
		c.address.mu.Unlock()
		c.maybeReportAddress()
		wait(c)
	}
	if reports.Load() != 4 {
		t.Fatal("plugin install/enable after node failed to rediscover")
	}
	for _, c := range clients {
		c.address.mu.Lock()
		remaining := time.Until(c.address.next)
		c.address.mu.Unlock()
		if remaining < 59*time.Minute {
			t.Fatal("successful report not cached")
		}
	}
	child := clients[1].ForNode(11)
	child.maybeReportAddress()
	wait(child)
	if reports.Load() != 4 {
		t.Fatal("machine child duplicated host report")
	}
}

func TestAddressTimeoutAndMalformedAck(t *testing.T) {
	for _, body := range []string{`<html>login</html>`, `{"data":{"accepted":false,"protocol":1}}`, `{"data":{"accepted":true,"protocol":99}}`, `{"data":{"accepted":true,"protocol":1}} trailing`} {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		c := NewClient(config.PanelConfig{URL: ts.URL, NodeID: 7})
		c.httpClient = ts.Client()
		if delay, failed := c.reportAddress(cachedHost()); delay != 10*time.Minute || failed {
			t.Error("unsupported response treated as capability")
		}
		ts.Close()
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(6 * time.Second):
		}
	}))
	defer ts.Close()
	c := NewClient(config.PanelConfig{URL: ts.URL, NodeID: 7})
	c.httpClient = ts.Client()
	start := time.Now()
	if _, failed := c.reportAddress(cachedHost()); !failed {
		t.Fatal("timeout not classified transient")
	}
	if time.Since(start) > 6*time.Second {
		t.Fatal("optional deadline not bounded")
	}
}

func TestAddressActualFlowScopeReceiver(t *testing.T) {
	receiver := os.Getenv("FLOWSCOPE_TEST_RECEIVER")
	if receiver == "" {
		t.Skip("set FLOWSCOPE_TEST_RECEIVER to xb-flowscope/tests/node-receiver.php for real Go/PHP integration")
	}
	php, err := exec.LookPath("php")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{}
	ext := filepath.Join(filepath.Dir(php), "ext")
	if _, err := os.Stat(filepath.Join(ext, "php_pdo_sqlite.dll")); err == nil {
		args = append(args, "-d", "extension_dir="+ext, "-d", "extension=pdo_sqlite", "-d", "extension=sqlite3", "-d", "extension=mbstring")
	}
	args = append(args, receiver)
	for _, tc := range []struct {
		name, token   string
		machine, node int
		enabled       bool
		status        int
		scope         string
	}{
		{"machine-no-collector", "fixture-machine-token", 41, 0, true, 200, "machine"},
		{"legacy-bound", "fixture-server-token", 0, 11, true, 200, "node"},
		{"legacy-unassigned", "fixture-server-token", 0, 13, true, 200, "node"},
		{"forged-machine", "fixture-machine-token", 42, 0, true, 401, ""},
		{"wrong-panel", "foreign-panel-token", 0, 11, true, 401, ""},
		{"disabled-plugin", "fixture-machine-token", 41, 0, false, 404, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var snapshot struct {
				Status         int                                                `json:"status"`
				Body           json.RawMessage                                    `json:"body"`
				MachineRecords int                                                `json:"machine_records"`
				Traffic        int                                                `json:"traffic_rows"`
				Cursors        int                                                `json:"cursors"`
				Addresses      struct{ Machines, Nodes []map[string]interface{} } `json:"addresses"`
			}
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				input, _ := json.Marshal(map[string]interface{}{"body": body, "enabled": tc.enabled})
				cmd := exec.Command(php, args...)
				cmd.Stdin = bytes.NewReader(input)
				output, err := cmd.Output()
				if err != nil {
					t.Error("PHP fixture failed", err)
					w.WriteHeader(500)
					return
				}
				if err := json.Unmarshal(output, &snapshot); err != nil {
					t.Error("invalid fixture response", err)
					w.WriteHeader(500)
					return
				}
				w.WriteHeader(snapshot.Status)
				w.Write(snapshot.Body)
			}))
			defer ts.Close()
			c := NewClient(config.PanelConfig{URL: ts.URL, Token: tc.token, MachineID: tc.machine, NodeID: tc.node})
			c.httpClient = ts.Client()
			_, failed := c.reportAddress(cachedHost())
			if failed {
				t.Fatal("real receiver failed")
			}
			if snapshot.Status != tc.status || snapshot.Traffic != 0 || snapshot.Cursors != 0 {
				t.Fatalf("status/accounting mismatch: %+v", snapshot)
			}
			if tc.status == 200 {
				var ack struct{ Data struct{ Scope string } }
				json.Unmarshal(snapshot.Body, &ack)
				if ack.Data.Scope != tc.scope {
					t.Fatal("credential scope widened")
				}
				if tc.scope == "machine" && snapshot.MachineRecords != 1 {
					t.Fatal("machine address not persisted")
				}
				if tc.scope == "node" && snapshot.MachineRecords != 0 {
					t.Fatal("panel-wide token wrote machine storage")
				}
				if tc.node == 13 && (len(snapshot.Addresses.Nodes) != 1 || len(snapshot.Addresses.Machines) != 0) {
					t.Fatal("unassigned node guessed machine")
				}
				if tc.node == 11 && (len(snapshot.Addresses.Machines) != 1 || snapshot.Addresses.Machines[0]["machine_id"] != float64(41)) {
					t.Fatal("trusted DB relationship not displayed")
				}
			}
		})
	}
}
