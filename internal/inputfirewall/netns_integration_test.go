//go:build linux && netns

package inputfirewall_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/inputfirewall"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/portforward"
)

var compatTools = []string{"iptables-nft", "ip6tables-nft", "iptables-legacy", "ip6tables-legacy"}

func diagnose(t *testing.T, phase string) {
	t.Helper()
	var rows []map[string]any
	for _, tool := range compatTools {
		text := command(t, tool+"-save", "-t", "filter")
		ports := regexp.MustCompile(`--dport ([0-9]+)`).FindAllStringSubmatch(text, -1)
		var selected []string
		for _, p := range ports {
			selected = append(selected, p[1])
		}
		rows = append(rows, map[string]any{"tool": tool, "owned_chain_count": strings.Count(text, ":XB_IN_"),
			"owned_jump_count": strings.Count(text, "-j XB_IN_"), "ports": selected,
			"owned_rule_count": strings.Count(text, "-A XB_IN_")})
	}
	data, _ := json.Marshal(map[string]any{"phase": phase, "backends": rows})
	t.Log("XB_DIAG " + string(data))
}

func netnsGuard(t *testing.T) string {
	t.Helper()
	host := os.Getenv("XB_NETNS_HOST_ID")
	current, err := os.Readlink("/proc/self/ns/net")
	if host == "" || err != nil || host == current || os.Getenv("XB_NETNS_PRIVATE_RUN") != "1" {
		t.Fatal("dedicated network and mount namespaces are required")
	}
	pid := os.Getenv("XB_NETNS_CLIENT_PID")
	if _, err := strconv.Atoi(pid); err != nil {
		t.Fatal("isolated client process is required")
	}
	client, err := os.Readlink("/proc/" + pid + "/ns/net")
	if err != nil || client == current || client == host {
		t.Fatal("client must have a separate, non-host network namespace")
	}
	return pid
}

func command(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("namespace test command %s failed: %v", name, err)
	}
	return string(out)
}

func nftBatch(t *testing.T, script string) {
	t.Helper()
	c := exec.Command("nft", "-f", "-")
	c.Stdin = strings.NewReader(script)
	if err := c.Run(); err != nil {
		t.Fatalf("isolated nft batch failed: %v", err)
	}
}

func config(port int, listen string) *model.NodeSpec {
	return &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: port, ListenIP: listen}
}

func echoUDP(t *testing.T, family, address string, port int) func() {
	t.Helper()
	c, err := net.ListenPacket(family, net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("isolated UDP listener failed: %v", err)
	}
	go func() {
		var data [128]byte
		for {
			n, peer, err := c.ReadFrom(data[:])
			if err != nil {
				return
			}
			_, _ = c.WriteTo(append([]byte(strconv.Itoa(port)+":"), data[:n]...), peer)
		}
	}()
	close := func() { _ = c.Close() }
	t.Cleanup(close)
	return close
}

func probe(t *testing.T, client string, family, port, expected int) bool {
	t.Helper()
	code := `import socket,sys
family,port,expected=map(int,sys.argv[1:])
sock=socket.socket(socket.AF_INET if family==4 else socket.AF_INET6,socket.SOCK_DGRAM)
sock.settimeout(0.65)
try:
 sock.sendto(b'namespace-probe',('10.253.30.1' if family==4 else 'fd00:253:30::1',port))
 data=sock.recv(128)
 print('yes' if data==str(expected).encode()+b':namespace-probe' else 'no')
except OSError:
 print('no')
`
	out := command(t, "nsenter", "--target", client, "--net", "python3", "-c", code,
		strconv.Itoa(family), strconv.Itoa(port), strconv.Itoa(expected))
	return strings.TrimSpace(out) == "yes"
}

func filteredSave(t *testing.T, tool string) string {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(command(t, tool+"-save", "-t", "filter"), "\n") {
		if strings.HasPrefix(line, "#") || strings.Contains(line, "XB_IN_") || strings.Contains(line, "xboard-node-input:v1:") || line == "" {
			continue
		}
		lines = append(lines, line)
	}
	// Traffic changes chain counters even when the rule body is untouched.
	return regexp.MustCompile(`\[[0-9]+:[0-9]+\]`).ReplaceAllString(strings.Join(lines, "\n"), "[0:0]")
}

// This suite runs only in tools/test_inputfirewall_netns.py's fresh namespaces.
// It verifies real packets and all four iptables compatibility backends together.
func TestManagedInputNetwork(t *testing.T) {
	client := netnsGuard(t)
	original := make(map[string]string)
	for _, tool := range compatTools {
		command(t, tool, "-N", "FOREIGN_KEEP")
		command(t, tool, "-A", "FOREIGN_KEEP", "-p", "tcp", "--dport", "22", "-j", "ACCEPT")
		command(t, tool, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
		if strings.HasPrefix(tool, "ip6") {
			command(t, tool, "-A", "INPUT", "-p", "ipv6-icmp", "-j", "ACCEPT")
		}
		command(t, tool, "-A", "INPUT", "-j", "FOREIGN_KEEP")
		command(t, tool, "-A", "INPUT", "-j", "REJECT")
		command(t, tool, "-P", "INPUT", "DROP")
		original[tool] = filteredSave(t, tool)
	}
	m := inputfirewall.New("netns-main-node")
	sibling := inputfirewall.New("netns-sibling-node")
	defer m.Close()
	defer sibling.Close()
	close4 := echoUDP(t, "udp4", "0.0.0.0", 17443)
	close6 := echoUDP(t, "udp6", "::", 17443)
	closeOther4 := echoUDP(t, "udp4", "0.0.0.0", 17444)
	closeOther6 := echoUDP(t, "udp6", "::", 17444)
	t.Run("reject_before_update", func(t *testing.T) {
		if probe(t, client, 4, 17443, 17443) || probe(t, client, 6, 17443, 17443) {
			t.Fatal("foreign INPUT rejection was not effective")
		}
	})
	t.Run("stale_owned_cleanup", func(t *testing.T) {
		id := fmt.Sprintf("%x", sha256.Sum256([]byte("deleted-before-restart")))
		chain, marker := "XB_IN_"+id[:20], "xboard-node-input:v1:"+id
		for _, tool := range compatTools {
			command(t, tool, "-N", chain)
			command(t, tool, "-A", chain, "-p", "udp", "--dport", "19999", "-m", "comment", "--comment", marker, "-j", "ACCEPT")
			command(t, tool, "-A", chain, "-m", "comment", "--comment", marker, "-j", "RETURN")
			command(t, tool, "-I", "INPUT", "1", "-m", "comment", "--comment", marker, "-j", chain)
		}
		if err := m.Update(config(17443, "")); err != nil {
			t.Fatal(err)
		}
		for _, tool := range compatTools {
			if strings.Contains(command(t, tool+"-save", "-t", "filter"), chain) {
				t.Fatal("stale owned grant survived startup")
			}
		}
	})
	t.Run("dual_stack_real_packets_and_scope", func(t *testing.T) {
		if !probe(t, client, 4, 17443, 17443) || !probe(t, client, 6, 17443, 17443) {
			t.Fatal("managed UDP listener did not pass both active filter backends")
		}
		if probe(t, client, 4, 17444, 17444) || probe(t, client, 6, 17444, 17444) {
			t.Fatal("unmanaged listening UDP port was opened")
		}
	})
	t.Run("idempotent_and_multiple_owners", func(t *testing.T) {
		defer sibling.Close()
		if err := sibling.Update(config(17444, "")); err != nil {
			t.Fatal(err)
		}
		before := make(map[string]string)
		for _, tool := range compatTools {
			before[tool] = command(t, tool+"-save", "-t", "filter")
		}
		for i := 0; i < 3; i++ {
			if err := m.Update(config(17443, "")); err != nil {
				t.Fatal(err)
			}
			if err := sibling.Update(config(17444, "")); err != nil {
				t.Fatal(err)
			}
		}
		for _, tool := range compatTools {
			// Remove only iptables-save's wall-clock header/footer.
			clean := func(s string) string {
				var out []string
				for _, line := range strings.Split(s, "\n") {
					if !strings.HasPrefix(line, "#") {
						out = append(out, line)
					}
				}
				return regexp.MustCompile(`\[[0-9]+:[0-9]+\]`).ReplaceAllString(strings.Join(out, "\n"), "[0:0]")
			}
			if clean(command(t, tool+"-save", "-t", "filter")) != clean(before[tool]) {
				diagnose(t, "idempotence")
				t.Fatal("reconciliation changed an already correct ruleset")
			}
		}
		if err := sibling.Close(); err != nil {
			t.Fatal(err)
		}
		if !probe(t, client, 4, 17443, 17443) || probe(t, client, 4, 17444, 17444) {
			t.Fatal("sibling cleanup changed the wrong grant")
		}
	})
	t.Run("repair_removed_jump", func(t *testing.T) {
		for _, tool := range compatTools {
			command(t, tool, "-D", "INPUT", "1")
		}
		if probe(t, client, 4, 17443, 17443) {
			t.Fatal("reload fixture failed to remove permission")
		}
		if err := m.Update(config(17443, "")); err != nil {
			t.Fatal(err)
		}
		if !probe(t, client, 4, 17443, 17443) || !probe(t, client, 6, 17443, 17443) {
			t.Fatal("permission was not repaired after reload")
		}
	})
	t.Run("port_and_address_change", func(t *testing.T) {
		if err := m.Update(config(17444, "10.253.30.1")); err != nil {
			t.Fatal(err)
		}
		new4, old4, new6 := probe(t, client, 4, 17444, 17444), probe(t, client, 4, 17443, 17443), probe(t, client, 6, 17444, 17444)
		if !new4 || old4 || new6 {
			diagnose(t, "port_address_change")
			t.Logf("XB_PROBE new4=%t old4=%t new6=%t", new4, old4, new6)
			t.Fatal("old port or unselected address family remained open")
		}
	})
	t.Run("native_input_chain_rejected_without_mutation", func(t *testing.T) {
		before := make(map[string]string)
		for _, tool := range compatTools {
			before[tool] = command(t, tool+"-save", "-t", "filter")
		}
		nftBatch(t, "add table inet foreign_guard\nadd chain inet foreign_guard input { type filter hook input priority 10; policy accept; }\n")
		if err := m.Update(config(17443, "")); err == nil {
			t.Fatal("native INPUT chain was silently accepted")
		}
		for _, tool := range compatTools {
			// A failed operation must leave the old grant and foreign rules intact.
			current := command(t, tool+"-save", "-t", "filter")
			if strings.Join(strings.Fields(current), " ") != strings.Join(strings.Fields(before[tool]), " ") {
				// Timestamp comments can vary; compare all rules without comments.
				keep := func(s string) string {
					var a []string
					for _, l := range strings.Split(s, "\n") {
						if !strings.HasPrefix(l, "#") {
							a = append(a, l)
						}
					}
					return strings.Join(a, "\n")
				}
				if keep(current) != keep(before[tool]) {
					t.Fatal("unsupported firewall caused a mutation")
				}
			}
		}
		nftBatch(t, "delete table inet foreign_guard\n")
	})
	close4()
	close6()
	closeOther4()
	closeOther6()
	t.Run("nat_redirect_plus_input_real_packets", func(t *testing.T) {
		nc := config(17443, "")
		nc.PortHopping = &model.PortHopping{Start: 17443, End: 19443}
		nat := portforward.New("netns-hop-node")
		defer nat.Close()
		if err := nat.Update(nc); err != nil {
			t.Fatal(err)
		}
		if err := m.Update(nc); err != nil {
			t.Fatal(err)
		}
		c4 := echoUDP(t, "udp4", "0.0.0.0", 17443)
		defer c4()
		c6 := echoUDP(t, "udp6", "::", 17443)
		defer c6()
		if !probe(t, client, 4, 17981, 17443) || !probe(t, client, 6, 18230, 17443) {
			t.Fatal("hopping UDP packet did not reach and return from actual listener")
		}
	})
	t.Run("close_preserves_all_foreign_rules_and_policies", func(t *testing.T) {
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		for _, tool := range compatTools {
			if filteredSave(t, tool) != original[tool] {
				t.Fatal("foreign filter rules or default policies changed")
			}
			if strings.Contains(command(t, tool+"-save", "-t", "filter"), "XB_IN_") {
				diagnose(t, "close")
				t.Fatal("owned grant survived cleanup")
			}
		}
	})
}
