//go:build linux && netns

package portforward

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// This is opt-in: the runner must supply fresh network and mount namespaces.
// It never runs as part of ordinary unit tests or against the host firewall.
func portableNamespaceGuard(t *testing.T) {
	t.Helper()
	host := os.Getenv("XB_NETNS_HOST_ID")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || host == "" || host == current || os.Getenv("XB_NETNS_PRIVATE_RUN") != "1" {
		t.Fatal("dedicated network and mount namespaces required")
	}
}

func TestPortableNATNetworkLifecycle(t *testing.T) {
	portableNamespaceGuard(t)
	m := New("netns-v9-portable-lifecycle")
	defer m.Close()
	n := node()
	n.ServerPort = 53
	n.PortHopping.Start = 53
	n.PortHopping.End = 55
	check := func(expected map[string]bool, target int) {
		t.Helper()
		data, err := m.system.snapshot(m.table, m.marker)
		if err != nil {
			t.Fatal(err)
		}
		v, err := inspect(data, m.table, m.marker)
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range []string{"inet", "ip", "ip6"} {
			if v.families[family] != expected[family] {
				t.Fatal("unexpected owned family", family)
			}
		}
		for _, port := range v.oldTargets {
			if port != target {
				t.Fatal("old or symbolic target survived")
			}
		}
	}
	if err := m.Update(n); err != nil {
		t.Fatal("IPv4 bootstrap", err)
	}
	check(map[string]bool{"ip": true}, 53)
	n.ListenIP = ""
	if err := m.Update(n); err != nil {
		t.Fatal("dual family update", err)
	}
	check(map[string]bool{"ip": true, "ip6": true}, 53)
	n.ListenIP = "127.0.0.1"
	n.ServerPort = 443
	if err := m.Update(n); err != nil {
		t.Fatal("address and target update", err)
	}
	check(map[string]bool{"ip": true}, 443)
	if err := m.Close(); err != nil {
		t.Fatal("portable cleanup", err)
	}
	check(nil, 0)
}

// Seed exactly the old v8 writer's syntax. This test requires a modern CLI
// capable of table comments, and is intentionally run only in that profile.
func TestPortableNATMigrateOldInetNetns(t *testing.T) {
	portableNamespaceGuard(t)
	for _, address := range []string{"", "0.0.0.0", "192.0.2.8", "2001:db8::8"} {
		t.Run(address, func(t *testing.T) {
			m := New("netns-v8-migration-" + address)
			defer m.Close()
			n := node()
			n.ListenIP = address
			n.ServerPort = 443
			n.PortHopping.Start = 53
			n.PortHopping.End = 55
			r, _ := validate(n)
			var script strings.Builder
			fmt.Fprintf(&script, "table inet %s {\n comment %q\n chain prerouting {\n type nat hook prerouting priority dstnat; policy accept;\n ", m.table, m.marker)
			if r.family == 4 {
				script.WriteString("meta nfproto ipv4 ")
			} else if r.family == 6 {
				script.WriteString("meta nfproto ipv6 ")
			}
			if r.address.IsValid() {
				family := "ip6"
				if r.address.Is4() {
					family = "ip"
				}
				fmt.Fprintf(&script, "%s daddr %s ", family, r.address)
			}
			fmt.Fprintf(&script, "fib daddr type local meta l4proto udp udp dport %d-%d counter redirect to :%d\n }\n}\n", r.start, r.end, r.target)
			if _, err := nft(script.String(), "-f", "-"); err != nil {
				t.Fatal("modern v8 seed failed", err)
			}
			read := func() *inventory {
				t.Helper()
				data, err := m.system.snapshot(m.table, m.marker)
				if err != nil {
					t.Fatal(err)
				}
				v, err := inspect(data, m.table, m.marker)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			if !read().families["inet"] {
				t.Fatal("real v8 table not recognized")
			}
			if err := m.Update(n); err != nil {
				t.Fatal("real v8 migration failed", err)
			}
			v := read()
			if v.families["inet"] || v.families["ip"] != (r.family == 0 || r.family == 4) || v.families["ip6"] != (r.family == 0 || r.family == 6) {
				t.Fatal("migration left incorrect families")
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			if read().owned {
				t.Fatal("migrated resources survived cleanup")
			}
		})
	}
}
