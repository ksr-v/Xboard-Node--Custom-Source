package portforward

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

// fakeHost models nft transaction semantics: a rejected batch cannot mutate
// the accepted snapshot. All managers share leases and the update lock.
type fakeHost struct {
	mu                 sync.Mutex
	leases             map[string]bool
	rows               []map[string]any
	scripts            []string
	failApply          bool
	failSnapshot       bool
	enabled            bool
	snapshots          int
	verifiedOldTargets []int
}
type fakeSystem struct{ host *fakeHost }

func (s fakeSystem) verify(_ *redirect, old []int) error {
	s.host.verifiedOldTargets = append([]int(nil), old...)
	return nil
}

func (s fakeSystem) available() bool { return s.host.enabled }
func (s fakeSystem) lease(name string) (func(), error) {
	s.host.mu.Lock()
	defer s.host.mu.Unlock()
	if s.host.leases[name] {
		return nil, errors.New("owner already active")
	}
	s.host.leases[name] = true
	return func() { s.host.mu.Lock(); delete(s.host.leases, name); s.host.mu.Unlock() }, nil
}
func (s fakeSystem) lock() (func(), error) { s.host.mu.Lock(); return s.host.mu.Unlock, nil }
func (s fakeSystem) snapshot(string, string) ([]byte, error) {
	s.host.snapshots++
	if s.host.failSnapshot {
		return nil, errors.New("NET_ADMIN denied")
	}
	return json.Marshal(map[string]any{"nftables": s.host.rows})
}
func (s fakeSystem) apply(script string) error {
	s.host.scripts = append(s.host.scripts, script)
	if s.host.failApply {
		return errors.New("atomic batch rejected")
	}
	for _, line := range strings.Split(script, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 4 && parts[0] == "delete" {
			rows := s.host.rows[:0]
			for _, row := range s.host.rows {
				var family, name string
				for kind, raw := range row {
					if item, ok := raw.(map[string]any); ok {
						family, _ = item["family"].(string)
						field := "table"
						if kind == "table" {
							field = "name"
						}
						name, _ = item[field].(string)
					}
				}
				if family != parts[2] || name != parts[3] {
					rows = append(rows, row)
				}
			}
			s.host.rows = rows
		}
	}
	var family, table, marker string
	for _, line := range strings.Split(script, "\n") {
		parts := strings.Fields(line)
		if len(parts) > 2 && parts[0] == "table" {
			family, table = parts[1], parts[2]
		}
		if len(parts) == 3 && parts[0] == "return" && parts[1] == "comment" {
			if json.Unmarshal([]byte(parts[2]), &marker) != nil {
				return errors.New("bad fake marker")
			}
		}
		if strings.Contains(line, "redirect to :") {
			r := &redirect{}
			for i, token := range parts {
				if token == "dport" {
					bounds := strings.Split(parts[i+1], "-")
					r.start, _ = strconv.Atoi(bounds[0])
					r.end, _ = strconv.Atoi(bounds[1])
				}
				if token == "to" {
					r.target, _ = strconv.Atoi(strings.TrimPrefix(parts[i+1], ":"))
				}
				if token == "daddr" && i == 1 {
					r.address, _ = netip.ParseAddr(parts[i+1])
				}
			}
			s.host.rows = append(s.host.rows, portableRows(family, table, marker, r)...)
		}
	}
	return nil
}
func tableRow(name, marker string) map[string]any {
	return map[string]any{"table": map[string]any{"family": "inet", "name": name, "comment": marker}}
}
func newFake(t *testing.T, owner string) (*Manager, *fakeHost) {
	t.Helper()
	m := New(owner)
	h := &fakeHost{leases: map[string]bool{}, rows: []map[string]any{}, enabled: true}
	m.system = fakeSystem{h}
	t.Cleanup(func() { _ = m.Close() })
	return m, h
}
func node() *model.NodeSpec {
	return &model.NodeSpec{Protocol: "hysteria", Version: 2, ListenIP: "0.0.0.0", ServerPort: 42443, PortHopping: &model.PortHopping{Start: 42450, End: 42453}}
}

func TestInvalidInputNeverTouchesHost(t *testing.T) {
	for name, mutate := range map[string]func(*model.NodeSpec){
		"non-hy2":           func(n *model.NodeSpec) { n.Protocol = "vless" },
		"hy1":               func(n *model.NodeSpec) { n.Version = 1 },
		"zero":              func(n *model.NodeSpec) { n.PortHopping.Start = 0 },
		"overflow":          func(n *model.NodeSpec) { n.PortHopping.End = 65536 },
		"reverse":           func(n *model.NodeSpec) { n.PortHopping.Start = 42454 },
		"listener":          func(n *model.NodeSpec) { n.ServerPort = 0 },
		"command-injection": func(n *model.NodeSpec) { n.ListenIP = "127.0.0.1; flush ruleset" },
		"zone":              func(n *model.NodeSpec) { n.ListenIP = "fe80::1%eth0" },
	} {
		t.Run(name, func(t *testing.T) {
			m, h := newFake(t, "test-invalid")
			h.enabled = false
			n := node()
			mutate(n)
			if m.Update(n) == nil {
				t.Fatal("accepted invalid request")
			}
			if h.snapshots != 0 || len(h.scripts) != 0 || len(h.leases) != 0 {
				t.Fatal("invalid request touched host")
			}
		})
	}
}

func TestNoRangeNeedsNoNftAndUnsupportedPlatformIsActionable(t *testing.T) {
	m, h := newFake(t, "no-range")
	h.enabled = false
	if err := m.Update(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if h.snapshots != 0 {
		t.Fatal("no-range attempted inventory without nft/root")
	}
}

func TestAtomicReplaceRollbackAndOwnOnlyCleanup(t *testing.T) {
	m, h := newFake(t, "stable panel-url /private/path")
	h.rows = append(h.rows, tableRow("foreign_filter", "administrator-owned"))
	if err := m.Update(node()); err != nil {
		t.Fatal(err)
	}
	if tableCount(h.rows) != 2 {
		t.Fatalf("expected foreign + own: %v", h.rows)
	}
	first := h.scripts[0]
	if strings.Contains(first, "flush") || strings.Contains(first, "add rule") || strings.Contains(first, "private/path") || strings.Contains(first, "panel-url") || strings.Contains(first, " accept\n") {
		t.Fatal("unsafe or sensitive script", first)
	}
	if !strings.Contains(first, "fib daddr type local") || !strings.Contains(first, "table ip ") || strings.Contains(first, "table inet ") || !strings.Contains(first, "redirect to :42443") {
		t.Fatal(first)
	}
	h.failApply = true
	next := node()
	next.PortHopping.End = 42459
	if m.Update(next) == nil {
		t.Fatal("failed atomic update accepted")
	}
	if tableCount(h.rows) != 2 {
		t.Fatal("failed batch changed accepted rules")
	}
	if !strings.HasPrefix(h.scripts[1], "delete table ip "+m.table+"\n") {
		t.Fatal("replacement not a single atomic batch")
	}
	h.failApply = false
	if err := m.Update(next); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(h.rows) != 1 || h.rows[0]["table"].(map[string]any)["name"] != "foreign_filter" {
		t.Fatal("foreign table changed")
	}
	if len(h.leases) != 0 {
		t.Fatal("owner lease not released")
	}
}

func TestOwnershipCollisionNeverDeletes(t *testing.T) {
	m, h := newFake(t, "collision")
	h.rows = append(h.rows, tableRow(m.table, "someone-else"))
	if m.Update(node()) == nil {
		t.Fatal("foreign same-name table accepted")
	}
	if m.Close() == nil {
		t.Fatal("cleanup did not expose collision")
	}
	if len(h.scripts) != 0 {
		t.Fatal("foreign table mutated")
	}
}

func TestStartupReclaimsStaleAndDisableCleansIt(t *testing.T) {
	for _, enable := range []bool{true, false} {
		t.Run(map[bool]string{true: "re-enable", false: "disable"}[enable], func(t *testing.T) {
			m, h := newFake(t, "restart")
			h.rows = append(h.rows, tableRow(m.table, m.marker))
			var n *model.NodeSpec
			if enable {
				n = node()
			}
			if err := m.Update(n); err != nil {
				t.Fatal(err)
			}
			if len(h.scripts) != 1 || !strings.HasPrefix(h.scripts[0], "delete table inet "+m.table+"\n") {
				t.Fatal("stale table not reclaimed")
			}
			if !enable && len(h.rows) != 0 {
				t.Fatal("disabled startup left stale redirect")
			}
			if !enable {
				before := h.snapshots
				if err := m.Update(nil); err != nil {
					t.Fatal(err)
				}
				if h.snapshots != before {
					t.Fatal("repeated empty update repeated startup check")
				}
			}
		})
	}
}

func TestSameOwnerLiveLeasePreventsSecondCleanup(t *testing.T) {
	first, h := newFake(t, "one-instance")
	if err := first.Update(node()); err != nil {
		t.Fatal(err)
	}
	second := New("one-instance")
	second.system = fakeSystem{h}
	if second.Update(node()) == nil {
		t.Fatal("second live owner acquired lease")
	}
	count := len(h.scripts)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if len(h.scripts) != count || tableCount(h.rows) != 1 {
		t.Fatal("failed second owner deleted live owner's table")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Update(node()); err != nil {
		t.Fatal("lease did not recover after first closed", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingPermissionsAndUnparseableRulesAreReported(t *testing.T) {
	m, h := newFake(t, "permissions")
	h.failSnapshot = true
	if err := m.Update(node()); err == nil || !strings.Contains(err.Error(), "NET_ADMIN") {
		t.Fatal(err)
	}
	if len(h.scripts) != 0 {
		t.Fatal("inventory failure changed rules")
	}
	for _, data := range []string{`null`, `{}`, `{"nftables":null}`, `{"nftables":[{"table":{}}]}`, `{"nftables":[{"rule":{"family":"inet"}}]}`, `not json`} {
		if _, err := inspect([]byte(data), m.table, m.marker); err == nil {
			t.Fatal("malformed inventory accepted", data)
		}
	}
}

func TestAddressFamiliesRestrictGeneratedRules(t *testing.T) {
	for _, tc := range []struct {
		ip, want string
		absent   string
	}{
		{"", "fib daddr type local", "meta nfproto"},
		{"::", "fib daddr type local", "meta nfproto"},
		{"0.0.0.0", "table ip safe_table", "table ip6 safe_table"},
		{"192.0.2.7", "ip daddr 192.0.2.7", "ip6 daddr"},
		{"2001:db8::7", "table ip6 safe_table", "table ip safe_table"},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			n := node()
			n.ListenIP = tc.ip
			r, err := validate(n)
			if err != nil {
				t.Fatal(err)
			}
			script := batch("safe_table", "hash-only", nil, r)
			if !strings.Contains(script, tc.want) || strings.Contains(script, tc.absent) {
				t.Fatal(script)
			}
		})
	}
}

func foreign(expr string, family string) nftRule {
	var e []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(expr), &e); err != nil {
		panic(err)
	}
	return nftRule{Family: family, Table: "foreign_nat", Chain: "prerouting", Expr: e}
}

func TestForeignAndCrossNodeNATConflicts(t *testing.T) {
	want, _ := validate(node())
	for _, tc := range []struct {
		name, expr, family string
		conflict           bool
	}{
		{"overlap", `[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[42449,42450]}}},{"redirect":{"port":9999}}]`, "inet", true},
		{"another-node", `[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[42450,42453]}}},{"redirect":{"port":9999}}]`, "inet", true},
		{"separate-port", `[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":443}},{"dnat":{"port":8080}}]`, "inet", false},
		{"tcp-only", `[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":42450}},{"dnat":{"port":8080}}]`, "inet", false},
		{"named-set-unknown", `[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":"@admin_ports"}},{"redirect":{"port":9999}}]`, "inet", true},
		{"named-protocol-unknown", `[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"@admin_protocols"}},{"redirect":{"port":9999}}]`, "inet", true},
		{"no-port-child-chain", `[{"dnat":{"addr":"192.0.2.9"}}]`, "inet", true},
		{"separate-family", `[{"redirect":{"port":9999}}]`, "ip6", false},
		{"family-selector", `[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}},{"redirect":{"port":9999}}]`, "inet", false},
		{"set-no-overlap", `[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"set":[53,{"range":[1000,2000]}]}}},{"redirect":{"port":9999}}]`, "inet", false},
		{"set-overlap", `[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"set":[53,42451]}}},{"redirect":{"port":9999}}]`, "inet", true},
		{"non-nat", `[{"accept":null}]`, "inet", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &inventory{rules: []nftRule{foreign(tc.expr, tc.family)}}
			if got := v.conflicts(want) != nil; got != tc.conflict {
				t.Fatalf("conflict=%v wanted %v", got, tc.conflict)
			}
		})
	}
}

func TestAddressDisjointAndDualStackOverlap(t *testing.T) {
	r := foreign(`[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},{"redirect":{"port":9999}}]`, "inet")
	for _, tc := range []struct {
		ip       string
		conflict bool
	}{{"198.51.100.2", false}, {"192.0.2.5", true}, {"0.0.0.0", true}, {"::", true}, {"2001:db8::5", false}} {
		n := node()
		n.ListenIP = tc.ip
		want, _ := validate(n)
		if got := (&inventory{rules: []nftRule{r}}).conflicts(want) != nil; got != tc.conflict {
			t.Fatalf("%s conflict=%v", tc.ip, got)
		}
	}
}

func TestCrossNodeCollisionRefusesBeforeMutation(t *testing.T) {
	m, h := newFake(t, "second-node")
	other := New("first-node")
	h.rows = append(h.rows, tableRow(other.table, other.marker), map[string]any{"rule": map[string]any{
		"family": "inet", "table": other.table, "chain": "prerouting", "expr": []any{
			map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "udp", "field": "dport"}}, "right": map[string]any{"range": []int{42450, 42453}}}},
			map[string]any{"redirect": map[string]any{"port": 9999}},
		},
	}})
	if err := m.Update(node()); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatal("overlapping Node was not refused", err)
	}
	if len(h.scripts) != 0 || len(h.rows) != 2 {
		t.Fatal("collision altered another Node")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(h.scripts) != 0 {
		t.Fatal("failed candidate cleanup touched another Node")
	}
}

func TestNoRuleDeletionAfterOwnerMarkerChanges(t *testing.T) {
	m, h := newFake(t, "takeover")
	if err := m.Update(node()); err != nil {
		t.Fatal(err)
	}
	h.rows[0] = tableRow(m.table, "different-owner")
	count := len(h.scripts)
	if err := m.Close(); err == nil {
		t.Fatal("foreign takeover was silently deleted")
	}
	if len(h.scripts) != count {
		t.Fatal("cleanup modified table after marker changed")
	}
}

func TestNoRangePermissionFailureDoesNotBreakUnrelatedNode(t *testing.T) {
	m, h := newFake(t, "non-admin-container")
	h.failSnapshot = true
	if err := m.Update(nil); err != nil {
		t.Fatal("unrelated Node requires NET_ADMIN", err)
	}
	if m.checked {
		t.Fatal("failed optional cleanup was recorded as successful")
	}
	if err := m.Update(node()); err == nil {
		t.Fatal("requested mapping hid NET_ADMIN failure")
	}
	h.failSnapshot = false
	if err := m.Update(node()); err != nil {
		t.Fatal(err)
	}
	h.failSnapshot = true
	if err := m.Update(nil); err == nil {
		t.Fatal("engaged cleanup hid permission failure")
	}
	h.failSnapshot = false
}

func TestStaleTargetIsNotExemptedByNewManager(t *testing.T) {
	m, h := newFake(t, "stale-old-target")
	old, _ := validate(node())
	old.target = 42451
	h.rows = legacyRows(m.table, m.marker, old)
	if err := m.Update(node()); err != nil {
		t.Fatal(err)
	}
	if len(h.verifiedOldTargets) != 0 {
		t.Fatal("new process trusted stale table's target")
	}
	// Only an accepted update during this Manager's lifetime can establish
	// the old target; it must still be present in its verified own table.
	old.target = 42443
	h.rows = legacyRows(m.table, m.marker, old)
	next := node()
	next.ServerPort = 42500
	if err := m.Update(next); err != nil {
		t.Fatal(err)
	}
	if len(h.verifiedOldTargets) != 1 || h.verifiedOldTargets[0] != 42443 {
		t.Fatal("accepted prior target not recognized", h.verifiedOldTargets)
	}
}
