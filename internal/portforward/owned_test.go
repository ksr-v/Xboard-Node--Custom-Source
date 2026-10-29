package portforward

import (
	"encoding/json"
	"strings"
	"testing"
)

func tableCount(rows []map[string]any) int {
	n := 0
	for _, r := range rows {
		if r["table"] != nil {
			n++
		}
	}
	return n
}

func natExpressions(family string, r *redirect) []any {
	var expr []any
	match := func(left map[string]any, right any) {
		expr = append(expr, map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}})
	}
	if family == "inet" && r.family != 0 {
		value := "ipv4"
		if r.family == 6 {
			value = "ipv6"
		}
		match(map[string]any{"meta": map[string]any{"key": "nfproto"}}, value)
	}
	if r.address.IsValid() {
		p := "ip6"
		if r.address.Is4() {
			p = "ip"
		}
		match(map[string]any{"payload": map[string]any{"protocol": p, "field": "daddr"}}, r.address.String())
	}
	match(map[string]any{"fib": map[string]any{"result": "type", "flags": []string{"daddr"}}}, "local")
	match(map[string]any{"meta": map[string]any{"key": "l4proto"}}, "udp")
	match(map[string]any{"payload": map[string]any{"protocol": "udp", "field": "dport"}}, map[string]any{"range": []int{r.start, r.end}})
	expr = append(expr, map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}, map[string]any{"redirect": map[string]any{"port": r.target}})
	return expr
}
func portableRows(family, table, marker string, r *redirect) []map[string]any {
	return []map[string]any{
		{"table": map[string]any{"family": family, "name": table}},
		{"chain": map[string]any{"family": family, "table": table, "name": ownerChain}},
		{"rule": map[string]any{"family": family, "table": table, "chain": ownerChain, "comment": marker, "expr": []any{map[string]any{"return": nil}}}},
		{"chain": map[string]any{"family": family, "table": table, "name": "prerouting", "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}},
		{"rule": map[string]any{"family": family, "table": table, "chain": "prerouting", "comment": marker, "expr": natExpressions(family, r)}},
	}
}
func legacyRows(table, marker string, r *redirect) []map[string]any {
	return []map[string]any{tableRow(table, marker),
		{"chain": map[string]any{"family": "inet", "table": table, "name": "prerouting", "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}},
		{"rule": map[string]any{"family": "inet", "table": table, "chain": "prerouting", "expr": natExpressions("inet", r)}},
	}
}
func inspectRows(t *testing.T, rows []map[string]any, m *Manager) (*inventory, error) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"nftables": rows})
	if err != nil {
		t.Fatal(err)
	}
	return inspect(data, m.table, m.marker)
}
func portableOwner(m *Manager) string {
	return portableMarkerPrefix + strings.TrimPrefix(m.marker, markerPrefix)
}

func TestPortableWriterUsesAtomicFamilyTablesWithoutTableComments(t *testing.T) {
	m, h := newFake(t, "portable-dual")
	n := node()
	n.ListenIP = ""
	if err := m.Update(n); err != nil {
		t.Fatal(err)
	}
	if tableCount(h.rows) != 2 {
		t.Fatal("dual stack is not two family tables")
	}
	script := h.scripts[0]
	if !strings.Contains(script, "table ip "+m.table) || !strings.Contains(script, "table ip6 "+m.table) || strings.Contains(script, "table inet") || strings.Contains(script, "priority dstnat") || !strings.Contains(script, "priority -100") || !strings.Contains(script, "return comment \""+portableOwner(m)+"\"") {
		t.Fatal("nonportable writer", script)
	}
	if err := m.Close(); err != nil || tableCount(h.rows) != 0 {
		t.Fatal("dual cleanup failed", err)
	}
}

func TestOldInetMigrationAndFailedBatchPreserveOldResources(t *testing.T) {
	m, h := newFake(t, "migration")
	r, _ := validate(node())
	h.rows = legacyRows(m.table, m.marker, r)
	h.failApply = true
	if m.Update(node()) == nil || tableCount(h.rows) != 1 || h.rows[0]["table"].(map[string]any)["family"] != "inet" {
		t.Fatal("rejected transaction modified old inet")
	}
	h.failApply = false
	if err := m.Update(node()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.scripts[1], "delete table inet "+m.table+"\n") || tableCount(h.rows) != 1 || h.rows[0]["table"].(map[string]any)["family"] != "ip" {
		t.Fatal("old inet not migrated atomically")
	}
}

func TestFamilyChangeDeletesOldGrantInSameTransaction(t *testing.T) {
	m, h := newFake(t, "family-change")
	if err := m.Update(node()); err != nil {
		t.Fatal(err)
	}
	n := node()
	n.ListenIP = "2001:db8::8"
	if err := m.Update(n); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.scripts[1], "delete table ip "+m.table+"\n") || !strings.Contains(h.scripts[1], "table ip6 "+m.table) || tableCount(h.rows) != 1 || h.rows[0]["table"].(map[string]any)["family"] != "ip6" {
		t.Fatal("old family retained")
	}
}

func TestPortableOwnershipRejectsForeignBodiesObjectsAndReferences(t *testing.T) {
	for name, mutate := range map[string]func([]map[string]any) []map[string]any{
		"sentinel-comment": func(rows []map[string]any) []map[string]any {
			rows[2]["rule"].(map[string]any)["comment"] = "wrong-owner"
			return rows
		},
		"sentinel-hook": func(rows []map[string]any) []map[string]any {
			rows[1]["chain"].(map[string]any)["hook"] = "input"
			return rows
		},
		"sentinel-verdict": func(rows []map[string]any) []map[string]any {
			rows[2]["rule"].(map[string]any)["expr"] = []any{map[string]any{"accept": nil}}
			return rows
		},
		"extra-chain": func(rows []map[string]any) []map[string]any {
			c := rows[1]["chain"].(map[string]any)
			return append(rows, map[string]any{"chain": map[string]any{"family": c["family"], "table": c["table"], "name": "foreign"}})
		},
		"extra-set": func(rows []map[string]any) []map[string]any {
			c := rows[1]["chain"].(map[string]any)
			return append(rows, map[string]any{"set": map[string]any{"family": c["family"], "table": c["table"], "name": "foreign"}})
		},
		"foreign-rule": func(rows []map[string]any) []map[string]any { return append(rows, rows[4]) },
		"foreign-comment": func(rows []map[string]any) []map[string]any {
			rows[4]["rule"].(map[string]any)["comment"] = "administrator"
			return rows
		},
		"jump-reference": func(rows []map[string]any) []map[string]any {
			rows[4]["rule"].(map[string]any)["expr"] = []any{map[string]any{"jump": map[string]any{"target": ownerChain}}}
			return rows
		},
		"wrong-priority": func(rows []map[string]any) []map[string]any {
			rows[3]["chain"].(map[string]any)["prio"] = -99
			return rows
		},
		"missing-sentinel": func(rows []map[string]any) []map[string]any { return []map[string]any{rows[0], rows[3], rows[4]} },
	} {
		t.Run(name, func(t *testing.T) {
			m, h := newFake(t, "strict-portable")
			r, _ := validate(node())
			h.rows = mutate(portableRows("ip", m.table, portableOwner(m), r))
			if m.Update(node()) == nil || len(h.scripts) != 0 {
				t.Fatal("unknown resources replaced")
			}
		})
	}
}

func TestLegacyInetWithForeignExtrasIsNotDeleted(t *testing.T) {
	for _, kind := range []string{"set", "chain", "rule"} {
		t.Run(kind, func(t *testing.T) {
			m, h := newFake(t, "strict-migration")
			r, _ := validate(node())
			h.rows = legacyRows(m.table, m.marker, r)
			item := map[string]any{"family": "inet", "table": m.table, "name": "administrator"}
			if kind == "rule" {
				item["chain"] = "prerouting"
				item["expr"] = []any{map[string]any{"accept": nil}}
			}
			h.rows = append(h.rows, map[string]any{kind: item})
			if m.Update(node()) == nil || len(h.scripts) != 0 {
				t.Fatal("legacy foreign resource deleted")
			}
		})
	}
}

func TestKnownPartialReloadCanBeRepairedWithoutRelaxingSentinel(t *testing.T) {
	m, h := newFake(t, "partial-reload")
	r, _ := validate(node())
	rows := portableRows("ip", m.table, portableOwner(m), r)
	h.rows = rows[:3]
	if err := m.Update(node()); err != nil || tableCount(h.rows) != 1 {
		t.Fatal("known missing forwarding chain not repaired", err)
	}
}

func TestRealOldJSONShapeSupportsImplicitEqualityAndNamePayload(t *testing.T) {
	m, h := newFake(t, "old-json")
	r, _ := validate(node())
	rows := portableRows("ip", m.table, portableOwner(m), r)
	var changed []any
	for _, item := range rows[4]["rule"].(map[string]any)["expr"].([]any) {
		expr := item.(map[string]any)
		if match, ok := expr["match"].(map[string]any); ok {
			delete(match, "op")
			left := match["left"].(map[string]any)
			if meta, ok := left["meta"].(map[string]any); ok {
				left["meta"] = meta["key"]
			}
			if p, ok := left["payload"].(map[string]any); ok {
				p["name"] = p["protocol"]
				delete(p, "protocol")
			}
		}
		changed = append(changed, expr)
	}
	rows[4]["rule"].(map[string]any)["expr"] = changed
	h.rows = rows
	view, err := inspectRows(t, rows, m)
	if err != nil || !view.families["ip"] || len(view.oldTargets) != 1 {
		t.Fatal("actual old JSON rejected", err)
	}
	if err := m.Update(node()); err != nil {
		t.Fatal(err)
	}
	want, _ := validate(node())
	for _, tc := range []struct {
		expr     string
		conflict bool
	}{
		{`[{"match":{"left":{"payload":{"name":"tcp","field":"dport"}},"right":22}},{"dnat":{"port":8080}}]`, false},
		{`[{"match":{"left":{"payload":{"name":"udp","field":"dport"}},"right":53}},{"redirect":{"port":53}}]`, false},
		{`[{"match":{"left":{"payload":{"name":"udp","field":"dport"}},"right":42450}},{"redirect":{"port":53}}]`, true},
		{`[{"match":{"op":"!=","left":{"payload":{"name":"udp","field":"dport"}},"right":53}},{"redirect":{"port":53}}]`, true},
	} {
		if got := (&inventory{rules: []nftRule{foreign(tc.expr, "ip")}}).conflicts(want) != nil; got != tc.conflict {
			t.Fatal("old-schema conflict guard widened", got, tc.conflict)
		}
	}
}

func TestModernNumericLocalAddressTypeIsVerifiedExactly(t *testing.T) {
	for _, local := range []int{2, 1, 0, 3} {
		m, h := newFake(t, "numeric-local")
		r, _ := validate(node())
		h.rows = portableRows("ip", m.table, portableOwner(m), r)
		expr := h.rows[4]["rule"].(map[string]any)["expr"].([]any)
		expr[0].(map[string]any)["match"].(map[string]any)["right"] = local
		_, err := inspectRows(t, h.rows, m)
		if (err == nil) != (local == 2) {
			t.Fatal("unknown address type accepted", local, err)
		}
	}
}

func TestForeignUnknownPayloadCannotProveNATDisjointness(t *testing.T) {
	want, _ := validate(node())
	for _, expr := range []string{
		`[{"match":{"left":{"payload":{"protocol":"tcp","field":"dport","unknown":true}},"right":22}},{"redirect":{"port":53}}]`,
		`[{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"},"unknown":true},"right":22}},{"redirect":{"port":53}}]`,
		`[{"match":{"left":{"payload":{"protocol":"udp","field":"dport"}},"right":null}},{"redirect":{"port":53}}]`,
		`[{"match":{"op":null,"left":{"payload":{"protocol":"udp","field":"dport"}},"right":53}},{"redirect":{"port":53}}]`,
		`[{"mangle":{"key":{"payload":{"protocol":"udp","field":"dport"}},"value":53}},{"match":{"left":{"payload":{"protocol":"udp","field":"dport"}},"right":53}},{"redirect":{"port":53}}]`,
		`[{"redirect":{"port":53}},{"match":{"left":{"payload":{"protocol":"udp","field":"dport"}},"right":53}}]`,
		`[{"unknown_action":{}},{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"redirect":{"port":53}}]`,
	} {
		if (&inventory{rules: []nftRule{foreign(expr, "ip")}}).conflicts(want) == nil {
			t.Fatal("unknown structure bypassed NAT overlap guard")
		}
	}
}
