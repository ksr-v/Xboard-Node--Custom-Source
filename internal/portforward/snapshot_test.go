package portforward

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/nftsnapshot"
)

func missingCommentRows(m *Manager) []map[string]any {
	r, _ := validate(node())
	rows := legacyRows(m.table, m.marker, r)
	table := rows[0]["table"].(map[string]any)
	delete(table, "comment")
	table["handle"] = 7
	rows[1]["chain"].(map[string]any)["handle"] = 1
	rows[2]["rule"].(map[string]any)["handle"] = 2
	return rows
}

func snapshotJSON(rows []map[string]any) []byte {
	data, _ := json.Marshal(map[string]any{"nftables": rows})
	return data
}

func legacyText(m *Manager) string {
	return fmt.Sprintf("table inet %s { # handle 7\n\tcomment %q\n\tchain prerouting { # handle 1\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tmeta nfproto ipv4 fib daddr type local udp dport 42450-42453 counter packets 3 bytes 300 redirect to :42443 # handle 2\n\t}\n}\n", m.table, m.marker)
}

type snapshotReply struct {
	data []byte
	err  error
}

func snapshotQuery(t *testing.T, m *Manager, replies ...snapshotReply) (nftsnapshot.Query, *int) {
	t.Helper()
	calls := 0
	query := func(args ...string) ([]byte, error) {
		t.Helper()
		want := []string{"-j", "-nn", "list", "ruleset"}
		if calls == 1 {
			want = []string{"-a", "-nn", "list", "table", "inet", m.table}
		}
		if !reflect.DeepEqual(args, want) || calls >= len(replies) {
			t.Fatalf("unexpected read-only query %v at call %d", args, calls)
		}
		reply := replies[calls]
		calls++
		return reply.data, reply.err
	}
	return query, &calls
}

func TestNft106MissingTableCommentRecoveredFromExactOwner(t *testing.T) {
	m := New("nft106-exact-owner")
	first := snapshotJSON(missingCommentRows(m))
	latestRows := missingCommentRows(m)
	// Active traffic must not make a safe migration impossible.
	latestRows[2]["rule"].(map[string]any)["expr"].([]any)[4].(map[string]any)["counter"] = map[string]any{"packets": uint64(9007199254740993), "bytes": uint64(18446744073709551615)}
	latestRows = append(latestRows, tableRow("administrator_table", "foreign"))
	query, calls := snapshotQuery(t, m, snapshotReply{data: first}, snapshotReply{data: []byte(legacyText(m))}, snapshotReply{data: snapshotJSON(latestRows)})
	got, err := readSnapshot(query, m.table, m.marker)
	if err != nil || *calls != 3 {
		t.Fatal("safe omitted comment rejected", err, *calls)
	}
	view, err := inspect(got, m.table, m.marker)
	if err != nil || !view.owned || !view.families["inet"] || len(view.oldTargets) != 1 || view.oldTargets[0] != 42443 || !strings.Contains(string(got), "administrator_table") {
		t.Fatal("new inventory or strict ownership lost", err)
	}
}

func TestNft106ObservedDebian12LegacyJSON(t *testing.T) {
	m := New("198-44-123-139-8443-machine-13-6e166b|node:25|/etc/xboard-node/instances/198-44-123-139-8443-machine-13-6e166b/node-25")
	// Captured nft 1.0.6 structure: table comment omitted, and the udp payload
	// already implies the protocol, so no redundant meta l4proto is present.
	data := []byte(fmt.Sprintf(`{"nftables":[{"metainfo":{"version":"1.0.6","release_name":"Lester Gooch #5","json_schema_version":1}},{"table":{"family":"inet","name":%q,"handle":7}},{"chain":{"family":"inet","table":%q,"name":"prerouting","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},{"rule":{"family":"inet","table":%q,"chain":"prerouting","handle":2,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"fib":{"result":"type","flags":["daddr"]}},"right":"local"}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[46686,48778]}}},{"counter":{"packets":29163,"bytes":37248406}},{"redirect":{"port":46686}}]}}]}`, m.table, m.table, m.table))
	text := fmt.Sprintf("table inet %s { # handle 7\n\tcomment %q\n\tchain prerouting { # handle 1\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tmeta nfproto ipv4 fib daddr type local udp dport 46686-48778 counter packets 29163 bytes 37248406 redirect to :46686 # handle 2\n\t}\n}\n", m.table, m.marker)
	query, _ := snapshotQuery(t, m, snapshotReply{data: data}, snapshotReply{data: []byte(text)}, snapshotReply{data: data})
	got, err := readSnapshot(query, m.table, m.marker)
	if err != nil {
		t.Fatal("observed production legacy shape rejected", err)
	}
	view, err := inspect(got, m.table, m.marker)
	if err != nil || !view.owned || len(view.oldTargets) != 1 || view.oldTargets[0] != 46686 {
		t.Fatal("observed production legacy table not verified", err)
	}
}

type commentOmittingSystem struct {
	fakeSystem
	text string
}

func (s commentOmittingSystem) snapshot(table, marker string) ([]byte, error) {
	return readSnapshot(func(args ...string) ([]byte, error) {
		if len(args) == 6 && args[0] == "-a" {
			return []byte(s.text), nil
		}
		return snapshotJSON(s.host.rows), nil
	}, table, marker)
}

func TestNft106UpgradeMigratesAtomicallyAndCloseDeletesOnlyOwnTable(t *testing.T) {
	m, h := newFake(t, "nft106-upgrade")
	h.rows = append(missingCommentRows(m), tableRow("foreign_filter", "administrator"))
	m.system = commentOmittingSystem{fakeSystem{h}, legacyText(m)}
	h.failApply = true
	if m.Update(node()) == nil || tableCount(h.rows) != 2 {
		t.Fatal("rejected transaction changed old table")
	}
	h.failApply = false
	if err := m.Update(node()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.scripts[1], "delete table inet "+m.table+"\n") || !strings.Contains(h.scripts[1], "table ip "+m.table) {
		t.Fatal("migration is not one owned-table transaction", h.scripts[1])
	}
	if err := m.Close(); err != nil || tableCount(h.rows) != 1 || h.rows[0]["table"].(map[string]any)["name"] != "foreign_filter" {
		t.Fatal("cleanup touched foreign resources", err)
	}
}

func TestNft106TextOwnershipFailureNeverMutates(t *testing.T) {
	m := New("nft106-malformed-text")
	valid := legacyText(m)
	for name, text := range map[string]string{
		"missing":            strings.ReplaceAll(valid, "\tcomment "+fmt.Sprintf("%q", m.marker)+"\n", ""),
		"wrong-owner":        strings.ReplaceAll(valid, m.marker, "another-owner"),
		"duplicate":          strings.Replace(valid, "\tcomment", "\tcomment "+fmt.Sprintf("%q", m.marker)+"\n\tcomment", 1),
		"different-table":    strings.ReplaceAll(valid, m.table, "different"),
		"different-handle":   strings.Replace(valid, "# handle 7", "# handle 8", 1),
		"nested-comment":     strings.Replace(strings.Replace(valid, "\tcomment "+fmt.Sprintf("%q", m.marker)+"\n", "", 1), "\t\ttype", "\t\tcomment "+fmt.Sprintf("%q", m.marker)+"\n\t\ttype", 1),
		"escaped-comment":    strings.Replace(valid, "comment "+fmt.Sprintf("%q", m.marker), "comment \"spoof\\\" }\\n comment "+m.marker+"\"", 1),
		"extra-table":        valid + valid,
		"inline-extra-table": strings.Replace(valid, "\t}\n", "\t} } table inet foreign {\n", 1),
		"extra-root":         strings.Replace(valid, "\tchain", "\tset foreign { type inet_service; }\n\tchain", 1),
		"foreign-chain":      strings.Replace(valid, "chain prerouting", "chain foreign", 1),
		"unbalanced":         strings.TrimSuffix(valid, "}\n"),
		"oversized":          strings.Repeat(" ", nftsnapshot.MaxOutput+1),
		"empty":              "",
	} {
		t.Run(name, func(t *testing.T) {
			n, h := newFake(t, "nft106-malformed-text")
			h.rows = missingCommentRows(n)
			n.system = commentOmittingSystem{fakeSystem{h}, text}
			if n.Update(node()) == nil || len(h.scripts) != 0 || tableCount(h.rows) != 1 {
				t.Fatal("unproven text ownership changed firewall")
			}
		})
	}
}

func TestNft106ExplicitCommentsNeverUseTextFallback(t *testing.T) {
	for name, comment := range map[string]any{"empty": "", "null": nil, "foreign": "another-owner", "wrong-type": 7} {
		t.Run(name, func(t *testing.T) {
			m := New("explicit-comment")
			rows := missingCommentRows(m)
			rows[0]["table"].(map[string]any)["comment"] = comment
			query, calls := snapshotQuery(t, m, snapshotReply{data: snapshotJSON(rows)})
			got, err := readSnapshot(query, m.table, m.marker)
			if err != nil || *calls != 1 {
				t.Fatal("explicit comment used compatibility fallback", err)
			}
			if _, err := inspect(got, m.table, m.marker); err == nil {
				t.Fatal("invalid explicit ownership accepted")
			}
		})
	}
}

func TestNft106UnknownJSONOrNamespaceCannotGainOwnership(t *testing.T) {
	for name, mutate := range map[string]func([]map[string]any) []byte{
		"duplicate-json-key": func(rows []map[string]any) []byte {
			return []byte(strings.Replace(string(snapshotJSON(rows)), `"handle":7`, `"handle":6,"handle":7`, 1))
		},
		"duplicate-entry": func(rows []map[string]any) []byte { return snapshotJSON(append(rows, rows[0])) },
		"unknown-field": func(rows []map[string]any) []byte {
			rows[0]["table"].(map[string]any)["unknown"] = true
			return snapshotJSON(rows)
		},
		"missing-handle": func(rows []map[string]any) []byte {
			delete(rows[0]["table"].(map[string]any), "handle")
			return snapshotJSON(rows)
		},
		"extra-rule": func(rows []map[string]any) []byte { return snapshotJSON(append(rows, rows[2])) },
		"extra-set": func(rows []map[string]any) []byte {
			table := rows[0]["table"].(map[string]any)["name"]
			return snapshotJSON(append(rows, map[string]any{"set": map[string]any{"family": "inet", "table": table, "name": "administrator"}}))
		},
		"extra-top-level": func(rows []map[string]any) []byte {
			return []byte(strings.TrimSuffix(string(snapshotJSON(rows)), "}") + `,"unexpected":true}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := New("untrusted-inventory")
			query, calls := snapshotQuery(t, m, snapshotReply{data: mutate(missingCommentRows(m))})
			got, err := readSnapshot(query, m.table, m.marker)
			if err == nil || len(got) != 0 || *calls != 1 {
				t.Fatal("unsafe JSON gained text ownership", err, *calls)
			}
		})
	}
}

func TestNft106ChangedNamespaceBetweenObservationsIsRejected(t *testing.T) {
	for name, mutate := range map[string]func([]map[string]any) []map[string]any{
		"table-handle": func(rows []map[string]any) []map[string]any {
			rows[0]["table"].(map[string]any)["handle"] = 8
			return rows
		},
		"rule-handle": func(rows []map[string]any) []map[string]any {
			rows[2]["rule"].(map[string]any)["handle"] = 3
			return rows
		},
		"redirect": func(rows []map[string]any) []map[string]any {
			expr := rows[2]["rule"].(map[string]any)["expr"].([]any)
			expr[len(expr)-1] = map[string]any{"redirect": map[string]any{"port": 42444}}
			return rows
		},
		"comment-added": func(rows []map[string]any) []map[string]any {
			rows[0]["table"].(map[string]any)["comment"] = "foreign"
			return rows
		},
		"rule-removed": func(rows []map[string]any) []map[string]any { return rows[:2] },
		"chain-changed": func(rows []map[string]any) []map[string]any {
			rows[1]["chain"].(map[string]any)["prio"] = -99
			return rows
		},
		"set-added": func(rows []map[string]any) []map[string]any {
			return append(rows, map[string]any{"set": map[string]any{"family": "inet", "table": rows[0]["table"].(map[string]any)["name"], "name": "new"}})
		},
		"table-removed": func([]map[string]any) []map[string]any { return []map[string]any{} },
	} {
		t.Run(name, func(t *testing.T) {
			m := New("racing-inventory")
			query, _ := snapshotQuery(t, m, snapshotReply{data: snapshotJSON(missingCommentRows(m))}, snapshotReply{data: []byte(legacyText(m))}, snapshotReply{data: snapshotJSON(mutate(missingCommentRows(m)))})
			if got, err := readSnapshot(query, m.table, m.marker); err == nil || len(got) != 0 {
				t.Fatal("changed namespace accepted")
			}
		})
	}
}

func TestNft106ReadErrorsPreserveOwnershipBoundary(t *testing.T) {
	for _, failingCall := range []int{1, 2} {
		m := New("failed-query")
		replies := []snapshotReply{{data: snapshotJSON(missingCommentRows(m))}, {data: []byte(legacyText(m))}, {data: snapshotJSON(missingCommentRows(m))}}
		replies[failingCall].err = errors.New("query failed")
		query, _ := snapshotQuery(t, m, replies...)
		if got, err := readSnapshot(query, m.table, m.marker); err == nil || len(got) != 0 {
			t.Fatal("failed independent query accepted")
		}
	}
}
