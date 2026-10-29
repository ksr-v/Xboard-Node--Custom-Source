package portforward

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

func ownedError() error {
	return fmt.Errorf("UDP port hopping owned NAT metadata or rules contain unknown resources; refusing replacement (no rules changed)")
}

// verifyOwnedTable checks the entire namespace before a whole-table delete.
// Missing forwarding resources may be repaired after a reload, but the full
// v1 table marker or v2 unhooked sentinel must remain independently provable.
func verifyOwnedTable(rows []map[string]json.RawMessage, family, table, marker string) ([]int, error) {
	portable := family != "inet"
	portableMarker := portableMarkerPrefix + strings.TrimPrefix(marker, markerPrefix)
	chains := make(map[string]bool)
	rules := make(map[string][]nftRule)
	for _, row := range rows {
		for kind, raw := range row {
			var loc struct{ Family, Table, Name string }
			if json.Unmarshal(raw, &loc) != nil {
				return nil, ownedError()
			}
			if kind == "table" {
				if loc.Family != family || loc.Name != table {
					continue
				}
				fields, ok := object(raw, "family", "name", "handle", "comment", "flags")
				if !ok {
					return nil, ownedError()
				}
				if flags, exists := fields["flags"]; exists {
					var f []string
					if json.Unmarshal(flags, &f) != nil || len(f) != 0 {
						return nil, ownedError()
					}
				}
				var comment string
				if c, exists := fields["comment"]; exists && json.Unmarshal(c, &comment) != nil {
					return nil, ownedError()
				}
				if portable && comment != "" || !portable && comment != marker {
					return nil, ownedError()
				}
				continue
			}
			if loc.Family != family || loc.Table != table {
				continue
			}
			switch kind {
			case "chain":
				if chains[loc.Name] || loc.Name != "prerouting" && (!portable || loc.Name != ownerChain) {
					return nil, ownedError()
				}
				if loc.Name == ownerChain {
					if _, ok := object(raw, "family", "table", "name", "handle"); !ok {
						return nil, ownedError()
					}
				} else {
					fields, ok := object(raw, "family", "table", "name", "handle", "type", "hook", "prio", "policy")
					if !ok || stringValue(fields["type"]) != "nat" || stringValue(fields["hook"]) != "prerouting" || stringValue(fields["policy"]) != "accept" {
						return nil, ownedError()
					}
					var priority int
					if json.Unmarshal(fields["prio"], &priority) != nil || priority != -100 {
						return nil, ownedError()
					}
				}
				chains[loc.Name] = true
			case "rule":
				if _, ok := object(raw, "family", "table", "chain", "handle", "expr", "comment"); !ok {
					return nil, ownedError()
				}
				var r nftRule
				if json.Unmarshal(raw, &r) != nil || r.Expr == nil {
					return nil, ownedError()
				}
				rules[r.Chain] = append(rules[r.Chain], r)
			default:
				// Sets, maps, objects, foreign references and future extensions
				// inside our name are not implicitly authorized for deletion.
				return nil, ownedError()
			}
		}
	}
	for name := range rules {
		if !chains[name] {
			return nil, ownedError()
		}
	}
	if portable {
		if !chains[ownerChain] || len(rules[ownerChain]) != 1 {
			return nil, ownedError()
		}
		r := rules[ownerChain][0]
		if r.Comment != portableMarker || len(r.Expr) != 1 || len(r.Expr[0]) != 1 || string(r.Expr[0]["return"]) != "null" {
			return nil, ownedError()
		}
	}
	if len(rules["prerouting"]) > 1 {
		return nil, ownedError()
	}
	var targets []int
	for _, r := range rules["prerouting"] {
		expected := ""
		if portable {
			expected = portableMarker
		}
		if r.Comment != expected {
			return nil, ownedError()
		}
		target, ok := parseOwnedRedirect(r, family)
		if !ok {
			return nil, ownedError()
		}
		targets = append(targets, target.target)
	}
	return targets, nil
}

func object(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, bool) {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return nil, false
	}
	for key := range value {
		found := false
		for _, candidate := range allowed {
			if candidate == key {
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return value, true
}
func stringValue(raw json.RawMessage) string { var s string; _ = json.Unmarshal(raw, &s); return s }

// nft 0.9.0 uses a string for meta and payload.name; newer releases use
// {key:...} and payload.protocol. It also omits op for equality (but emits !=).
func metaKey(raw json.RawMessage) (string, bool) {
	var key string
	if json.Unmarshal(raw, &key) == nil {
		return key, key != ""
	}
	fields, ok := object(raw, "key")
	if !ok || len(fields) != 1 {
		return "", false
	}
	key = stringValue(fields["key"])
	return key, key != ""
}

func payload(raw json.RawMessage) (string, string, bool) {
	fields, ok := object(raw, "protocol", "name", "field")
	if !ok {
		return "", "", false
	}
	protocol, name := "", ""
	if raw, exists := fields["protocol"]; exists {
		if json.Unmarshal(raw, &protocol) != nil || protocol == "" {
			return "", "", false
		}
	}
	if raw, exists := fields["name"]; exists {
		if json.Unmarshal(raw, &name) != nil || name == "" {
			return "", "", false
		}
	}
	if protocol == "" {
		protocol = name
	} else if name != "" && name != protocol {
		return "", "", false
	}
	field := stringValue(fields["field"])
	return protocol, field, protocol != "" && field != ""
}

func isEnum(raw json.RawMessage, text string, number int) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == text
	}
	var n int
	return json.Unmarshal(raw, &n) == nil && n == number
}

func parseOwnedRedirect(rule nftRule, family string) (*redirect, bool) {
	r := &redirect{}
	if family == "ip" {
		r.family = 4
	} else if family == "ip6" {
		r.family = 6
	}
	if len(rule.Expr) < 4 {
		return nil, false
	}
	seen := make(map[string]bool)
	for i, expr := range rule.Expr {
		if len(expr) != 1 {
			return nil, false
		}
		if i == len(rule.Expr)-2 {
			raw, ok := expr["counter"]
			if !ok {
				return nil, false
			}
			counter, ok := object(raw, "packets", "bytes")
			if !ok || len(counter) != 2 {
				return nil, false
			}
			for _, value := range counter {
				var count uint64
				if len(value) == 0 || value[0] < '0' || value[0] > '9' || json.Unmarshal(value, &count) != nil {
					return nil, false
				}
			}
			continue
		}
		if i == len(rule.Expr)-1 {
			raw, ok := expr["redirect"]
			if !ok {
				return nil, false
			}
			destination, ok := object(raw, "port")
			if !ok || len(destination) != 1 || json.Unmarshal(destination["port"], &r.target) != nil || r.target < 1 || r.target > 65535 {
				return nil, false
			}
			continue
		}
		raw, ok := expr["match"]
		if !ok {
			return nil, false
		}
		match, ok := object(raw, "op", "left", "right")
		if !ok {
			return nil, false
		}
		if raw, exists := match["op"]; exists {
			var op string
			if json.Unmarshal(raw, &op) != nil || op != "==" {
				return nil, false
			}
		}
		left, ok := object(match["left"], "fib", "meta", "payload")
		if !ok || len(left) != 1 {
			return nil, false
		}
		right := match["right"]
		var key string
		if fib, exists := left["fib"]; exists {
			key = "fib"
			fields, ok := object(fib, "result", "flags")
			if !ok || len(fields) != 2 || stringValue(fields["result"]) != "type" || !isEnum(right, "local", 2) {
				return nil, false
			}
			var flags []string
			if json.Unmarshal(fields["flags"], &flags) != nil || len(flags) != 1 || flags[0] != "daddr" {
				return nil, false
			}
		} else if meta, exists := left["meta"]; exists {
			name, ok := metaKey(meta)
			if !ok {
				return nil, false
			}
			key = name
			switch name {
			case "l4proto":
				if !isEnum(right, "udp", 17) {
					return nil, false
				}
			case "nfproto":
				selected := 0
				if isEnum(right, "ipv4", 2) {
					selected = 4
				} else if isEnum(right, "ipv6", 10) {
					selected = 6
				} else {
					return nil, false
				}
				if r.family != 0 && r.family != selected {
					return nil, false
				}
				r.family = selected
			default:
				return nil, false
			}
		} else if p, exists := left["payload"]; exists {
			protocol, field, ok := payload(p)
			if !ok {
				return nil, false
			}
			if protocol == "udp" && field == "dport" {
				key = "ports"
				ranges, ok := portRanges(right)
				if !ok || len(ranges) != 1 || ranges[0][0] < 1 {
					return nil, false
				}
				r.start, r.end = ranges[0][0], ranges[0][1]
			} else if (protocol == "ip" || protocol == "ip6") && field == "daddr" {
				key = "address"
				address, ok := exactAddress(right)
				if !ok {
					return nil, false
				}
				selected := 6
				if address.Is4() {
					selected = 4
				}
				if protocol == "ip" && selected != 4 || protocol == "ip6" && selected != 6 || r.family != 0 && r.family != selected {
					return nil, false
				}
				r.family = selected
				r.address = address
			} else {
				return nil, false
			}
		}
		if key == "" || seen[key] {
			return nil, false
		}
		seen[key] = true
	}
	return r, seen["fib"] && seen["ports"]
}

func exactAddress(raw json.RawMessage) (netip.Addr, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if address, err := netip.ParseAddr(text); err == nil && address.Zone() == "" {
			return address.Unmap(), true
		}
		if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Bits() == prefix.Addr().BitLen() {
			return prefix.Addr().Unmap(), true
		}
		return netip.Addr{}, false
	}
	value, ok := object(raw, "prefix")
	if !ok || len(value) != 1 {
		return netip.Addr{}, false
	}
	prefix, ok := object(value["prefix"], "addr", "len")
	if !ok || len(prefix) != 2 {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(stringValue(prefix["addr"]))
	var bits int
	if err != nil || address.Zone() != "" || json.Unmarshal(prefix["len"], &bits) != nil || bits != address.BitLen() {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}
