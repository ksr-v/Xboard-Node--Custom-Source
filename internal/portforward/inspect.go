package portforward

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
)

type nftTable struct{ Family, Name, Comment string }
type nftRule struct {
	Family string                       `json:"family"`
	Table  string                       `json:"table"`
	Chain  string                       `json:"chain"`
	Expr   []map[string]json.RawMessage `json:"expr"`
}
type inventory struct {
	owned      bool
	rules      []nftRule
	oldTargets []int
}

func inspect(data []byte, table, marker string) (*inventory, error) {
	var doc struct {
		Entries *[]map[string]json.RawMessage `json:"nftables"`
	}
	if len(data) > 16<<20 || json.Unmarshal(data, &doc) != nil || doc.Entries == nil {
		return nil, fmt.Errorf("UDP port hopping cannot safely parse the nftables ruleset; no rules changed")
	}
	v := &inventory{}
	for _, entry := range *doc.Entries {
		if raw, ok := entry["table"]; ok {
			var t nftTable
			if json.Unmarshal(raw, &t) != nil || t.Name == "" || t.Family == "" {
				return nil, fmt.Errorf("UDP port hopping cannot safely parse an nftables table; no rules changed")
			}
			if t.Family == "inet" && t.Name == table {
				if t.Comment != marker || v.owned {
					return nil, fmt.Errorf("UDP port hopping table %s has a foreign or duplicate ownership marker; refusing replacement", table)
				}
				v.owned = true
			}
		}
		if raw, ok := entry["rule"]; ok {
			var r nftRule
			if json.Unmarshal(raw, &r) != nil || r.Family == "" || r.Table == "" || r.Chain == "" || r.Expr == nil {
				return nil, fmt.Errorf("UDP port hopping cannot safely parse an nftables rule; no rules changed")
			}
			v.rules = append(v.rules, r)
		}
	}
	// Ignore a rule only after the containing table's full marker was verified.
	filtered := v.rules[:0]
	for _, r := range v.rules {
		if v.owned && r.Family == "inet" && r.Table == table {
			for _, expr := range r.Expr {
				if raw, ok := expr["redirect"]; ok {
					var target struct {
						Port int `json:"port"`
					}
					if json.Unmarshal(raw, &target) == nil && target.Port > 0 && target.Port <= 65535 {
						v.oldTargets = append(v.oldTargets, target.Port)
					}
				}
			}
		} else {
			filtered = append(filtered, r)
		}
	}
	v.rules = filtered
	return v, nil
}

func (v *inventory) conflicts(want *redirect) error {
	for _, rule := range v.rules {
		hasNAT := false
		for _, e := range rule.Expr {
			for _, key := range []string{"dnat", "redirect", "tproxy"} {
				if _, ok := e[key]; ok {
					hasNAT = true
				}
			}
		}
		if !hasNAT || disjoint(rule, want) {
			continue
		}
		// Do not include comments or arbitrary expression data in errors.
		return fmt.Errorf("UDP port hopping conflicts with a possibly overlapping existing NAT rule in %s table %q chain %q; choose a disjoint range/address or reconcile that rule manually (no rules changed)", rule.Family, rule.Table, rule.Chain)
	}
	return nil
}

func disjoint(rule nftRule, want *redirect) bool {
	if (want.family == 4 && rule.Family == "ip6") || (want.family == 6 && rule.Family == "ip") {
		return true
	}
	for _, e := range rule.Expr {
		raw, ok := e["match"]
		if !ok {
			continue
		}
		var match struct {
			Op    string                     `json:"op"`
			Left  map[string]json.RawMessage `json:"left"`
			Right json.RawMessage            `json:"right"`
		}
		if json.Unmarshal(raw, &match) != nil || (match.Op != "==" && match.Op != "in") {
			continue
		}
		if metaRaw, ok := match.Left["meta"]; ok {
			var meta struct {
				Key string `json:"key"`
			}
			if json.Unmarshal(metaRaw, &meta) == nil {
				if meta.Key == "l4proto" && excludesValue(match.Right, "udp", 17) {
					return true
				}
				if meta.Key == "nfproto" && want.family != 0 {
					name, number := "ipv4", 2
					if want.family == 6 {
						name, number = "ipv6", 10
					}
					if excludesValue(match.Right, name, number) {
						return true
					}
				}
			}
		}
		if payloadRaw, ok := match.Left["payload"]; ok {
			var p struct {
				Protocol string `json:"protocol"`
				Field    string `json:"field"`
			}
			if json.Unmarshal(payloadRaw, &p) != nil {
				continue
			}
			// A transport payload match implies its protocol, even without an
			// explicit meta l4proto selector in nft's JSON representation.
			if p.Protocol == "tcp" || p.Protocol == "sctp" || p.Protocol == "dccp" || p.Protocol == "icmp" || p.Protocol == "icmpv6" {
				return true
			}
			if (p.Protocol == "ip6" && want.family == 4) || (p.Protocol == "ip" && want.family == 6) {
				return true
			}
			if p.Protocol == "udp" && p.Field == "dport" {
				if ranges, ok := portRanges(match.Right); ok {
					overlaps := false
					for _, r := range ranges {
						if r[0] <= want.end && want.start <= r[1] {
							overlaps = true
						}
					}
					if !overlaps {
						return true
					}
				}
			}
			if (p.Protocol == "ip" || p.Protocol == "ip6") && p.Field == "daddr" && want.address.IsValid() {
				if includes, known := addressIncludes(match.Right, want.address); known && !includes {
					return true
				}
			}
		}
	}
	return false
}

// A value/set is only used to prove non-overlap when every item is understood.
// Named sets, expressions and inverted matches remain conservative conflicts.
func excludesValue(raw json.RawMessage, text string, number int) bool {
	var str string
	if json.Unmarshal(raw, &str) == nil {
		known := map[string]bool{"tcp": true, "udp": true, "sctp": true, "dccp": true, "icmp": true, "icmpv6": true, "esp": true, "ah": true, "gre": true, "udplite": true}
		if text == "ipv4" || text == "ipv6" {
			known = map[string]bool{"ipv4": true, "ipv6": true, "arp": true, "bridge": true, "netdev": true}
		}
		return known[str] && str != text
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n != number
	}
	var set struct {
		Values []json.RawMessage `json:"set"`
	}
	if json.Unmarshal(raw, &set) == nil && len(set.Values) > 0 {
		for _, item := range set.Values {
			if !excludesValue(item, text, number) {
				return false
			}
		}
		return true
	}
	return false
}

func portRanges(raw json.RawMessage) ([][2]int, bool) {
	var n int
	if json.Unmarshal(raw, &n) == nil && n >= 0 && n <= 65535 {
		return [][2]int{{n, n}}, true
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return nil, false
	}
	if r, ok := value["range"]; ok {
		var pair []int
		if json.Unmarshal(r, &pair) == nil && len(pair) == 2 && pair[0] >= 0 && pair[0] <= pair[1] && pair[1] <= 65535 {
			return [][2]int{{pair[0], pair[1]}}, true
		}
	}
	if set, ok := value["set"]; ok {
		var items []json.RawMessage
		if json.Unmarshal(set, &items) != nil || len(items) == 0 {
			return nil, false
		}
		var all [][2]int
		for _, item := range items {
			r, known := portRanges(item)
			if !known {
				return nil, false
			}
			all = append(all, r...)
		}
		return all, true
	}
	return nil, false
}

func addressIncludes(raw json.RawMessage, address netip.Addr) (bool, bool) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if a, err := netip.ParseAddr(text); err == nil {
			return a.Unmap() == address, true
		}
		if p, err := netip.ParsePrefix(text); err == nil {
			return p.Contains(address), true
		}
		return false, false
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return false, false
	}
	if prefix, ok := value["prefix"]; ok {
		var p struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		if json.Unmarshal(prefix, &p) == nil {
			if parsed, err := netip.ParsePrefix(p.Addr + "/" + strconv.Itoa(p.Len)); err == nil {
				return parsed.Contains(address), true
			}
		}
	}
	if set, ok := value["set"]; ok {
		var items []json.RawMessage
		if json.Unmarshal(set, &items) != nil || len(items) == 0 {
			return false, false
		}
		any := false
		for _, item := range items {
			yes, known := addressIncludes(item, address)
			if !known {
				return false, false
			}
			any = any || yes
		}
		return any, true
	}
	return false, false
}
