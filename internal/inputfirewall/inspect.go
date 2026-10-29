package inputfirewall

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

const maxOutput = 16 << 20

type chain struct {
	policy string
	rules  [][]string
}
type snapshot struct {
	chains map[string]chain
	input  [][]string
}
type ownedChain struct {
	name, marker string
	rules, jumps [][]string
	positions    []int // one-based INPUT positions
}

var chainName = regexp.MustCompile(`^[A-Za-z0-9_.:+-]{1,64}$`)
var counters = regexp.MustCompile(`^\[[0-9]+:[0-9]+\]$`)

func inspectSave(data []byte) (*snapshot, error) {
	if len(data) > maxOutput || bytes.IndexByte(data, 0) >= 0 {
		return nil, errRules
	}
	s := &snapshot{chains: make(map[string]chain)}
	inside, done := false, false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 1<<20 {
			return nil, errRules
		}
		if line == "*filter" {
			if inside || done {
				return nil, errRules
			}
			inside = true
			continue
		}
		if line == "COMMIT" {
			if !inside {
				return nil, errRules
			}
			inside = false
			done = true
			continue
		}
		if !inside {
			return nil, errRules
		}
		if strings.HasPrefix(line, ":") {
			parts := strings.Fields(line[1:])
			if len(parts) != 3 || !chainName.MatchString(parts[0]) || !counters.MatchString(parts[2]) {
				return nil, errRules
			}
			if _, exists := s.chains[parts[0]]; exists {
				return nil, errRules
			}
			if parts[1] != "-" && parts[1] != "ACCEPT" && parts[1] != "DROP" {
				return nil, errRules
			}
			s.chains[parts[0]] = chain{policy: parts[1]}
			continue
		}
		tokens, err := splitRule(line)
		if err != nil {
			return nil, errRules
		}
		if len(tokens) > 0 && counters.MatchString(tokens[0]) {
			tokens = tokens[1:]
		}
		if len(tokens) < 3 || tokens[0] != "-A" {
			return nil, errRules
		}
		entry, exists := s.chains[tokens[1]]
		if !exists {
			return nil, errRules
		}
		entry.rules = append(entry.rules, append([]string(nil), tokens[2:]...))
		s.chains[tokens[1]] = entry
	}
	if inside || (!done && len(s.chains) > 0) {
		return nil, errRules
	}
	if input, exists := s.chains["INPUT"]; exists && input.policy == "-" {
		return nil, errRules
	}
	s.input = s.chains["INPUT"].rules
	return s, nil
}

// splitRule handles the quoting emitted by both iptables-save implementations.
// It deliberately does not expand variables, substitutions, escapes or commands.
func splitRule(line string) ([]string, error) {
	var result []string
	var token strings.Builder
	quoteByte := byte(0)
	started := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '\r' || ch == '\n' || ch == 0 {
			return nil, errRules
		}
		if ch == '\\' && quoteByte != '\'' {
			i++
			if i == len(line) {
				return nil, errRules
			}
			token.WriteByte(line[i])
			started = true
			continue
		}
		if quoteByte != 0 {
			if ch == quoteByte {
				quoteByte = 0
			} else {
				token.WriteByte(ch)
			}
			started = true
			continue
		}
		if ch == '\'' || ch == '"' {
			quoteByte = ch
			started = true
			continue
		}
		if ch == ' ' || ch == '\t' {
			if started {
				result = append(result, token.String())
				token.Reset()
				started = false
			}
			continue
		}
		if ch < 32 || ch == 127 {
			return nil, errRules
		}
		token.WriteByte(ch)
		started = true
	}
	if quoteByte != 0 {
		return nil, errRules
	}
	if started {
		result = append(result, token.String())
	}
	return result, nil
}

func owned(s *snapshot) (map[string]ownedChain, error) {
	result := make(map[string]ownedChain)
	for name, entry := range s.chains {
		if !strings.HasPrefix(name, chainPrefix) {
			continue
		}
		if len(name) != len(chainPrefix)+20 || !lowerHex(name[len(chainPrefix):], 20) || entry.policy != "-" || len(entry.rules) != 2 {
			return nil, errOwnership
		}
		allow, ok := parseOwned(entry.rules[0], "ACCEPT")
		if !ok {
			return nil, errOwnership
		}
		ret, ok := parseOwned(entry.rules[1], "RETURN")
		if !ok || allow.marker != ret.marker || name != chainPrefix+strings.TrimPrefix(allow.marker, markerPrefix)[:20] {
			return nil, errOwnership
		}
		result[name] = ownedChain{name: name, marker: allow.marker, rules: entry.rules}
	}
	for source, entry := range s.chains {
		for position, rule := range entry.rules {
			// Any mention outside its strict own body is treated conservatively.
			// In particular, goto and conditional/foreign jumps must not be lost.
			var referenced string
			for _, token := range rule {
				if strings.HasPrefix(token, chainPrefix) {
					if referenced != "" && referenced != token {
						return nil, errOwnership
					}
					referenced = token
				}
			}
			if referenced == "" {
				continue
			}
			owner, exists := result[referenced]
			if !exists || source != "INPUT" || !isJump(rule, owner.marker, referenced) {
				return nil, errOwnership
			}
			owner.jumps = append(owner.jumps, rule)
			owner.positions = append(owner.positions, position+1)
			result[referenced] = owner
		}
	}
	return result, nil
}

type ownedRule struct {
	marker, address string
	port            int
}

func parseOwned(tokens []string, target string) (ownedRule, bool) {
	var value ownedRule
	seen := make(map[string]bool)
	modules := make(map[string]bool)
	jump, protocol := "", ""
	for i := 0; i < len(tokens); i += 2 {
		if i+1 >= len(tokens) {
			return value, false
		}
		key, arg := tokens[i], tokens[i+1]
		if key == "-m" {
			if modules[arg] || (arg != "udp" && arg != "comment") {
				return value, false
			}
			modules[arg] = true
			continue
		}
		if seen[key] {
			return value, false
		}
		seen[key] = true
		switch key {
		case "-p":
			protocol = arg
		case "-d":
			address, err := netip.ParsePrefix(arg)
			if err != nil {
				a, err := netip.ParseAddr(arg)
				if err != nil || a.Zone() != "" {
					return value, false
				}
				address = netip.PrefixFrom(a, a.BitLen())
			}
			if address.Bits() != address.Addr().BitLen() || address.Addr().Zone() != "" {
				return value, false
			}
			value.address = address.String()
		case "--dport":
			port, err := strconv.Atoi(arg)
			if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != arg {
				return value, false
			}
			value.port = port
		case "--comment":
			value.marker = arg
		case "-j":
			jump = arg
		default:
			return value, false
		}
	}
	if jump != target || !validMarker(value.marker) || !modules["comment"] {
		return value, false
	}
	if target == "RETURN" {
		return value, len(seen) == 2 && len(modules) == 1
	}
	return value, protocol == "udp" && value.port > 0 && modules["udp"] && len(modules) == 2 && (len(seen) == 4 || len(seen) == 5 && value.address != "")
}

func validMarker(marker string) bool {
	return strings.HasPrefix(marker, markerPrefix) && lowerHex(strings.TrimPrefix(marker, markerPrefix), 64)
}
func lowerHex(value string, n int) bool {
	if len(value) != n || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func jumpTarget(rule []string) string {
	for i := 0; i+1 < len(rule); i++ {
		if rule[i] == "-j" || rule[i] == "-g" {
			return rule[i+1]
		}
	}
	return ""
}
func isJump(tokens []string, marker, name string) bool {
	if len(tokens) != 6 {
		return false
	}
	seen := make(map[string]string)
	for i := 0; i < len(tokens); i += 2 {
		key, value := tokens[i], tokens[i+1]
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = value
	}
	return len(seen) == 3 && seen["-m"] == "comment" && seen["--comment"] == marker && seen["-j"] == name
}

func sameBody(a, b ownedChain) bool {
	if a.name != b.name || a.marker != b.marker || len(a.rules) != 2 || len(b.rules) != 2 {
		return false
	}
	for i, target := range []string{"ACCEPT", "RETURN"} {
		x, xok := parseOwned(a.rules[i], target)
		y, yok := parseOwned(b.rules[i], target)
		if !xok || !yok || !reflect.DeepEqual(x, y) {
			return false
		}
	}
	return true
}

func inspectNft(data []byte) error {
	if len(data) > maxOutput {
		return errRules
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return errRules
	}
	var rows []map[string]json.RawMessage
	if raw, ok := top["nftables"]; !ok || string(raw) == "null" || json.Unmarshal(raw, &rows) != nil {
		return errRules
	}
	for _, row := range rows {
		if len(row) == 0 {
			return errRules
		}
		raw, ok := row["chain"]
		if !ok {
			continue
		}
		var c struct {
			Family, Table, Name, Type, Hook string
			Prio                            json.RawMessage
		}
		if json.Unmarshal(raw, &c) != nil || c.Family == "" || c.Table == "" || c.Name == "" {
			return errRules
		}
		if c.Hook == "" {
			continue
		}
		if c.Hook != "input" {
			continue
		}
		if c.Type == "nat" {
			continue
		}
		if c.Type != "filter" {
			return errUnsupported
		}
		if (c.Family != "ip" && c.Family != "ip6") || c.Table != "filter" || c.Name != "INPUT" {
			return errUnsupported
		}
		var priority int
		if len(c.Prio) == 0 || json.Unmarshal(c.Prio, &priority) != nil || priority != 0 {
			return errUnsupported
		}
	}
	return nil
}
