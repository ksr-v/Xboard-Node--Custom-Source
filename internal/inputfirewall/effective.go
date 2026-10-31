package inputfirewall

import (
	"net/netip"
	"strconv"
)

// effectiveInput proves only simple filter decisions for a new inbound flow.
// Unknown host chains and packet conditions remain unknown; no guessed verdict
// is used to repair or authorize a rule. NAT, routes and cloud ACLs are outside
// this local INPUT observation.
func effectiveInput(s *snapshot, all map[string]ownedChain, l *listener) string {
	for _, rule := range s.input {
		matches, certain, target := simpleMatch(rule, l)
		if !matches {
			continue
		}
		if !certain {
			return "unknown"
		}
		switch target {
		case "ACCEPT":
			return "allowed"
		case "DROP", "REJECT":
			return "blocked"
		case "RETURN":
			return inputPolicy(s)
		default:
			owned, ok := all[target]
			if !ok {
				return "unknown"
			}
			for _, child := range owned.rules {
				matches, certain, target := simpleMatch(child, l)
				if !matches {
					continue
				}
				if !certain {
					return "unknown"
				}
				if target == "ACCEPT" {
					return "allowed"
				}
				if target == "RETURN" {
					break
				}
				return "unknown"
			}
		}
	}
	return inputPolicy(s)
}

func inputPolicy(s *snapshot) string {
	switch s.chains["INPUT"].policy {
	case "ACCEPT", "":
		return "allowed"
	case "DROP":
		return "blocked"
	}
	return "unknown"
}

// A known protocol or exact-port mismatch proves a rule cannot apply even when
// its other conditions are opaque. Otherwise every unrecognized predicate is
// retained as uncertainty instead of silently ignored.
func simpleMatch(rule []string, l *listener) (matches, certain bool, target string) {
	matches, certain = true, true
	protocol, port := "", ""
	var destination, source string
	for i := 0; i < len(rule); {
		if i+1 >= len(rule) {
			certain = false
			break
		}
		key, arg := rule[i], rule[i+1]
		i += 2
		switch key {
		case "-p", "--protocol":
			if protocol != "" {
				certain = false
			}
			protocol = arg
		case "--dport", "--destination-port":
			if port != "" {
				certain = false
			}
			port = arg
		case "-d", "--destination":
			destination = arg
		case "-s", "--source":
			source = arg
		case "-m", "--match":
			if arg != "tcp" && arg != "udp" && arg != "comment" {
				certain = false
			}
		case "--comment": // comment text is one opaque token
		case "-j", "--jump":
			if target != "" {
				certain = false
			}
			target = arg
		case "--reject-with":
		default:
			certain = false
		}
	}
	if protocol != "" && protocol != "all" && protocol != "0" {
		if protocol == "6" {
			protocol = "tcp"
		}
		if protocol == "17" {
			protocol = "udp"
		}
		if protocol != l.transport {
			return false, true, target
		}
	}
	if port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			certain = false
		} else if value != l.port {
			return false, true, target
		}
	}
	if destination != "" {
		prefix, err := netip.ParsePrefix(destination)
		if err != nil {
			if address, e := netip.ParseAddr(destination); e == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
				err = nil
			}
		}
		if err != nil {
			certain = false
		} else if l.address.IsValid() {
			if !prefix.Contains(l.address) {
				return false, true, target
			}
		} else if prefix.Bits() != 0 {
			certain = false
		}
	}
	if source != "" {
		prefix, err := netip.ParsePrefix(source)
		if err != nil || prefix.Bits() != 0 {
			certain = false
		}
	}
	if target == "" {
		certain = false
	}
	return matches, certain, target
}
