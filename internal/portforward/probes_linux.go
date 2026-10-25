//go:build linux

package portforward

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type udpSocket struct {
	address netip.Addr
	port    int
	inode   string
	dual    bool
}

func parseUDPSockets(data []byte, ipv6 bool) ([]udpSocket, error) {
	var result []udpSocket
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "sl" {
			continue
		}
		if len(fields) < 10 {
			return nil, fmt.Errorf("cannot parse UDP socket metadata")
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("cannot parse UDP local endpoint")
		}
		port, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil {
			return nil, fmt.Errorf("cannot parse UDP local port")
		}
		raw, err := hex.DecodeString(parts[0])
		if err != nil || (!ipv6 && len(raw) != 4) || (ipv6 && len(raw) != 16) {
			return nil, fmt.Errorf("cannot parse UDP local address")
		}
		for i := 0; i < len(raw); i += 4 {
			v := binary.BigEndian.Uint32(raw[i : i+4])
			binary.NativeEndian.PutUint32(raw[i:i+4], v)
		}
		address, _ := netip.AddrFromSlice(raw)
		result = append(result, udpSocket{address: address.Unmap(), port: int(port), inode: fields[9], dual: ipv6 && address.IsUnspecified()})
	}
	return result, nil
}

func socketOverlaps(s udpSocket, r *redirect) bool {
	if s.port < r.start || s.port > r.end {
		return false
	}
	if !s.dual && ((r.family == 4 && !s.address.Is4()) || (r.family == 6 && s.address.Is4())) {
		return false
	}
	if r.address.IsValid() && !s.address.IsUnspecified() && r.address != s.address {
		return false
	}
	return true
}

func checkSockets(sockets []udpSocket, r *redirect, oldTargets []int, ownInodes map[string]bool) error {
	allowed := map[int]bool{r.target: true}
	for _, p := range oldTargets {
		allowed[p] = true
	}
	for _, s := range sockets {
		if !socketOverlaps(s, r) {
			continue
		}
		if allowed[s.port] && ownInodes[s.inode] {
			continue
		}
		return fmt.Errorf("UDP port hopping range overlaps an existing UDP socket on port %d; choose another range (existing service and rules were not changed)", s.port)
	}
	return nil
}

func (linuxSystem) verify(r *redirect, oldTargets []int) error {
	var sockets []udpSocket
	for _, name := range []string{"udp", "udp6"} {
		data, err := os.ReadFile("/proc/self/net/" + name)
		if os.IsNotExist(err) && name == "udp6" {
			continue
		}
		if err != nil {
			return fmt.Errorf("UDP port hopping cannot inspect local UDP sockets; no rules changed: %w", err)
		}
		rows, err := parseUDPSockets(data, name == "udp6")
		if err != nil {
			return fmt.Errorf("UDP port hopping cannot inspect local UDP sockets; no rules changed: %w", err)
		}
		sockets = append(sockets, rows...)
	}
	inodes := map[string]bool{}
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("UDP port hopping cannot prove ownership of local sockets; no rules changed: %w", err)
	}
	for _, file := range files {
		target, err := os.Readlink("/proc/self/fd/" + file.Name())
		if err == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	if err := checkSockets(sockets, r, oldTargets, inodes); err != nil {
		return err
	}
	for _, name := range []string{"iptables-legacy-save", "ip6tables-legacy-save"} {
		path, err := exec.LookPath(name)
		if err != nil {
			if _, binaryErr := exec.LookPath(strings.TrimSuffix(name, "-save")); binaryErr == nil {
				return fmt.Errorf("UDP port hopping cannot inspect installed legacy iptables NAT; install its save tool or unify the host firewall backend")
			}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		data, err := exec.CommandContext(ctx, path, "-t", "nat").Output()
		cancel()
		if err != nil {
			return fmt.Errorf("UDP port hopping cannot inspect legacy iptables NAT; unify the host firewall backend before enabling a range")
		}
		if err := checkLegacy(data); err != nil {
			return err
		}
	}
	return nil
}

// legacyWords handles quoting/escaping from iptables-save without evaluating a
// shell. Quoted comments can never masquerade as protocol or jump selectors.
func legacyWords(line string) ([]string, error) {
	var words []string
	var b strings.Builder
	var quote rune
	escaped, started := false, false
	flush := func() {
		if started {
			words = append(words, b.String())
			b.Reset()
			started = false
		}
	}
	for _, c := range line {
		if escaped {
			b.WriteRune(c)
			escaped = false
			started = true
			continue
		}
		if c == '\\' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				b.WriteRune(c)
			}
			started = true
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			started = true
			continue
		}
		if c == ' ' || c == '\t' {
			flush()
			continue
		}
		b.WriteRune(c)
		started = true
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("cannot parse legacy NAT metadata")
	}
	flush()
	return words, nil
}

func checkLegacy(data []byte) error {
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "-A ") {
			continue
		}
		words, err := legacyWords(line)
		if err != nil {
			return fmt.Errorf("UDP port hopping cannot safely inspect legacy iptables NAT; no rules changed")
		}
		nat, tcp, header := false, false, true
		for i := 2; i < len(words); i++ { // Skip -A and its chain-name argument.
			word := words[i]
			if word == "--comment" {
				i++
				continue
			}
			if strings.HasPrefix(word, "--comment=") {
				continue
			}
			// iptables-save emits its canonical base protocol selector before
			// extension modules. Later free-form module arguments cannot prove
			// TCP, even when a string/comment value resembles a protocol flag.
			if word == "-m" || word == "--match" {
				header = false
				i++
				continue
			}
			if (word == "-p" || word == "--protocol") && i+1 < len(words) {
				if header && (words[i+1] == "tcp" || words[i+1] == "6") && (i == 0 || words[i-1] != "!") {
					tcp = true
				}
				i++
				continue
			}
			if header && (word == "--protocol=tcp" || word == "--protocol=6") && (i == 0 || words[i-1] != "!") {
				tcp = true
				continue
			}
			if (word == "-j" || word == "--jump") && i+1 < len(words) {
				nat = words[i+1] == "DNAT" || words[i+1] == "REDIRECT"
				i++
				header = false
				continue
			}
			if word == "--jump=DNAT" || word == "--jump=REDIRECT" {
				nat = true
				header = false
			}
		}
		if nat && !tcp {
			return fmt.Errorf("UDP port hopping found UDP or unknown-protocol DNAT/REDIRECT in legacy iptables; automatic mapping does not support mixed legacy/nft NAT, reconcile the existing rules first (no rules changed)")
		}
	}
	return nil
}
