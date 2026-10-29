// Package inputfirewall maintains narrowly scoped INPUT permissions for the
// Hysteria2 listeners of this Node process. It never persists the host ruleset.
package inputfirewall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cedar2025/xboard-node/internal/model"
)

const chainPrefix = "XB_IN_"
const markerPrefix = "xboard-node-input:v1:"

var (
	errInvalid      = errors.New("managed Hysteria2 INPUT received an invalid listener or owner")
	errRules        = errors.New("managed Hysteria2 INPUT cannot safely identify the host rules; no unknown resources were changed")
	errOwnership    = errors.New("managed Hysteria2 INPUT ownership or references conflict; unknown resources were preserved")
	errUnsupported  = errors.New("managed Hysteria2 INPUT does not support native nftables INPUT chains or firewalld; use manual firewall management")
	errUnavailable  = errors.New("managed Hysteria2 INPUT requires Linux, root/CAP_NET_ADMIN, nftables and the active iptables backends")
	errOperation    = errors.New("managed Hysteria2 INPUT operation failed; check permissions and firewall reloads")
	errCompensation = errors.New("managed Hysteria2 INPUT update and owned-rule recovery were incomplete; retry reconciliation")
	errLease        = errors.New("managed Hysteria2 INPUT is already active in another Node process; use one managed process per network namespace")
)

type backend struct {
	family                 int
	kind                   string
	command, save, restore string
}

func (b backend) key() string { return strconv.Itoa(b.family) + "/" + b.kind }

type system interface {
	acquire() error
	discover() ([]backend, error)
	checkNative() error
	read(backend) ([]byte, error)
	apply(backend, string) error
}

// controller is shared by every instance in this process. Its host lease is
// deliberately retained until process exit, including when the last Node stops.
type controller struct {
	mu     sync.Mutex
	system system
	leased bool
	owners map[string]*Manager
}

var processController = newController(newSystem())

func newController(s system) *controller {
	return &controller{system: s, owners: make(map[string]*Manager)}
}

type Manager struct {
	name, marker string
	ownerOK      bool
	registered   bool
	controller   *controller
}

// New requires the same stable, per-node owner across restarts. Enablement is
// decided by the caller's local configuration; this package reads no environment.
func New(owner string) *Manager {
	digest := sha256.Sum256([]byte(owner))
	id := hex.EncodeToString(digest[:])
	return &Manager{name: chainPrefix + id[:20], marker: markerPrefix + id,
		ownerOK: strings.TrimSpace(owner) != "", controller: processController}
}

type listener struct {
	port, family int
	address      netip.Addr
}

func validate(n *model.NodeSpec) (*listener, error) {
	if n == nil || n.Protocol != "hysteria" || n.Version != 2 {
		return nil, nil
	}
	if n.ServerPort < 1 || n.ServerPort > 65535 || model.ValidatePortHopping(n) != nil {
		return nil, errInvalid
	}
	l := &listener{port: n.ServerPort}
	if n.ListenIP == "" || n.ListenIP == "::" {
		return l, nil
	}
	address, err := netip.ParseAddr(n.ListenIP)
	if err != nil || address.Zone() != "" || address.IsMulticast() {
		return nil, errInvalid
	}
	address = address.Unmap()
	if address.Is4() {
		l.family = 4
	} else {
		l.family = 6
	}
	if !address.IsUnspecified() {
		l.address = address
	}
	return l, nil
}

// Update replaces only this owner's rules. Repeating it also repairs rules
// removed or displaced by a firewall reload. nil/non-HY2 removes this owner.
func (m *Manager) Update(n *model.NodeSpec) error {
	want, err := validate(n)
	if err != nil || !m.ownerOK {
		return errInvalid
	}
	c := m.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	return m.update(want)
}

func (m *Manager) update(want *listener) error {
	c := m.controller
	if other := c.owners[m.name]; other != nil && other != m {
		return errOwnership
	}
	if !c.leased {
		if err := c.system.acquire(); err != nil {
			return safeError(err)
		}
		c.leased = true
	}
	if err := c.system.checkNative(); err != nil && want != nil {
		return safeError(err)
	}
	backends, err := c.system.discover()
	if err != nil {
		return safeError(err)
	}
	if len(backends) == 0 {
		return errUnavailable
	}
	seen := make(map[string]bool)
	var work []change
	available := make(map[int]bool)
	for _, b := range backends {
		if seen[b.key()] {
			continue
		}
		seen[b.key()] = true
		available[b.family] = true
		data, err := c.system.read(b)
		if err != nil {
			return safeError(err)
		}
		s, err := inspectSave(data)
		if err != nil {
			return err
		}
		all, err := owned(s)
		if err != nil {
			return err
		}
		// The process-wide exclusive lease proves that no other enabled Node
		// process can own these resources. Never clean a live sibling instance.
		remove := make(map[string]bool)
		for name := range all {
			if c.owners[name] == nil {
				remove[name] = true
			}
		}
		var desired *ownedChain
		if want != nil && (want.family == 0 || want.family == b.family) {
			d := m.desired(want)
			desired = &d
		}
		remove[m.name] = true
		before := make(map[string]ownedChain)
		after := make(map[string]ownedChain)
		for name := range remove {
			if entry, ok := all[name]; ok {
				before[name] = entry
			}
		}
		if desired != nil {
			after[m.name] = *desired
		}
		script := patch(s, all, remove, after)
		work = append(work, change{backend: b, before: before, after: after, script: script, names: remove})
	}
	if want != nil && ((want.family != 0 && !available[want.family]) || (want.family == 0 && !available[4] && !available[6])) {
		return errUnavailable
	}
	// A failed or timed-out first transaction may still have committed. Keep
	// the owner registered so Close can retry strict, own-only cleanup even
	// when the immediate compensation also fails.
	c.owners[m.name] = m
	m.registered = true
	var applied []change
	for _, entry := range work {
		if entry.script == "" {
			continue
		}
		if err := c.system.apply(entry.backend, entry.script); err != nil {
			// A timeout can occur after commit. Include the failed backend and
			// inspect its current owned subset rather than assuming no change.
			applied = append(applied, entry)
			if !c.recover(applied) {
				return errCompensation
			}
			return safeError(err)
		}
		applied = append(applied, entry)
	}
	return nil
}

type change struct {
	backend       backend
	before, after map[string]ownedChain
	names         map[string]bool
	script        string
}

func (c *controller) recover(changes []change) bool {
	ok := true
	for i := len(changes) - 1; i >= 0; i-- {
		entry := changes[i]
		data, err := c.system.read(entry.backend)
		if err != nil {
			ok = false
			continue
		}
		s, err := inspectSave(data)
		if err != nil {
			ok = false
			continue
		}
		all, err := owned(s)
		if err != nil {
			ok = false
			continue
		}
		// Refuse to overwrite a simultaneous external change, including an
		// unfamiliar body bearing a valid-looking chain prefix.
		for name := range entry.names {
			current, exists := all[name]
			if !exists {
				continue
			}
			previous, was := entry.before[name]
			next, will := entry.after[name]
			if (!was || !sameBody(current, previous)) && (!will || !sameBody(current, next)) {
				err = errOwnership
				break
			}
		}
		if err != nil {
			ok = false
			continue
		}
		script := patch(s, all, entry.names, entry.before)
		if script != "" && c.system.apply(entry.backend, script) != nil {
			ok = false
		}
	}
	return ok
}

// Close never starts host management for an unused Manager and never removes
// another Manager's live resources. The shared host lease remains held.
func (m *Manager) Close() error {
	c := m.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if !m.registered || c.owners[m.name] != m {
		return nil
	}
	err := m.update(nil)
	if c.owners[m.name] == m {
		delete(c.owners, m.name)
	}
	m.registered = false
	return err
}

func (m *Manager) desired(l *listener) ownedChain {
	allow := []string{"-p", "udp", "-m", "udp", "--dport", strconv.Itoa(l.port)}
	if l.address.IsValid() {
		bits := "/128"
		if l.address.Is4() {
			bits = "/32"
		}
		allow = append([]string{"-d", l.address.String() + bits}, allow...)
	}
	allow = append(allow, "-m", "comment", "--comment", m.marker, "-j", "ACCEPT")
	return ownedChain{name: m.name, marker: m.marker,
		rules: [][]string{allow, {"-m", "comment", "--comment", m.marker, "-j", "RETURN"}},
		jumps: [][]string{{"-m", "comment", "--comment", m.marker, "-j", m.name}}}
}

func safeError(err error) error {
	for _, known := range []error{errInvalid, errRules, errOwnership, errUnsupported, errUnavailable, errOperation, errCompensation, errLease} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errOperation
}

// patch uses --noflush restore semantics. Only verified, owned user chains are
// declared (and therefore rebuilt); no foreign chain or policy is declared.
func patch(s *snapshot, all map[string]ownedChain, remove map[string]bool, desired map[string]ownedChain) string {
	var names []string
	for name := range remove {
		names = append(names, name)
	}
	sort.Strings(names)
	var body strings.Builder
	prefix := 0
	for _, rule := range s.input {
		name := jumpTarget(rule)
		if entry, ok := all[name]; !ok || !isJump(rule, entry.marker, name) {
			break
		}
		if !remove[name] {
			prefix++
		}
	}
	for _, name := range names {
		old, exists := all[name]
		next, want := desired[name]
		if exists && want && sameBody(old, next) && len(old.jumps) == 1 && old.positions[0] <= leadingOwned(s, all) {
			continue
		}
		if exists {
			for _, jump := range old.jumps {
				writeRule(&body, "-D", "INPUT", 0, jump)
			}
		}
		if want {
			body.WriteString(":" + name + " - [0:0]\n")
			for _, rule := range next.rules {
				writeRule(&body, "-A", name, 0, rule)
			}
			prefix++
			writeRule(&body, "-I", "INPUT", prefix, next.jumps[0])
		} else if exists {
			for _, rule := range old.rules {
				writeRule(&body, "-D", name, 0, rule)
			}
			body.WriteString("-X " + name + "\n")
		}
	}
	if body.Len() == 0 {
		return ""
	}
	return "*filter\n" + body.String() + "COMMIT\n"
}

func leadingOwned(s *snapshot, all map[string]ownedChain) int {
	count := 0
	for _, rule := range s.input {
		entry, ok := all[jumpTarget(rule)]
		if !ok || !isJump(rule, entry.marker, entry.name) {
			break
		}
		count++
	}
	return count
}

func writeRule(b *strings.Builder, op, chain string, index int, rule []string) {
	b.WriteString(op + " " + chain)
	if index > 0 {
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(index))
	}
	for _, token := range rule {
		b.WriteByte(' ')
		b.WriteString(quote(token))
	}
	b.WriteByte('\n')
}

func quote(token string) string {
	// Owned tokens are already strictly validated. Quote comments consistently
	// with iptables-save; this is restore syntax, never shell syntax.
	if strings.ContainsAny(token, " \t\\\"") {
		return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(token) + "\""
	}
	return token
}
