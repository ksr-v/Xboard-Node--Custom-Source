// Package inputfirewall maintains narrowly scoped INPUT permissions for the
// running listeners of this Node process. It never persists the host ruleset.
package inputfirewall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	errInvalid      = errors.New("managed INPUT received an invalid listener or owner")
	errRules        = errors.New("managed INPUT cannot safely identify the host rules; no unknown resources were changed")
	errOwnership    = errors.New("managed INPUT ownership or references conflict; unknown resources were preserved")
	errUnsupported  = errors.New("managed INPUT does not support native nftables INPUT chains or firewalld; use manual firewall management")
	errUnavailable  = errors.New("managed INPUT requires Linux, root/CAP_NET_ADMIN, nftables and the active iptables backends")
	errOperation    = errors.New("managed INPUT operation failed; check permissions and firewall reloads")
	errCompensation = errors.New("managed INPUT update and owned-rule recovery were incomplete; retry reconciliation")
	errLease        = errors.New("managed INPUT is already active in another Node process; use one managed process per network namespace")
	errLegacyNFT    = errors.New("managed INPUT cannot safely manage active nftables compatibility INPUT with nft 0.9.0; use manual firewall management")
	errExternal     = errors.New("managed INPUT detected UFW or firewalld ownership; configure Node ports through that firewall manager")
	errVerification = errors.New("managed INPUT post-repair verification failed; rules changed concurrently or were not installed")
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
	transport    string
}

// Listener describes a successfully started kernel listener, never panel intent.
type Listener struct {
	Protocol      string `json:"protocol"`
	Transport     string `json:"transport"`
	ListenAddress string `json:"listen_address"`
	ListenPort    int    `json:"listen_port"`
}

type Status struct {
	Healthy    bool             `json:"healthy"`
	Repairable bool             `json:"repairable"`
	Chain      string           `json:"chain"`
	Backends   []BackendStatus  `json:"backends"`
	Issues     []string         `json:"issues"`
	Listeners  []ListenerStatus `json:"listeners"`
}

type ListenerStatus struct {
	Listener
	Allowed         bool     `json:"allowed"`
	RuleStatus      string   `json:"rule_status"`
	EffectiveStatus string   `json:"effective_status"`
	Issues          []string `json:"issues"`
}

// Reserve protects every live registry owner, including locally disabled
// owners, from another manager's orphan sweep. It never touches host state.
func (m *Manager) Reserve() error {
	c := m.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if !m.ownerOK {
		return errInvalid
	}
	if other := c.owners[m.name]; other != nil && other != m {
		return errOwnership
	}
	c.owners[m.name] = m
	return nil
}

func (m *Manager) ReleaseReservation() {
	c := m.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	if !m.registered && c.owners[m.name] == m {
		delete(c.owners, m.name)
	}
}

type BackendStatus struct {
	Family       int      `json:"family"`
	Kind         string   `json:"kind"`
	Policy       string   `json:"policy"`
	ChainPresent bool     `json:"chain_present"`
	Referenced   bool     `json:"referenced"`
	Ordered      bool     `json:"ordered"`
	Allowed      bool     `json:"allowed"`
	Issues       []string `json:"issues"`
}

func validateListeners(values []Listener) ([]*listener, error) {
	if len(values) > 4096 {
		return nil, errInvalid
	}
	var result []*listener
	seen := make(map[string]bool)
	for _, v := range values {
		if strings.TrimSpace(v.Protocol) == "" || (v.Transport != "tcp" && v.Transport != "udp") {
			return nil, errInvalid
		}
		// Reuse the strict address/port validation without interpreting protocol names.
		l, err := validate(&model.NodeSpec{Protocol: "hysteria", Version: 2, ListenIP: v.ListenAddress, ServerPort: v.ListenPort})
		if err != nil {
			return nil, err
		}
		l.transport = v.Transport
		key := strconv.Itoa(l.family) + "/" + l.address.String() + "/" + l.transport + "/" + strconv.Itoa(l.port)
		if !seen[key] {
			result = append(result, l)
			seen[key] = true
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.family != b.family {
			return a.family < b.family
		}
		if a.address != b.address {
			return a.address.String() < b.address.String()
		}
		if a.transport != b.transport {
			return a.transport < b.transport
		}
		return a.port < b.port
	})
	return result, nil
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
	var listeners []*listener
	if want != nil {
		want.transport = "udp"
		listeners = []*listener{want}
	}
	return m.update(listeners)
}

// UpdateListeners replaces this owner's permissions using accepted runtime data.
func (m *Manager) UpdateListeners(values []Listener) error {
	want, err := validateListeners(values)
	if err != nil || !m.ownerOK {
		return errInvalid
	}
	c := m.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	return m.update(want)
}

func (m *Manager) update(want []*listener) error {
	c := m.controller
	if other := c.owners[m.name]; other != nil && other != m {
		return errOwnership
	}
	if !c.leased {
		if err := c.system.acquire(); err != nil {
			return phaseError("acquire management lease", err)
		}
		c.leased = true
	}
	if err := c.system.checkNative(); err != nil && len(want) > 0 {
		return phaseError("inspect native nft INPUT", err)
	}
	backends, err := c.system.discover()
	if err != nil {
		return phaseError("discover active filter backends", err)
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
			return phaseError("read IPv"+b.key()+" filter", err)
		}
		s, err := inspectSave(data)
		if err != nil {
			return err
		}
		if len(want) > 0 && externallyManaged(s) {
			return errExternal
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
		selected := listenersForFamily(want, b.family)
		if len(selected) > 0 {
			d := m.desiredMany(selected)
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
	for _, l := range want {
		if (l.family != 0 && !available[l.family]) || (l.family == 0 && !available[4] && !available[6]) {
			return errUnavailable
		}
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
				return phaseError("apply IPv"+entry.backend.key()+" filter and compensate", errCompensation)
			}
			return phaseError("apply IPv"+entry.backend.key()+" filter", err)
		}
		applied = append(applied, entry)
	}
	for _, entry := range work {
		if err := c.verify(entry); err != nil {
			return phaseError("verify IPv"+entry.backend.key()+" filter", err)
		}
	}
	return nil
}

func listenersForFamily(values []*listener, family int) []*listener {
	var result []*listener
	for _, l := range values {
		if l.family == 0 || l.family == family {
			result = append(result, l)
		}
	}
	return result
}

func (c *controller) verify(entry change) error {
	data, err := c.system.read(entry.backend)
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
	for name := range entry.names {
		current, exists := all[name]
		wanted, desired := entry.after[name]
		if exists != desired || desired && (!sameBody(current, wanted) || len(current.jumps) != 1 || current.positions[0] > leadingOwned(s, all)) {
			return errVerification
		}
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
	return m.desiredMany([]*listener{l})
}

func (m *Manager) desiredMany(listeners []*listener) ownedChain {
	var rules [][]string
	for _, l := range listeners {
		transport := l.transport
		if transport == "" {
			transport = "udp"
		} // legacy HY2 API
		allow := []string{"-p", transport, "-m", transport, "--dport", strconv.Itoa(l.port)}
		if l.address.IsValid() {
			bits := "/128"
			if l.address.Is4() {
				bits = "/32"
			}
			allow = append([]string{"-d", l.address.String() + bits}, allow...)
		}
		allow = append(allow, "-m", "comment", "--comment", m.marker, "-j", "ACCEPT")
		rules = append(rules, allow)
	}
	rules = append(rules, []string{"-m", "comment", "--comment", m.marker, "-j", "RETURN"})
	return ownedChain{name: m.name, marker: m.marker,
		rules: rules,
		jumps: [][]string{{"-m", "comment", "--comment", m.marker, "-j", m.name}}}
}

func safeError(err error) error {
	var contextual *operationError
	if errors.As(err, &contextual) {
		return &operationError{stage: contextual.stage, cause: safeError(contextual.cause)}
	}
	for _, known := range []error{errInvalid, errRules, errOwnership, errUnsupported, errUnavailable, errOperation, errCompensation, errLease, errLegacyNFT, errExternal, errVerification} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errOperation
}

type operationError struct {
	stage string
	cause error
}

func (e *operationError) Error() string { return fmt.Sprintf("%s: %s", e.stage, e.cause) }
func (e *operationError) Unwrap() error { return e.cause }
func phaseError(stage string, err error) error {
	return &operationError{stage: stage, cause: safeError(err)}
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
