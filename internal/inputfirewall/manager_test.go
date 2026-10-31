package inputfirewall

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

type fakeSystem struct {
	backends                     []backend
	states                       map[string]*snapshot
	scripts                      []string
	leased, checks               int
	leaseErr, nativeErr, readErr error
	failKey                      string
	failAfter                    bool
	failRecovery                 bool
	failed                       bool
	afterApply                   func(*fakeSystem, backend)
}

func newFake(t *testing.T, owner string, backends ...backend) (*Manager, *fakeSystem) {
	t.Helper()
	if len(backends) == 0 {
		backends = []backend{{family: 4, kind: "nft"}}
	}
	f := &fakeSystem{backends: backends, states: make(map[string]*snapshot)}
	for _, b := range backends {
		f.states[b.key()] = baseSnapshot()
	}
	m := New(owner)
	m.controller = newController(f)
	return m, f
}
func baseSnapshot() *snapshot {
	return &snapshot{chains: map[string]chain{
		"INPUT":  {policy: "DROP", rules: [][]string{{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, {"-j", "REJECT", "--reject-with", "icmp-host-prohibited"}}},
		"OUTPUT": {policy: "ACCEPT", rules: [][]string{{"-d", "169.254.0.0/16", "-j", "ACCEPT"}}},
	}, input: [][]string{{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, {"-j", "REJECT", "--reject-with", "icmp-host-prohibited"}}}
}
func cloneSnapshot(s *snapshot) *snapshot {
	r := &snapshot{chains: make(map[string]chain)}
	for name, c := range s.chains {
		r.chains[name] = chain{policy: c.policy, rules: cloneRules(c.rules)}
	}
	r.input = r.chains["INPUT"].rules
	return r
}
func cloneRules(rules [][]string) [][]string {
	var result [][]string
	for _, rule := range rules {
		result = append(result, append([]string(nil), rule...))
	}
	return result
}
func (f *fakeSystem) acquire() error               { f.leased++; return f.leaseErr }
func (f *fakeSystem) checkNative() error           { f.checks++; return f.nativeErr }
func (f *fakeSystem) discover() ([]backend, error) { return f.backends, nil }
func (f *fakeSystem) read(b backend) ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return renderSave(f.states[b.key()]), nil
}
func renderSave(s *snapshot) []byte {
	var b strings.Builder
	b.WriteString("# generated\n*filter\n")
	var names []string
	for name := range s.chains {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, ":%s %s [0:0]\n", name, s.chains[name].policy)
	}
	for _, name := range names {
		for _, rule := range s.chains[name].rules {
			writeRule(&b, "-A", name, 0, rule)
		}
	}
	b.WriteString("COMMIT\n# completed\n")
	return []byte(b.String())
}
func (f *fakeSystem) apply(b backend, input string) error {
	f.scripts = append(f.scripts, b.key()+"\n"+input)
	fail := b.key() == f.failKey && !f.failed
	if fail {
		f.failed = true
		if !f.failAfter {
			return errors.New("private stderr password=secret")
		}
	} else if f.failed && f.failRecovery {
		return errors.New("private recovery")
	}
	s := cloneSnapshot(f.states[b.key()])
	for _, line := range strings.Split(input, "\n") {
		if line == "" || line == "*filter" || line == "COMMIT" {
			continue
		}
		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line[1:])
			s.chains[fields[0]] = chain{policy: "-"}
			continue
		}
		parts, err := splitRule(line)
		if err != nil {
			return err
		}
		if len(parts) < 2 {
			return errors.New("bad fake command")
		}
		name := parts[1]
		entry, exists := s.chains[name]
		if !exists {
			return errors.New("fake chain absent")
		}
		switch parts[0] {
		case "-X":
			if len(entry.rules) != 0 {
				return errors.New("fake chain not empty")
			}
			delete(s.chains, name)
			continue
		case "-A":
			entry.rules = append(entry.rules, parts[2:])
		case "-I":
			index, err := strconv.Atoi(parts[2])
			if err != nil || index < 1 || index > len(entry.rules)+1 {
				return errors.New("bad fake index")
			}
			index--
			entry.rules = append(entry.rules, nil)
			copy(entry.rules[index+1:], entry.rules[index:])
			entry.rules[index] = parts[3:]
		case "-D":
			found := -1
			for i, r := range entry.rules {
				if reflect.DeepEqual(r, parts[2:]) {
					found = i
					break
				}
			}
			if found < 0 {
				return errors.New("fake delete absent")
			}
			entry.rules = append(entry.rules[:found], entry.rules[found+1:]...)
		default:
			return errors.New("unexpected fake command")
		}
		s.chains[name] = entry
	}
	s.input = s.chains["INPUT"].rules
	f.states[b.key()] = s
	if f.afterApply != nil {
		f.afterApply(f, b)
	}
	if fail {
		return errors.New("private timeout token=secret")
	}
	return nil
}
func hy2() *model.NodeSpec {
	return &model.NodeSpec{Protocol: "hysteria", Version: 2, ListenIP: "0.0.0.0", ServerPort: 17443}
}
func ownedAt(t *testing.T, f *fakeSystem, b backend) map[string]ownedChain {
	t.Helper()
	all, err := owned(f.states[b.key()])
	if err != nil {
		t.Fatal(err)
	}
	return all
}

func TestListenerValidationNeverTouchesHost(t *testing.T) {
	for name, mutate := range map[string]func(*model.NodeSpec){
		"zero": func(n *model.NodeSpec) { n.ServerPort = 0 }, "overflow": func(n *model.NodeSpec) { n.ServerPort = 65536 },
		"injection": func(n *model.NodeSpec) { n.ListenIP = "0.0.0.0; flush" }, "hostname": func(n *model.NodeSpec) { n.ListenIP = "node.invalid" },
		"zone": func(n *model.NodeSpec) { n.ListenIP = "fe80::1%ens3" }, "multicast": func(n *model.NodeSpec) { n.ListenIP = "ff02::1" },
		"invalid-range": func(n *model.NodeSpec) { n.PortHopping = &model.PortHopping{Start: 20, End: 10} },
	} {
		t.Run(name, func(t *testing.T) {
			m, f := newFake(t, "validation")
			n := hy2()
			mutate(n)
			if m.Update(n) != errInvalid {
				t.Fatal("invalid listener accepted")
			}
			if f.leased+f.checks+len(f.scripts) != 0 {
				t.Fatal("invalid request touched host")
			}
		})
	}
	m, f := newFake(t, "")
	if m.Update(hy2()) != errInvalid || f.leased != 0 {
		t.Fatal("empty owner accepted")
	}
}

func TestActualPortOnlyAndRepeatIsIdempotent(t *testing.T) {
	m, f := newFake(t, "actual-port")
	b := f.backends[0]
	before := cloneSnapshot(f.states[b.key()])
	n := hy2()
	n.PortHopping = &model.PortHopping{Start: 17443, End: 19443}
	if err := m.Update(n); err != nil {
		t.Fatal(err)
	}
	all := ownedAt(t, f, b)
	entry := all[m.name]
	rule, ok := parseOwned(entry.rules[0], "ACCEPT")
	if !ok || rule.port != 17443 || rule.address != "" {
		t.Fatal(entry)
	}
	if len(entry.jumps) != 1 || entry.positions[0] != 1 {
		t.Fatal("jump behind reject", entry)
	}
	if strings.Contains(f.scripts[0], "19443") || strings.Contains(f.scripts[0], "-P ") {
		t.Fatal("range or policy changed")
	}
	if !reflect.DeepEqual(f.states[b.key()].chains["OUTPUT"], before.chains["OUTPUT"]) {
		t.Fatal("provider OUTPUT changed")
	}
	if err := m.Update(n); err != nil || len(f.scripts) != 1 || f.leased != 1 {
		t.Fatal("repeat mutated rules or reacquired lease", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.states[b.key()], before) {
		t.Fatal("close changed foreign state")
	}
}

func TestFamiliesAndExactAddresses(t *testing.T) {
	backends := []backend{{family: 4, kind: "nft"}, {family: 4, kind: "legacy"}, {family: 6, kind: "nft"}, {family: 6, kind: "legacy"}}
	for _, address := range []string{"", "::", "0.0.0.0", "192.0.2.8", "2001:db8::8", "::ffff:192.0.2.8"} {
		t.Run(address, func(t *testing.T) {
			m, f := newFake(t, "family", backends...)
			n := hy2()
			n.ListenIP = address
			if err := m.Update(n); err != nil {
				t.Fatal(err)
			}
			want, _ := validate(n)
			for _, b := range backends {
				all := ownedAt(t, f, b)
				_, exists := all[m.name]
				if exists != (want.family == 0 || want.family == b.family) {
					t.Fatal("wrong family", b)
				}
				if exists {
					r, _ := parseOwned(all[m.name].rules[0], "ACCEPT")
					if want.address.IsValid() && !strings.HasPrefix(r.address, want.address.String()+"/") {
						t.Fatal("address widened", r)
					}
				}
			}
		})
	}
}

func TestMultipleOwnersDoNotFightLeadingPrefix(t *testing.T) {
	a, f := newFake(t, "owner-A")
	b := New("owner-B")
	b.controller = a.controller
	if err := a.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	n := hy2()
	n.ServerPort = 17444
	if err := b.Update(n); err != nil {
		t.Fatal(err)
	}
	count := len(f.scripts)
	for range 3 {
		if err := a.Update(hy2()); err != nil {
			t.Fatal(err)
		}
		if err := b.Update(n); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.scripts) != count {
		t.Fatal("owners fight for first INPUT position")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	all := ownedAt(t, f, f.backends[0])
	if len(all) != 1 || all[b.name].name == "" {
		t.Fatal("closed sibling", all)
	}
	if f.leased != 1 {
		t.Fatal("process lease not shared")
	}
}

func TestLiveDuplicateOwnerRefused(t *testing.T) {
	a, f := newFake(t, "duplicate")
	b := New("duplicate")
	b.controller = a.controller
	if err := a.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	count := len(f.scripts)
	if b.Update(hy2()) != errOwnership || b.Close() != nil || len(f.scripts) != count {
		t.Fatal("duplicate modified live owner")
	}
}

func TestStartupRemovesStrictStaleOwnersAndRetainsLiveSiblings(t *testing.T) {
	m, f := newFake(t, "current")
	old := New("removed-while-stopped")
	d := old.desired(&listener{port: 17442, family: 4})
	s := f.states[f.backends[0].key()]
	s.chains[d.name] = chain{policy: "-", rules: d.rules}
	input := s.chains["INPUT"]
	input.rules = append(d.jumps, input.rules...)
	s.chains["INPUT"] = input
	s.input = input.rules
	if err := m.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	all := ownedAt(t, f, f.backends[0])
	if len(all) != 1 || all[m.name].name == "" {
		t.Fatal("stale resources retained", all)
	}
}

func TestReloadAndDisplacementAreRepaired(t *testing.T) {
	m, f := newFake(t, "reload")
	b := f.backends[0]
	if err := m.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	s := f.states[b.key()]
	input := s.chains["INPUT"]
	jump := input.rules[0]
	input.rules = append(input.rules[1:], jump)
	s.chains["INPUT"] = input
	s.input = input.rules
	if err := m.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	if ownedAt(t, f, b)[m.name].positions[0] != 1 {
		t.Fatal("jump left behind reject")
	}
	f.states[b.key()] = baseSnapshot()
	if err := m.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	if ownedAt(t, f, b)[m.name].name == "" {
		t.Fatal("reload not repaired")
	}
}

func TestProtocolChangeAndNilCleanOnlySelf(t *testing.T) {
	for _, next := range []*model.NodeSpec{nil, {Protocol: "hysteria", Version: 1}, {Protocol: "vless"}} {
		m, f := newFake(t, "disable")
		before := cloneSnapshot(f.states[f.backends[0].key()])
		if err := m.Update(hy2()); err != nil {
			t.Fatal(err)
		}
		if err := m.Update(next); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(f.states[f.backends[0].key()], before) {
			t.Fatal("disable changed host state")
		}
	}
}

func TestCrossBackendFailureCompensatesOnlyOwnedSubset(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(strconv.FormatBool(afterCommit), func(t *testing.T) {
			backends := []backend{{family: 4, kind: "nft"}, {family: 4, kind: "legacy"}}
			m, f := newFake(t, "rollback", backends...)
			if err := m.Update(hy2()); err != nil {
				t.Fatal(err)
			}
			f.failKey = backends[1].key()
			f.failAfter = afterCommit
			f.afterApply = func(f *fakeSystem, b backend) {
				s := f.states[b.key()]
				c := s.chains["OUTPUT"]
				if len(c.rules) == 1 {
					c.rules = append(c.rules, []string{"-d", "198.51.100.1/32", "-j", "ACCEPT"})
					s.chains["OUTPUT"] = c
				}
			}
			n := hy2()
			n.ServerPort = 17444
			err := m.Update(n)
			if !errors.Is(err, errOperation) || strings.Contains(err.Error(), "secret") {
				t.Fatal("unsafe error", err)
			}
			for _, b := range backends {
				r, _ := parseOwned(ownedAt(t, f, b)[m.name].rules[0], "ACCEPT")
				if r.port != 17443 {
					t.Fatal("old owned port not recovered", b, r)
				}
				if b == backends[0] && len(f.states[b.key()].chains["OUTPUT"].rules) != 2 {
					t.Fatal("foreign concurrent change reverted")
				}
			}
		})
	}
}

func TestRecoveryFailureIsExplicit(t *testing.T) {
	backends := []backend{{family: 4, kind: "nft"}, {family: 4, kind: "legacy"}}
	m, f := newFake(t, "partial", backends...)
	if err := m.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	f.failKey = backends[1].key()
	f.failRecovery = true
	n := hy2()
	n.ServerPort = 17444
	if err := m.Update(n); !errors.Is(err, errCompensation) {
		t.Fatal(err)
	}
	f.failRecovery = false
	f.failKey = ""
	if err := m.Update(hy2()); err != nil {
		t.Fatal("subsequent reconciliation failed", err)
	}
}

func TestFirstPartialUpdateStillAllowsCloseCleanup(t *testing.T) {
	m, f := newFake(t, "first-partial")
	f.failKey = f.backends[0].key()
	f.failAfter = true
	f.failRecovery = true
	if err := m.Update(hy2()); !errors.Is(err, errCompensation) {
		t.Fatal(err)
	}
	if !m.registered || len(ownedAt(t, f, f.backends[0])) != 1 {
		t.Fatal("partial owner was forgotten")
	}
	f.failKey = ""
	f.failRecovery = false
	if err := m.Close(); err != nil {
		t.Fatal("recovered cleanup failed", err)
	}
	if len(ownedAt(t, f, f.backends[0])) != 0 || m.registered {
		t.Fatal("first partial allow retained")
	}
}

func TestNativeFirewallAppearingDoesNotPreventOwnCleanup(t *testing.T) {
	m, f := newFake(t, "native-cleanup")
	if err := m.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	f.nativeErr = errUnsupported
	if err := m.Close(); err != nil || len(ownedAt(t, f, f.backends[0])) != 0 {
		t.Fatal("native change prevented cleanup", err)
	}
}

func TestFailedCloseCanBeReclaimedByNewSameOwner(t *testing.T) {
	m, f := newFake(t, "close-retry")
	if err := m.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	f.failKey = f.backends[0].key()
	f.failRecovery = true
	if m.Close() == nil || m.registered {
		t.Fatal("failed close retained a live owner")
	}
	f.failKey = ""
	f.failRecovery = false
	next := New("close-retry")
	next.controller = m.controller
	if err := next.Update(hy2()); err != nil {
		t.Fatal("new lifecycle could not reclaim owner", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSiblingReconciliationRetriesRetiredOrphanCleanup(t *testing.T) {
	m, f := newFake(t, "retired")
	sibling := New("live-sibling")
	sibling.controller = m.controller
	if err := m.Update(hy2()); err != nil {
		t.Fatal(err)
	}
	n := hy2()
	n.ServerPort = 17444
	if err := sibling.Update(n); err != nil {
		t.Fatal(err)
	}
	f.failKey = f.backends[0].key()
	f.failRecovery = true
	if m.Close() == nil {
		t.Fatal("failure fixture did not fail")
	}
	f.failKey = ""
	f.failRecovery = false
	if err := sibling.Update(n); err != nil {
		t.Fatal(err)
	}
	all := ownedAt(t, f, f.backends[0])
	if len(all) != 1 || all[sibling.name].name == "" {
		t.Fatal("retired orphan not removed", all)
	}
}

func TestOwnershipCollisionAndForeignReferencesNeverMutate(t *testing.T) {
	for _, mutate := range []func(*snapshot, string){
		func(s *snapshot, name string) {
			s.chains[name] = chain{policy: "-", rules: [][]string{{"-j", "ACCEPT"}}}
		},
		func(s *snapshot, name string) {
			c := s.chains["OUTPUT"]
			c.rules = append(c.rules, []string{"-j", name})
			s.chains["OUTPUT"] = c
		},
	} {
		m, f := newFake(t, "unknown")
		s := f.states[f.backends[0].key()]
		d := m.desired(&listener{port: 17443})
		s.chains[m.name] = chain{policy: "-", rules: d.rules}
		mutate(s, m.name)
		if m.Update(hy2()) != errOwnership || len(f.scripts) != 0 {
			t.Fatal("unknown resource changed")
		}
	}
}

func TestUnavailableUnsupportedAndUnusedClose(t *testing.T) {
	for _, failure := range []error{errLease, errUnavailable, errors.New("host private failure")} {
		m, f := newFake(t, "failure")
		f.leaseErr = failure
		if m.Close() != nil || f.leased != 0 {
			t.Fatal("unused close touched host")
		}
		err := m.Update(hy2())
		if err == nil || strings.Contains(err.Error(), "private") || len(f.scripts) != 0 {
			t.Fatal(err)
		}
	}
	m, f := newFake(t, "native")
	f.nativeErr = errUnsupported
	if !errors.Is(m.Update(hy2()), errUnsupported) || len(f.scripts) != 0 {
		t.Fatal("unsupported host changed")
	}
}

func TestBackendAliasesDeduplicateAndMissingFamilyRefuses(t *testing.T) {
	b := backend{family: 4, kind: "nft"}
	m, f := newFake(t, "alias", b, b)
	if err := m.Update(hy2()); err != nil || len(f.scripts) != 1 {
		t.Fatal("alias duplicated", err)
	}
	n := hy2()
	n.ListenIP = "2001:db8::1"
	count := len(f.scripts)
	if m.Update(n) != errUnavailable || len(f.scripts) != count {
		t.Fatal("missing family partially changed rules")
	}
}
