package inputfirewall

import "testing"

func TestEffectiveHostUDPAllowedTCPBlockedBeforeOwnedRepair(t *testing.T) {
	m, f := newFake(t, "effective-fault")
	s := f.states[f.backends[0].key()]
	c := s.chains["INPUT"]
	c.rules = [][]string{{"-p", "udp", "--dport", "17443", "-j", "ACCEPT"}, {"-p", "tcp", "--dport", "22", "-j", "ACCEPT"}, {"-j", "REJECT"}}
	s.chains["INPUT"] = c
	s.input = c.rules
	want := runtimeListeners()[:2]
	status, err := m.CheckListeners(want)
	if err != nil || status.Healthy || len(status.Listeners) != 2 {
		t.Fatal(status, err)
	}
	if status.Listeners[0].RuleStatus != "missing" || status.Listeners[0].EffectiveStatus != "blocked" || status.Listeners[1].RuleStatus != "missing" || status.Listeners[1].EffectiveStatus != "allowed" {
		t.Fatal(status.Listeners)
	}
	if f.leased != 0 || len(f.scripts) != 0 {
		t.Fatal("effective observation mutated host")
	}
	if err := m.UpdateListeners(want); err != nil {
		t.Fatal(err)
	}
	status, err = m.CheckListeners(want)
	if err != nil || status.Listeners[0].EffectiveStatus != "allowed" || status.Listeners[1].EffectiveStatus != "allowed" {
		t.Fatal(status, err)
	}
}

func TestEffectiveManualPolicyAndUnknownHostRules(t *testing.T) {
	for _, tc := range []struct {
		name, policy string
		rules        [][]string
		expected     string
	}{
		{"manual-default-accept", "ACCEPT", nil, "allowed"},
		{"manual-default-drop", "DROP", nil, "blocked"},
		{"exact-accept", "DROP", [][]string{{"-p", "tcp", "-m", "tcp", "--dport", "443", "-j", "ACCEPT"}}, "allowed"},
		{"exact-reject", "ACCEPT", [][]string{{"-p", "tcp", "--dport", "443", "-j", "REJECT", "--reject-with", "tcp-reset"}}, "blocked"},
		{"unknown-jump", "ACCEPT", [][]string{{"-j", "FOREIGN"}}, "unknown"},
		{"unknown-source", "DROP", [][]string{{"-s", "192.0.2.0/24", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"}}, "unknown"},
		{"unmatched-unknown-condition", "DROP", [][]string{{"-s", "192.0.2.0/24", "-p", "udp", "--dport", "443", "-j", "ACCEPT"}}, "blocked"},
		{"unconditional-accept", "DROP", [][]string{{"-j", "ACCEPT"}}, "allowed"},
		{"accept-after-unknown-jump", "DROP", [][]string{{"-j", "FOREIGN"}, {"-j", "ACCEPT"}}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, f := newFake(t, tc.name)
			s := f.states[f.backends[0].key()]
			s.chains["INPUT"] = chain{policy: tc.policy, rules: tc.rules}
			s.input = tc.rules
			s.chains["FOREIGN"] = chain{policy: "-"}
			status, err := m.CheckListeners(runtimeListeners()[:1])
			if err != nil || status.Listeners[0].EffectiveStatus != tc.expected {
				t.Fatal(status, err)
			}
		})
	}
}

func TestEffectiveOtherOwnersReturnAndSharedPortPermissions(t *testing.T) {
	a, f := newFake(t, "effective-owner-a")
	if err := a.UpdateListeners(runtimeListeners()[1:2]); err != nil {
		t.Fatal(err)
	}
	b := New("effective-owner-b")
	b.controller = a.controller
	status, err := b.CheckListeners(runtimeListeners()[:2])
	if err != nil || status.Listeners[0].EffectiveStatus != "unknown" { // base contains opaque conntrack before REJECT
		t.Fatal(status, err)
	}
	if status.Listeners[1].EffectiveStatus != "allowed" || status.Listeners[1].RuleStatus != "missing" {
		t.Fatal(status.Listeners)
	}
	s := f.states[f.backends[0].key()]
	c := s.chains["INPUT"]
	c.rules = append(c.rules[:1], []string{"-j", "REJECT"})
	s.chains["INPUT"] = c
	s.input = c.rules
	status, err = b.CheckListeners(runtimeListeners()[:2])
	if err != nil || status.Listeners[0].EffectiveStatus != "blocked" || status.Listeners[1].EffectiveStatus != "allowed" {
		t.Fatal(status, err)
	}
}

func TestReservedDisabledOwnerSurvivesSiblingOrphanSweep(t *testing.T) {
	live, f := newFake(t, "reserved-disabled")
	if err := live.UpdateListeners(runtimeListeners()[:1]); err != nil {
		t.Fatal(err)
	}
	// Model a disabled live registration around rules from a previous lifetime.
	delete(live.controller.owners, live.name)
	live.registered = false
	if err := live.Reserve(); err != nil {
		t.Fatal(err)
	}
	other := New("enabled-sibling")
	other.controller = live.controller
	if err := other.UpdateListeners(runtimeListeners()[1:2]); err != nil {
		t.Fatal(err)
	}
	if _, ok := ownedAt(t, f, f.backends[0])[live.name]; !ok {
		t.Fatal("disabled reserved live owner's rules swept")
	}
	duplicate := New("reserved-disabled")
	duplicate.controller = live.controller
	if duplicate.Reserve() != errOwnership {
		t.Fatal("reservation conflict accepted")
	}
	live.ReleaseReservation()
	if err := other.UpdateListeners(runtimeListeners()[1:2]); err != nil {
		t.Fatal(err)
	}
	if _, ok := ownedAt(t, f, f.backends[0])[live.name]; ok {
		t.Fatal("released orphan not reclaimed")
	}
	other.ReleaseReservation()
	if other.controller.owners[other.name] != other {
		t.Fatal("active registered owner reservation released")
	}
}
