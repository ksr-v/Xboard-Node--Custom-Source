package inputfirewall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func runtimeListeners() []Listener {
	return []Listener{
		{Protocol: "vless", Transport: "tcp", ListenAddress: "0.0.0.0", ListenPort: 443},
		{Protocol: "hysteria2", Transport: "udp", ListenAddress: "0.0.0.0", ListenPort: 17443},
		{Protocol: "shadowsocks", Transport: "udp", ListenAddress: "0.0.0.0", ListenPort: 443},
	}
}

func TestRuntimeTCPUDPReadOnlyCheckAndHundredReconciliations(t *testing.T) {
	m, f := newFake(t, "runtime-tcp-udp")
	want := runtimeListeners()
	before := cloneSnapshot(f.states[f.backends[0].key()])
	s, err := m.CheckListeners(want)
	if err != nil || s.Healthy || !s.Repairable || len(s.Backends) != 1 || s.Backends[0].Policy != "DROP" {
		t.Fatal(s, err)
	}
	if f.leased != 0 || m.registered || len(f.scripts) != 0 || len(m.controller.owners) != 0 {
		t.Fatal("check obtained write authority")
	}
	if !reflect.DeepEqual(f.states[f.backends[0].key()], before) {
		t.Fatal("check modified host")
	}
	if err := m.UpdateListeners(want); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		s, err := m.CheckListeners(want)
		if err != nil || !s.Healthy || !s.Repairable || !s.Backends[0].Allowed {
			t.Fatal(s, err)
		}
		if err := m.UpdateListeners(want); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.scripts) != 1 || f.leased != 1 {
		t.Fatal("repeated reconcile produced rules", len(f.scripts), f.leased)
	}
	entry := ownedAt(t, f, f.backends[0])[m.name]
	if len(entry.rules) != 4 {
		t.Fatal(entry)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.states[f.backends[0].key()], before) {
		t.Fatal("close changed SSH/reject/host state")
	}
}

func TestRuntimePartialOwnedRulesRepairFromMarkedEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*snapshot, string){
		"missing-allow": func(s *snapshot, name string) { c := s.chains[name]; c.rules = c.rules[1:]; s.chains[name] = c },
		"missing-return": func(s *snapshot, name string) {
			c := s.chains[name]
			c.rules = c.rules[:len(c.rules)-1]
			s.chains[name] = c
		},
		"missing-entire-body-with-jump-proof": func(s *snapshot, name string) { c := s.chains[name]; c.rules = nil; s.chains[name] = c },
		"changed-port":                        func(s *snapshot, name string) { c := s.chains[name]; c.rules[0][5] = "8443"; s.chains[name] = c },
		"changed-transport": func(s *snapshot, name string) {
			c := s.chains[name]
			c.rules[0][1] = "udp"
			c.rules[0][3] = "udp"
			s.chains[name] = c
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, f := newFake(t, name)
			if err := m.UpdateListeners(runtimeListeners()); err != nil {
				t.Fatal(err)
			}
			mutate(f.states[f.backends[0].key()], m.name)
			s, err := m.CheckListeners(runtimeListeners())
			if err != nil || s.Healthy || !s.Repairable {
				t.Fatal(s, err)
			}
			if err := m.UpdateListeners(runtimeListeners()); err != nil {
				t.Fatal(err)
			}
			s, err = m.CheckListeners(runtimeListeners())
			if err != nil || !s.Healthy {
				t.Fatal(s, err)
			}
		})
	}
}

func TestRuntimeUnknownResourcesAndExternalManagersArePreserved(t *testing.T) {
	for _, external := range []bool{false, true} {
		m, f := newFake(t, "foreign-preserve")
		if err := m.UpdateListeners(runtimeListeners()); err != nil {
			t.Fatal(err)
		}
		s := f.states[f.backends[0].key()]
		if external {
			s.chains["ufw-before-input"] = chain{policy: "-"}
		} else {
			c := s.chains[m.name]
			c.rules = append(c.rules, []string{"-j", "ACCEPT"})
			s.chains[m.name] = c
		}
		before := cloneSnapshot(s)
		count := len(f.scripts)
		status, err := m.CheckListeners(runtimeListeners())
		if err == nil || status.Repairable || status.Healthy {
			t.Fatal(status, err)
		}
		if err := m.UpdateListeners(runtimeListeners()); err == nil {
			t.Fatal("unknown resources accepted")
		}
		if len(f.scripts) != count || !reflect.DeepEqual(before, s) {
			t.Fatal("foreign resources mutated")
		}
	}
}

func TestRuntimeValidationAndFutureProtocols(t *testing.T) {
	for _, v := range []Listener{
		{Protocol: "vless", Transport: "tcp", ListenPort: 0},
		{Protocol: "", Transport: "tcp", ListenPort: 443},
		{Protocol: "future", Transport: "sctp", ListenPort: 443},
		{Protocol: "future", Transport: "tcp", ListenPort: 443, ListenAddress: "host.invalid"},
	} {
		m, f := newFake(t, "invalid-runtime")
		if m.UpdateListeners([]Listener{v}) != errInvalid {
			t.Fatal(v)
		}
		if _, err := m.CheckListeners([]Listener{v}); err != errInvalid {
			t.Fatal(v, err)
		}
		if f.leased+f.checks+len(f.scripts) != 0 {
			t.Fatal("invalid listener touched host")
		}
	}
	m, f := newFake(t, "future")
	v := Listener{Protocol: "future-registered-kernel", Transport: "tcp", ListenPort: 29999}
	if err := m.UpdateListeners([]Listener{v, v}); err != nil {
		t.Fatal(err)
	}
	if len(ownedAt(t, f, f.backends[0])[m.name].rules) != 2 {
		t.Fatal("duplicate runtime socket was not deduplicated")
	}
}

func TestRuntimeRepairVerifiesCommittedResult(t *testing.T) {
	m, f := newFake(t, "post-verify")
	f.afterApply = func(f *fakeSystem, b backend) {
		s := f.states[b.key()]
		c := s.chains["INPUT"]
		c.rules = c.rules[1:]
		s.chains["INPUT"] = c
		s.input = c.rules
	}
	if err := m.UpdateListeners(runtimeListeners()); !errors.Is(err, errVerification) {
		t.Fatal("lost committed jump not detected", err)
	}
	if strings.Contains(errVerification.Error(), "secret") {
		t.Fatal("private error exposed")
	}
}

func TestRuntimePerPortStatusDistinguishesMissingTCPFromAllowedUDP(t *testing.T) {
	m, f := newFake(t, "per-port")
	want := runtimeListeners()
	if err := m.UpdateListeners(want); err != nil {
		t.Fatal(err)
	}
	s := f.states[f.backends[0].key()]
	c := s.chains[m.name]
	c.rules = c.rules[1:]
	s.chains[m.name] = c // sorted TCP precedes UDP
	status, err := m.CheckListeners(want)
	if err != nil || status.Healthy || len(status.Listeners) != 3 {
		t.Fatal(status, err)
	}
	if status.Listeners[0].Allowed || !status.Listeners[1].Allowed || !status.Listeners[2].Allowed {
		t.Fatal("per-port status conflated TCP and UDP", status.Listeners)
	}
	// A validly marked RETURN moved ahead of UDP blocks it despite rule presence.
	c.rules = append(c.rules[len(c.rules)-1:], c.rules[:len(c.rules)-1]...)
	s.chains[m.name] = c
	status, err = m.CheckListeners(want)
	if err != nil || status.Listeners[1].Allowed {
		t.Fatal("permission after RETURN reported as allowed", status, err)
	}
}
