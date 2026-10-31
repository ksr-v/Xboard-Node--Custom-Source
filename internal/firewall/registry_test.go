package firewall

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/inputfirewall"
)

type registryManager struct {
	updates    int
	checks     int
	closes     int
	listeners  []inputfirewall.Listener
	fail       bool
	onUpdate   func()
	reserves   int
	releases   int
	reserveErr error
	closeErr   error
	checkErr   error
	status     *inputfirewall.Status
	lifecycle  []string
}

func (m *registryManager) UpdateListeners(listeners []inputfirewall.Listener) error {
	m.updates++
	if m.onUpdate != nil {
		m.onUpdate()
	}
	if m.fail {
		return errors.New("fixture denied")
	}
	m.listeners = append([]inputfirewall.Listener(nil), listeners...)
	return nil
}
func (m *registryManager) CheckListeners([]inputfirewall.Listener) (inputfirewall.Status, error) {
	m.checks++
	if m.status != nil {
		return *m.status, m.checkErr
	}
	return inputfirewall.Status{Healthy: !m.fail, Repairable: true}, nil
}
func (m *registryManager) Close() error {
	m.closes++
	m.lifecycle = append(m.lifecycle, "close")
	return m.closeErr
}
func (m *registryManager) Reserve() error {
	m.reserves++
	m.lifecycle = append(m.lifecycle, "reserve")
	return m.reserveErr
}
func (m *registryManager) ReleaseReservation() {
	m.releases++
	m.lifecycle = append(m.lifecycle, "release")
}

func TestRegistryReportsLivePortsReadOnlyAndHonorsLocalAuthorization(t *testing.T) {
	r := NewRegistry()
	live := []inputfirewall.Listener{{Protocol: "vless", Transport: "tcp", ListenAddress: "::", ListenPort: 18443}}
	enabled, disabled := &registryManager{}, &registryManager{}
	a := r.RegisterWithManager("a", "instance-a", 1, true, func() ([]inputfirewall.Listener, error) { return live, nil }, enabled)
	b := r.RegisterWithManager("b", "instance-b", 2, false, func() ([]inputfirewall.Listener, error) { return live, nil }, disabled)
	defer a.Close()
	defer b.Close()
	if enabled.reserves != 1 || disabled.reserves != 1 {
		t.Fatal("live owners were not reserved independently of local mutation permission")
	}
	report := r.Report()
	if !report.Healthy || len(report.Ports) != 2 || enabled.updates != 0 || disabled.updates != 0 {
		t.Fatal("report mutated rules or omitted a disabled registration")
	}
	if err := b.Sync(); err != nil {
		t.Fatal(err)
	}
	r.Repair()
	if enabled.updates != 1 || disabled.updates != 0 {
		t.Fatal("repair bypassed local authorization")
	}
	live = nil
	report = r.Report()
	if len(report.Ports) != 0 {
		t.Fatal("report cached a stopped runtime listener")
	}
}

func TestRegistryReservationFailureAndDuplicateDoNotReplaceLiveOwner(t *testing.T) {
	r := NewRegistry()
	provider := func() ([]inputfirewall.Listener, error) { return nil, nil }
	denied := &registryManager{reserveErr: errors.New("owner already reserved")}
	failed := r.RegisterWithManager("owner", "first", 1, true, provider, denied)
	if !failed.conflict || failed.Sync() == nil || len(r.Report().Owners) != 0 {
		t.Fatal("failed reservation installed an owner")
	}
	failed.Close()
	if denied.releases != 0 {
		t.Fatal("failed reservation released another live owner's reservation")
	}
	liveManager := &registryManager{}
	live := r.RegisterWithManager("owner", "second", 2, false, provider, liveManager)
	defer live.Close()
	duplicateManager := &registryManager{}
	duplicate := r.RegisterWithManager("owner", "third", 3, true, provider, duplicateManager)
	duplicate.Close()
	report := r.Report()
	if duplicateManager.reserves != 0 || duplicateManager.releases != 0 || len(report.Owners) != 1 || report.Owners[0].NodeID != 2 {
		t.Fatal("duplicate registration changed live reservation")
	}
}

func TestRegistryReleasesDisabledAndFailedCleanupReservations(t *testing.T) {
	for _, managed := range []bool{false, true} {
		r := NewRegistry()
		m := &registryManager{closeErr: errors.New("cleanup denied")}
		registration := r.RegisterWithManager("owner", "instance", 1, managed, func() ([]inputfirewall.Listener, error) { return nil, nil }, m)
		err := registration.Close()
		if (err != nil) != managed || m.releases != 1 || m.closes != map[bool]int{true: 1, false: 0}[managed] {
			t.Fatalf("managed=%v reservation cleanup incomplete", managed)
		}
		if managed && (len(m.lifecycle) != 3 || m.lifecycle[1] != "close" || m.lifecycle[2] != "release") {
			t.Fatal("reservation released before managed cleanup")
		}
		registration.Close()
		if m.releases != 1 {
			t.Fatal("reservation released twice")
		}
	}
}

func TestRegistrySeparatesOwnedPermissionsFromEffectiveInput(t *testing.T) {
	listener := inputfirewall.Listener{Protocol: "vless", Transport: "tcp", ListenAddress: "::", ListenPort: 18443}
	for _, effective := range []string{"allowed", "blocked", "unknown"} {
		r := NewRegistry()
		m := &registryManager{status: &inputfirewall.Status{Healthy: false, Repairable: true, Listeners: []inputfirewall.ListenerStatus{{Listener: listener, RuleStatus: "missing", EffectiveStatus: effective}}}}
		registration := r.RegisterWithManager("owner", "instance", 1, true, func() ([]inputfirewall.Listener, error) { return []inputfirewall.Listener{listener}, nil }, m)
		report := r.Report()
		if report.Ports[0].RuleStatus != "missing" || report.Ports[0].EffectiveStatus != effective {
			t.Fatal("missing owned permission was conflated with actual INPUT verdict")
		}
		m.checkErr = errors.New("native inspection unavailable")
		if r.Report().Ports[0].EffectiveStatus != "unknown" {
			t.Fatal("inspection failure retained an unproven INPUT verdict")
		}
		registration.Close()
	}
}

func TestRegistryDiscoveryFailureDoesNotWritePartialPermissions(t *testing.T) {
	r := NewRegistry()
	m := &registryManager{}
	registration := r.RegisterWithManager("owner", "instance", 1, true, func() ([]inputfirewall.Listener, error) {
		return []inputfirewall.Listener{{Protocol: "http", Transport: "tcp", ListenAddress: "::", ListenPort: 18443}}, errors.New("unknown runtime transport")
	}, m)
	defer registration.Close()
	if registration.Sync() == nil {
		t.Fatal("unknown runtime silently accepted")
	}
	report := r.Repair()
	if report.Healthy || m.updates != 0 || len(report.Issues) != 1 || report.Ports[0].RuleStatus != "unknown" || report.Owners[0].Status.Repairable {
		t.Fatal("discovery failure opened partial listener set")
	}
}

func TestRegistryConcurrentRepairAndOwnerIsolation(t *testing.T) {
	r := NewRegistry()
	aManager, bManager := &registryManager{}, &registryManager{}
	provider := func() ([]inputfirewall.Listener, error) { return nil, nil }
	a := r.RegisterWithManager("a", "instance", 1, true, provider, aManager)
	b := r.RegisterWithManager("b", "instance", 2, true, provider, bManager)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.Repair() }()
	}
	wg.Wait()
	if aManager.updates != 100 || bManager.updates != 100 {
		t.Fatal("concurrent repair lost synchronization")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if aManager.closes != 1 || bManager.closes != 0 || len(r.Report().Owners) != 1 {
		t.Fatal("close affected a different instance")
	}
	duplicate := r.RegisterWithManager("b", "other", 3, true, provider, &registryManager{})
	if duplicate.Sync() == nil {
		t.Fatal("duplicate stable owner accepted")
	}
	duplicate.Close()
	if len(r.Report().Owners) != 1 {
		t.Fatal("duplicate registration removed the live owner")
	}
	b.Close()
}

func TestRegistryRepairCannotRaceRuntimeReplacement(t *testing.T) {
	r := NewRegistry()
	entered, release, changed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	m := &registryManager{}
	live := []inputfirewall.Listener{{Protocol: "vless", Transport: "tcp", ListenAddress: "::", ListenPort: 18443}}
	registration := r.RegisterWithManager("owner", "instance", 1, true, func() ([]inputfirewall.Listener, error) { return live, nil }, m)
	defer registration.Close()
	var once sync.Once
	m.onUpdate = func() { once.Do(func() { close(entered); <-release }) }
	repaired := make(chan struct{})
	go func() { r.Repair(); close(repaired) }()
	<-entered
	replaced := make(chan struct{})
	go func() {
		registration.ChangeRuntime(func() error { live = nil; close(changed); return nil })
		close(replaced)
	}()
	select {
	case <-changed:
		t.Fatal("runtime changed while a repair used its earlier snapshot")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-repaired:
	case <-time.After(time.Second):
		t.Fatal("repair stalled")
	}
	select {
	case <-replaced:
	case <-time.After(time.Second):
		t.Fatal("replacement stalled")
	}
	if len(m.listeners) != 0 {
		t.Fatal("stopped listener was reopened by concurrent repair")
	}
}
