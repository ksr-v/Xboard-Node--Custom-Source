package service

import (
	"context"
	"errors"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/inputfirewall"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

type recordedNetworkRules struct {
	calls     []*model.NodeSpec
	listeners [][]inputfirewall.Listener
	fail      func(*model.NodeSpec) bool
	failInput bool
	closed    bool
	onUpdate  func()
	onClose   func()
}
type networkPush struct{ connected bool }

func (p networkPush) Run(context.Context)               {}
func (p networkPush) IsConnected() bool                 { return p.connected }
func (p networkPush) SendDeviceReport(map[int][]string) {}
func (r *recordedNetworkRules) Update(n *model.NodeSpec) error {
	r.calls = append(r.calls, n)
	if r.onUpdate != nil {
		r.onUpdate()
	}
	if r.fail != nil && r.fail(n) {
		return errors.New("fixture NAT failure")
	}
	return nil
}
func (r *recordedNetworkRules) UpdateListeners(listeners []inputfirewall.Listener) error {
	r.listeners = append(r.listeners, append([]inputfirewall.Listener(nil), listeners...))
	if r.onUpdate != nil {
		r.onUpdate()
	}
	if r.failInput {
		return errors.New("fixture INPUT failure")
	}
	return nil
}
func (r *recordedNetworkRules) CheckListeners([]inputfirewall.Listener) (inputfirewall.Status, error) {
	return inputfirewall.Status{Healthy: !r.failInput, Repairable: true}, nil
}
func (r *recordedNetworkRules) Close() error {
	r.closed = true
	if r.onClose != nil {
		r.onClose()
	}
	return nil
}

func TestServiceManagedInputHasOnlyLocalGrant(t *testing.T) {
	for _, env := range []string{"", "0", "1"} {
		for _, optOut := range []bool{false, true} {
			t.Setenv("XBOARD_NODE_MANAGED_INPUT", env)
			cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
			if optOut {
				value := false
				cfg.Firewall.ManagedInput = &value
			}
			s := newService(cfg, nil)
			want := env == "1" && !optOut
			if (s.inputFirewall != nil) != want {
				t.Fatal("local authorization was ignored")
			}
			s.applyRemoteOverrides(context.Background(), &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: 18443})
			if (s.inputFirewall != nil) != want {
				t.Fatal("remote snapshot granted host permissions")
			}
		}
	}
}

func TestInputFailureIsNonfatalAndRetriesAfterKernelStarted(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	input := &recordedNetworkRules{failInput: true}
	s.inputFirewall = input
	n := &model.NodeSpec{Protocol: "vless", ServerPort: 18443}
	k.onStart = func() {
		if len(input.listeners) != 0 {
			t.Fatal("INPUT opened before kernel accepted listener")
		}
	}
	if !s.startKernel(n, []model.UserSpec{{ID: 1, UUID: "fixture"}}) || !k.running || s.appliedState.Config != n {
		t.Fatal("INPUT error stopped working kernel")
	}
	if len(input.listeners) != 1 || input.listeners[0][0].Transport != "tcp" {
		t.Fatal("VLESS runtime not registered")
	}
	input.failInput = false
	s.reconcileActiveNetworkRules()
	if len(input.listeners) != 2 || k.startCalls != 1 {
		t.Fatal("INPUT recovery restarted kernel or was not retried")
	}
}

func TestFailedKernelDoesNotOpenCandidateInput(t *testing.T) {
	k := &fakeKernel{startErr: errors.New("bind failed")}
	s := newTestService(k)
	input := &recordedNetworkRules{}
	s.inputFirewall = input
	if s.startKernel(hoppingSpec(20000), []model.UserSpec{{ID: 1}}) {
		t.Fatal("failed kernel accepted")
	}
	for _, listeners := range input.listeners {
		if len(listeners) != 0 {
			t.Fatal("failed candidate listener was opened")
		}
	}
}

func TestNATFailureDoesNotApplyNewInput(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	old, desired := hoppingSpec(20000), hoppingSpec(21000)
	s.appliedState.Config, s.lastConfig = old, desired
	s.lastUsers = []model.UserSpec{{ID: 1}}
	s.portForward = &recordedNetworkRules{fail: func(*model.NodeSpec) bool { return true }}
	input := &recordedNetworkRules{}
	s.inputFirewall = input
	s.applyChanges(context.Background(), true, false)
	if k.reloadCalls != 0 || len(input.listeners) != 0 || s.appliedState.Config != old {
		t.Fatal("NAT failure changed INPUT/kernel")
	}
}

func TestKernelReloadFailureUsesActualRecoveredInput(t *testing.T) {
	old, desired := hoppingSpec(20000), hoppingSpec(21000)
	desired.ServerPort = 18444
	k := &fakeKernel{running: true, reloadErr: errors.New("previous kernel restored"), runtime: fakeRuntime(old)}
	s := newTestService(k)
	s.appliedState.Config, s.lastConfig = old, desired
	s.lastUsers = []model.UserSpec{{ID: 1}}
	nat, input := &recordedNetworkRules{}, &recordedNetworkRules{}
	s.portForward, s.inputFirewall = nat, input
	s.applyChanges(context.Background(), true, false)
	if len(nat.calls) != 2 || nat.calls[0] != desired || nat.calls[1] != old {
		t.Fatal("NAT rollback lost")
	}
	if len(input.listeners) != 1 || input.listeners[0][0].ListenPort != old.ServerPort || k.startCalls != 0 {
		t.Fatal("INPUT followed rejected panel snapshot")
	}
}

func TestPeriodicInputUsesKernelRuntimeEvenWithNoUsers(t *testing.T) {
	for _, connected := range []bool{false, true} {
		actual := kernel.Inbound{Protocol: "shadowsocks", Transport: "udp", ListenAddress: "127.0.0.2", ListenPort: 19555}
		k := &fakeKernel{running: true, runtime: []kernel.Inbound{actual}}
		s := newTestService(k)
		s.appliedState.Config = hoppingSpec(20000)
		s.lastConfig = &model.NodeSpec{Protocol: "vless", ServerPort: 18444}
		s.lastConfigHash = computeConfigHash(s.lastConfig)
		s.wsClient = networkPush{connected: connected}
		input := &recordedNetworkRules{}
		s.inputFirewall = input
		s.reconcileNetworkRules(context.Background())
		if len(input.listeners) != 1 || len(input.listeners[0]) != 1 || input.listeners[0][0].ListenPort != actual.ListenPort || input.listeners[0][0].ListenAddress != actual.ListenAddress {
			t.Fatal("periodic repair guessed panel configuration or ignored active zero-user listener")
		}
	}
}

func TestInactivePeriodicInputRemovesAcceptedOldPorts(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.appliedState.Config = hoppingSpec(20000)
	input := &recordedNetworkRules{}
	s.inputFirewall = input
	s.reconcileActiveNetworkRules()
	if len(input.listeners) != 1 || len(input.listeners[0]) != 0 {
		t.Fatal("inactive kernel restored old permissions")
	}
}

func localNetworkFixture() *config.Config {
	return &config.Config{Kernel: config.KernelConfig{Type: "singbox"}, Node: config.NodeConfig{TrackInterval: 10, DeviceReportInterval: 30}, WS: config.WSConfig{DiscoveryInterval: 300}, Standalone: &config.StandaloneConfig{Enabled: true, Node: config.StandaloneNodeConfig{Protocol: "vless", ServerPort: 18443}, Users: []config.StandaloneUser{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}}}
}

func TestInitialInputFailureKeepsServiceRunning(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.cfg = localNetworkFixture()
	s.source = controlplane.NewLocalControlPlane(s.cfg)
	input := &recordedNetworkRules{failInput: true}
	s.inputFirewall = input
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatalf("INPUT error discarded service: %v", err)
	}
	if !k.running || s.appliedState.Config == nil {
		t.Fatal("INPUT error prevented kernel activation")
	}
	input.failInput = false
	s.reconcileNetworkRules(context.Background())
	if k.startCalls != 1 || len(input.listeners) != 2 {
		t.Fatal("recovery failed or restarted kernel")
	}
}

func TestServiceShutdownStopsKernelBeforeRuleCleanup(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.tracker = tracker.New()
	s.cfg = localNetworkFixture()
	cp := controlplane.NewLocalControlPlane(s.cfg)
	s.source, s.sink = cp, cp
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nat, input := &recordedNetworkRules{}, &recordedNetworkRules{}
	input.onUpdate = func() {
		if k.running {
			cancel()
		}
	}
	input.onClose = func() {
		if k.running {
			t.Error("INPUT cleanup preceded kernel stop")
		}
	}
	nat.onClose = func() {
		if k.running {
			t.Error("NAT cleanup preceded kernel stop")
		}
	}
	s.portForward, s.inputFirewall = nat, input
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !nat.closed || !input.closed || k.running {
		t.Fatal("shutdown cleanup incomplete")
	}
}
