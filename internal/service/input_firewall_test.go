package service

import (
	"context"
	"errors"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

type recordedNetworkRules struct {
	calls    []*model.NodeSpec
	fail     func(*model.NodeSpec) bool
	closed   bool
	onUpdate func()
	onClose  func()
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
		return errors.New("fixture rule failure")
	}
	return nil
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
			if got, want := s.inputFirewall != nil, env == "1" && !optOut; got != want {
				t.Fatalf("env=%q optout=%v manager=%v want=%v", env, optOut, got, want)
			}
			// Panel-owned NodeSpec has no host policy field, and overrides must
			// not reinterpret protocol/config changes as a local permission grant.
			s.applyRemoteOverrides(context.Background(), &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: 18443})
			if (s.inputFirewall != nil) != (env == "1" && !optOut) {
				t.Fatal("remote override changed local firewall grant")
			}
		}
	}
}

func TestInputFailureRestoresNATAndPreservesAcceptedKernel(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	old, desired := hoppingSpec(20000), hoppingSpec(21000)
	s.appliedState.Config, s.lastConfig = old, desired
	s.lastUsers = []model.UserSpec{{ID: 1, UUID: "fixture"}}
	nat := &recordedNetworkRules{}
	input := &recordedNetworkRules{fail: func(n *model.NodeSpec) bool { return n == desired }}
	s.portForward, s.inputFirewall = nat, input
	s.applyChanges(context.Background(), true, false)
	if k.reloadCalls != 0 || !k.running || s.appliedState.Config != old || s.lastConfigHash != computeConfigHash(old) {
		t.Fatal("failed INPUT candidate changed accepted kernel/config")
	}
	if len(nat.calls) != 2 || nat.calls[0] != desired || nat.calls[1] != old || len(input.calls) != 2 || input.calls[1] != old {
		t.Fatal("failed INPUT candidate did not compensate both rule managers")
	}
	input.fail = nil
	s.retryPendingConfig(context.Background())
	if k.reloadCalls != 1 || s.appliedState.Config != desired || s.lastConfigHash != computeConfigHash(desired) {
		t.Fatal("pending network configuration was not retryable")
	}
}

func TestNATFailureDoesNotApplyNewInput(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	old, desired := hoppingSpec(20000), hoppingSpec(21000)
	s.appliedState.Config, s.lastConfig = old, desired
	s.lastUsers = []model.UserSpec{{ID: 1, UUID: "fixture"}}
	s.portForward = &recordedNetworkRules{fail: func(*model.NodeSpec) bool { return true }}
	input := &recordedNetworkRules{}
	s.inputFirewall = input
	s.applyChanges(context.Background(), true, false)
	if k.reloadCalls != 0 || len(input.calls) != 0 || s.appliedState.Config != old {
		t.Fatal("failed NAT changed INPUT/kernel")
	}
}

func TestKernelReloadFailureRestoresInputAndNAT(t *testing.T) {
	k := &fakeKernel{running: true, reloadErr: errors.New("previous kernel restored")}
	s := newTestService(k)
	old, desired := hoppingSpec(20000), hoppingSpec(21000)
	s.appliedState.Config, s.lastConfig = old, desired
	s.lastUsers = []model.UserSpec{{ID: 1, UUID: "fixture"}}
	nat, input := &recordedNetworkRules{}, &recordedNetworkRules{}
	s.portForward, s.inputFirewall = nat, input
	s.applyChanges(context.Background(), true, false)
	for _, rules := range []*recordedNetworkRules{nat, input} {
		if len(rules.calls) != 2 || rules.calls[0] != desired || rules.calls[1] != old {
			t.Fatal("kernel rejection did not restore accepted rule target")
		}
	}
	if k.startCalls != 0 || s.appliedState.Config != old {
		t.Fatal("recovered kernel/config overwritten")
	}
}

func TestPeriodicNetworkRepairUsesAppliedSnapshotWithOrWithoutPush(t *testing.T) {
	for _, disconnected := range []bool{false, true} {
		k := &fakeKernel{running: true}
		s := newTestService(k)
		old, desired := hoppingSpec(20000), hoppingSpec(21000)
		s.appliedState.Config, s.lastConfig = old, desired
		s.lastConfigHash = computeConfigHash(old)
		s.lastUsers = []model.UserSpec{{ID: 1, UUID: "fixture"}}
		// Reject the pending snapshot. The repair must still use accepted old.
		nat := &recordedNetworkRules{fail: func(n *model.NodeSpec) bool { return n == desired }}
		input := &recordedNetworkRules{}
		s.portForward, s.inputFirewall = nat, input
		s.wsClient = networkPush{connected: !disconnected}
		s.reconcileNetworkRules(context.Background())
		if len(input.calls) != 1 || input.calls[0] != old || nat.calls[len(nat.calls)-1] != old {
			t.Fatal("repair used pending/rejected config or depended on WS")
		}
	}
}

func TestInactivePeriodicRepairCleansOwnedRules(t *testing.T) {
	for _, running := range []bool{false, true} {
		k := &fakeKernel{running: running}
		s := newTestService(k)
		s.appliedState.Config = hoppingSpec(20000)
		nat, input := &recordedNetworkRules{}, &recordedNetworkRules{}
		s.portForward, s.inputFirewall = nat, input
		s.reconcileActiveNetworkRules()
		if len(nat.calls) != 1 || nat.calls[0] != nil || len(input.calls) != 1 || input.calls[0] != nil {
			t.Fatal("inactive node restored an old open port")
		}
	}
}

func localNetworkFixture() *config.Config {
	return &config.Config{
		Kernel: config.KernelConfig{Type: "singbox"},
		Node:   config.NodeConfig{TrackInterval: 10, DeviceReportInterval: 30},
		WS:     config.WSConfig{DiscoveryInterval: 300},
		Standalone: &config.StandaloneConfig{Enabled: true,
			Node:  config.StandaloneNodeConfig{Protocol: "vless", ServerPort: 18443},
			Users: []config.StandaloneUser{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}},
	}
}

func TestInitialNetworkFailureRemainsInServiceForAutomaticRetry(t *testing.T) {
	k := &fakeKernel{}
	s := newTestService(k)
	s.cfg = localNetworkFixture()
	s.source = controlplane.NewLocalControlPlane(s.cfg)
	s.inputFirewall = &recordedNetworkRules{fail: func(n *model.NodeSpec) bool { return n != nil }}
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatalf("transient startup rules failure discarded Service: %v", err)
	}
	if k.running || s.appliedState.Config != nil || s.lastConfig == nil || s.lastConfigHash == computeConfigHash(s.lastConfig) {
		t.Fatal("failed startup accepted desired config")
	}
	s.inputFirewall.(*recordedNetworkRules).fail = nil
	s.reconcileNetworkRules(context.Background())
	if !k.running || k.startCalls != 1 || s.appliedState.Config != s.lastConfig {
		t.Fatal("initial desired config did not recover")
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
	input.onUpdate = cancel
	input.onClose = func() {
		if k.running {
			t.Error("INPUT cleanup ran before kernel stop")
		}
	}
	nat.onClose = func() {
		if k.running {
			t.Error("NAT cleanup ran before kernel stop")
		}
	}
	s.portForward, s.inputFirewall = nat, input
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !nat.closed || !input.closed || k.running {
		t.Fatal("shutdown omitted owned rule cleanup")
	}
}
