package service

import (
	"context"
	"errors"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

type fakePortForward struct {
	err    error
	calls  []*model.NodeSpec
	closed bool
}

func (f *fakePortForward) Update(n *model.NodeSpec) error {
	f.calls = append(f.calls, n)
	return f.err
}
func (f *fakePortForward) Close() error { f.closed = true; return nil }

func hoppingSpec(start int) *model.NodeSpec {
	return &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: 443, PortHopping: &model.PortHopping{Start: start, End: start + 9}}
}

func TestPortForwardFailurePreservesKernelAndRetriesAfter304(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	f := &fakePortForward{err: errors.New("CAP_NET_ADMIN denied")}
	s.portForward = f
	old, desired := hoppingSpec(20000), hoppingSpec(21000)
	s.appliedState.Config, s.lastConfig = old, desired
	s.lastUsers = []model.UserSpec{{ID: 1, UUID: "fixture"}}
	s.lastConfigHash = computeConfigHash(desired)
	s.applyChanges(context.Background(), true, false)
	if k.reloadCalls != 0 || !k.running || s.appliedState.Config != old || s.lastConfigHash != computeConfigHash(old) {
		t.Fatal("privilege failure touched the running kernel or accepted desired config")
	}
	f.err = nil
	s.applyPullResult(context.Background(), pullResult{})
	if k.reloadCalls != 1 || s.appliedState.Config != desired || len(f.calls) != 2 {
		t.Fatal("unaccepted forwarding configuration not retried")
	}
}

func TestKernelReloadFailureRestoresPreviousPortForward(t *testing.T) {
	k := &fakeKernel{running: true, reloadErr: errors.New("candidate invalid; previous kernel restored")}
	s := newTestService(k)
	f := &fakePortForward{}
	s.portForward = f
	old, desired := hoppingSpec(20000), hoppingSpec(21000)
	s.appliedState.Config, s.lastConfig = old, desired
	s.lastUsers = []model.UserSpec{{ID: 1, UUID: "fixture"}}
	s.applyChanges(context.Background(), true, false)
	if len(f.calls) != 2 || f.calls[0] != desired || f.calls[1] != old || k.startCalls != 0 || s.appliedState.Config != old {
		t.Fatal("kernel rejection did not restore old mapping without overwriting recovered kernel")
	}
}

func TestFailedInitialStartRemovesCandidateForwardAndCleanup(t *testing.T) {
	k := &fakeKernel{startErr: errors.New("listener in use")}
	s := newTestService(k)
	f := &fakePortForward{}
	s.portForward = f
	if s.startKernel(hoppingSpec(20000), []model.UserSpec{{ID: 1, UUID: "fixture"}}) {
		t.Fatal("failed kernel accepted")
	}
	if len(f.calls) != 2 || f.calls[1] != nil {
		t.Fatal("failed initial startup left candidate forwarding")
	}
	s.closePortForward()
	if !f.closed {
		t.Fatal("service cleanup omitted forwarding manager")
	}
}

func TestPortHoppingRangeChangesConfigurationHash(t *testing.T) {
	if computeConfigHash(hoppingSpec(20000)) == computeConfigHash(hoppingSpec(21000)) {
		t.Fatal("range changes do not trigger config application")
	}
}

func TestConnectedPushTickRetriesRejectedForwardingWithoutNewSave(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	f := &fakePortForward{err: errors.New("temporarily denied")}
	s.portForward = f
	old, desired := hoppingSpec(20000), hoppingSpec(21000)
	s.lastConfig, s.appliedState.Config = desired, old
	s.lastConfigHash = computeConfigHash(old)
	s.lastUsers = []model.UserSpec{{ID: 1, UUID: "fixture"}}
	s.retryPendingConfig(context.Background())
	if k.reloadCalls != 0 {
		t.Fatal("rejected mapping changed running kernel")
	}
	f.err = nil
	s.retryPendingConfig(context.Background())
	if k.reloadCalls != 1 || s.appliedState.Config != desired {
		t.Fatal("connected WS tick failed to retry pending mapping")
	}
	s.retryPendingConfig(context.Background())
	if k.reloadCalls != 1 {
		t.Fatal("accepted config was needlessly reapplied")
	}
}

func TestHoppingStartsWhenFirstEligibleUserArrives(t *testing.T) {
	for _, delta := range []bool{false, true} {
		k := &fakeKernel{}
		s := newTestService(k)
		f := &fakePortForward{}
		s.portForward = f
		s.lastConfig = hoppingSpec(20000)
		users := []model.UserSpec{{ID: 1, UUID: "fixture"}}
		if delta {
			s.applyUserDelta(context.Background(), "add", users)
		} else {
			s.applyUserUpdate(context.Background(), users, computeUserHash(users))
		}
		if !k.running || k.startCalls != 1 || len(f.calls) != 1 || f.calls[0] != s.lastConfig || len(s.lastUsers) != 1 {
			t.Fatalf("first user did not start listener and forwarding (delta=%v)", delta)
		}
	}
}
