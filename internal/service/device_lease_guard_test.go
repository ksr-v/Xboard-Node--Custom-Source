package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

type leaseGuardKernel struct {
	*fakeKernel
	closed []string
}

func (k *leaseGuardKernel) CloseUserConnections(_ context.Context, userUUID string) error {
	k.closed = append(k.closed, userUUID)
	return nil
}

func TestLeaseGuardClosesOnlyLimitedOnlineUsersBeforeExpiry(t *testing.T) {
	start := time.Now()
	k := &leaseGuardKernel{fakeKernel: &fakeKernel{running: true}}
	s := &Service{kernel: k, tracker: tracker.New(), deviceLeaseGuard: newDeviceLeaseGuard(start)}
	s.lastUsers = []model.UserSpec{
		{ID: 1, UUID: "limited-online", DeviceLimit: 1},
		{ID: 2, UUID: "unlimited-online", DeviceLimit: 0},
		{ID: 3, UUID: "limited-offline", DeviceLimit: 1},
	}
	s.tracker.Process(nil, map[int]map[string]bool{1: {"127.0.0.2": true}, 2: {"127.0.0.3": true}}, 2)
	s.enforceDeviceLeaseAt(context.Background(), start.Add(54*time.Second))
	if len(k.closed) != 0 {
		t.Fatal("live lease was closed early")
	}
	s.enforceDeviceLeaseAt(context.Background(), start.Add(55*time.Second))
	if !reflect.DeepEqual(k.closed, []string{"limited-online"}) {
		t.Fatalf("wrong connections closed: %v", k.closed)
	}
	// Acknowledged reporting recovers without waiting for a node restart.
	s.acknowledgeDeviceReportAt(start.Add(56 * time.Second))
	s.enforceDeviceLeaseAt(context.Background(), start.Add(110*time.Second))
	if len(k.closed) != 1 {
		t.Fatal("recovered lease kept closing connections")
	}
	s.enforceDeviceLeaseAt(context.Background(), start.Add(111*time.Second))
	if len(k.closed) != 2 {
		t.Fatal("new report lease did not expire independently")
	}
}

func TestLeaseGuardDoesNotAffectOlderPanels(t *testing.T) {
	k := &leaseGuardKernel{fakeKernel: &fakeKernel{running: true}}
	s := &Service{kernel: k, tracker: tracker.New(), lastUsers: []model.UserSpec{{ID: 1, UUID: "limited", DeviceLimit: 1}}}
	s.tracker.Process(nil, map[int]map[string]bool{1: {"127.0.0.2": true}}, 1)
	s.enforceDeviceLeaseAt(context.Background(), time.Now().Add(time.Hour))
	s.acknowledgeDeviceReportAt(time.Now())
	if len(k.closed) != 0 || s.deviceLeaseGuard != nil {
		t.Fatal("older panel received lease-enforcement behavior")
	}
}

type leaseGuardSource struct{ controlplane.Source }

func (*leaseGuardSource) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }

type leaseGuardSink struct {
	controlplane.Sink
	err error
}

func (*leaseGuardSink) SupportsReporting() bool                   { return true }
func (s *leaseGuardSink) Report(controlplane.ReportPayload) error { return s.err }

func TestOnlyAcknowledgedReportsRenewLease(t *testing.T) {
	s := newTestService(&fakeKernel{running: true})
	s.tracker = tracker.New()
	s.source = &leaseGuardSource{}
	s.sink = &leaseGuardSink{err: errors.New("unavailable")}
	old := time.Now().Add(-deviceLeaseAcknowledgementWindow)
	s.deviceLeaseGuard = newDeviceLeaseGuard(old)
	s.pushReportSync()
	if !s.deviceLeaseGuard.expired(time.Now()) {
		t.Fatal("failed report renewed forwarding lease")
	}
	s.sink = &leaseGuardSink{}
	s.pushReportSync()
	if s.deviceLeaseGuard.expired(time.Now()) {
		t.Fatal("successful full report did not recover forwarding lease")
	}
}

func TestLeaseGuardRejectsOlderAcknowledgements(t *testing.T) {
	start := time.Now()
	guard := newDeviceLeaseGuard(start)
	guard.acknowledge(start.Add(20 * time.Second))
	guard.acknowledge(start.Add(5 * time.Second))
	if guard.expired(start.Add(74 * time.Second)) {
		t.Fatal("older ACK moved the forwarding lease backwards")
	}
}

type heartbeatGuardSink struct {
	controlplane.Sink
	reports chan struct{}
}

func (*heartbeatGuardSink) SupportsReporting() bool { return true }
func (s *heartbeatGuardSink) Report(controlplane.ReportPayload) error {
	s.reports <- struct{}{}
	return nil
}

func TestLeaseHeartbeatRecoveryDoesNotWaitForLegacyBackoff(t *testing.T) {
	for _, capable := range []bool{false, true} {
		s := newTestService(&fakeKernel{running: true})
		s.tracker = tracker.New()
		s.source = &leaseGuardSource{}
		sink := &heartbeatGuardSink{reports: make(chan struct{}, 1)}
		s.sink = sink
		s.pushBackoff.skipRemaining = 8
		if capable {
			s.deviceLeaseGuard = newDeviceLeaseGuard(time.Now())
		}
		s.pushReportAsync()
		if !capable {
			if len(sink.reports) != 0 || s.pushActive.Load() {
				t.Fatal("legacy panel report no longer obeys its backoff")
			}
			continue
		}
		select {
		case <-sink.reports:
		case <-time.After(2 * time.Second):
			t.Fatal("capable node skipped its lease heartbeat after recovery")
		}
		deadline := time.Now().Add(time.Second)
		for s.pushActive.Load() {
			if time.Now().After(deadline) {
				t.Fatal("report did not finish")
			}
			time.Sleep(time.Millisecond)
		}
	}
}
