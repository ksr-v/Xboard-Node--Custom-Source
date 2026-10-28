package singbox

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestSourcePresenceRetainsLegacyUnlimitedFlowAfterLimitedClose(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	var limit atomic.Int64
	tracker.SetDeviceLimitFunc(func(string) (int, bool) { value := int(limit.Load()); return value, value > 0 })
	s := New(config.KernelConfig{})
	s.connTracker = tracker
	legacy := tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	if !s.HasUserSourceIP("uuid-1", "127.0.0.2") || s.HasUserSourceIP("uuid-1", "127.0.0.3") || s.HasUserSourceIP("unknown", "127.0.0.2") {
		t.Fatal("unlimited source presence is incorrect")
	}
	limit.Store(1)
	probes := make(chan bool, 1)
	tracker.SetDeviceAdmissionFunc(func(string, string) (func(), error) {
		return func() { go func() { probes <- s.HasUserSourceIP("uuid-1", "127.0.0.2") }() }, nil
	})
	limited := tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	_ = limited.Close()
	select {
	case retained := <-probes:
		if !retained {
			t.Fatal("closing short limited flow hid old unlimited flow")
		}
	case <-time.After(time.Second):
		t.Fatal("async release probe deadlocked")
	}
	_ = legacy.Close()
	if s.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("closed legacy flow remained present")
	}
}

func TestSourcePresenceAsyncReleaseWaitsForStopWithoutBlockingClose(t *testing.T) {
	tracker := admissionTracker()
	s := New(config.KernelConfig{})
	s.connTracker = tracker
	probes := make(chan bool, 1)
	tracker.SetDeviceAdmissionFunc(func(string, string) (func(), error) {
		return func() { go func() { probes <- s.HasUserSourceIP("uuid-1", "127.0.0.2") }() }, nil
	})
	conn := tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	closed := make(chan struct{})
	go func() { _ = conn.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close waited for a probe needing the Stop mutex")
	}
	select {
	case <-probes:
		t.Fatal("presence was read during lifecycle transition")
	default:
	}
	s.mu.Unlock()
	locked = false
	select {
	case present := <-probes:
		if present {
			t.Fatal("local accounting was not decremented before callback")
		}
	case <-time.After(time.Second):
		t.Fatal("probe did not resume after Stop mutex unlocked")
	}
}

func TestSourcePresenceIncludesDrainingTrackerAndCapturedIdentity(t *testing.T) {
	old := NewConnTracker(0)
	old.SetUserMap(map[string]int{"uuid-1": 1})
	legacy := old.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	s := New(config.KernelConfig{})
	s.connTracker = NewConnTracker(0)
	s.drainingTrackers = map[*ConnTracker]struct{}{old: {}}
	if !s.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("replacement hid an old draining source")
	}
	if _, ips, count, _ := s.GetUserTraffic(context.Background()); count != 1 || !ips[1]["127.0.0.2"] {
		t.Fatal("full snapshot disagreed with draining presence")
	}
	old.usersMu.Lock()
	old.uuidMap = map[string]int{}
	old.usersMu.Unlock()
	if !s.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("removed lookup hid captured old identity")
	}
	_ = s.CloseUserConnections(context.Background(), "uuid-1")
	_ = legacy.Close()
	if s.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("closed draining source remained present")
	}
	if _, ips, count, _ := s.GetUserTraffic(context.Background()); count != 0 || len(ips) != 0 {
		t.Fatal("closed draining source remained in snapshot")
	}
}

func TestSourcePresenceConcurrentCloseAndProbe(t *testing.T) {
	tracker := admissionTracker()
	s := New(config.KernelConfig{})
	s.connTracker = tracker
	conn := tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.HasUserSourceIP("uuid-1", "127.0.0.2")
			}
		}()
	}
	_ = conn.Close()
	wg.Wait()
	if s.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("closed source remained present")
	}
}
