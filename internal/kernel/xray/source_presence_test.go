package xray

import (
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestSourcePresenceRetainsLegacyUnlimitedFlowAfterLimitedClose(t *testing.T) {
	d := newTestDispatcher()
	users := []model.UserSpec{{ID: 1, UUID: "uuid-1"}}
	applyDispatcherLimits(d, users)
	x := New(config.KernelConfig{Type: "xray"})
	x.limitDispatcher = d
	legacy, _, _, _ := forceTrackedLink(t, d, 1, "127.0.0.2", nil, nil)
	if !x.HasUserSourceIP("uuid-1", "127.0.0.2") || x.HasUserSourceIP("uuid-1", "127.0.0.3") || x.HasUserSourceIP("unknown", "127.0.0.2") {
		t.Fatal("unlimited source presence is incorrect")
	}
	users[0].DeviceLimit = 1
	applyDispatcherLimits(d, users)
	probes := make(chan bool, 1)
	limited, _, _, _ := forceTrackedLink(t, d, 1, "127.0.0.2", nil, func() { go func() { probes <- x.HasUserSourceIP("uuid-1", "127.0.0.2") }() })
	limited.close()
	select {
	case retained := <-probes:
		if !retained {
			t.Fatal("short limited close hid original unlimited flow")
		}
	case <-time.After(time.Second):
		t.Fatal("async probe deadlocked")
	}
	legacy.close()
	if x.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("closed legacy flow remained present")
	}
}

func TestSourcePresenceWaitsForStopNilDispatcherWindow(t *testing.T) {
	d := limitedDispatcher()
	x := New(config.KernelConfig{Type: "xray"})
	x.limitDispatcher = d
	probes := make(chan bool, 1)
	active, _, _, _ := forceTrackedLink(t, d, 1, "127.0.0.2", nil, func() { go func() { probes <- x.HasUserSourceIP("uuid-1", "127.0.0.2") }() })
	x.lifecycleMu.Lock()
	locked := true
	defer func() {
		if locked {
			x.lifecycleMu.Unlock()
		}
	}()
	x.mu.Lock()
	x.limitDispatcher = nil
	x.mu.Unlock()
	closed := make(chan struct{})
	go func() { active.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("release callback blocked lifecycle shutdown")
	}
	select {
	case <-probes:
		t.Fatal("nil dispatcher was observed before old flows finished draining")
	default:
	}
	d.CloseAllLinks()
	x.lifecycleMu.Unlock()
	locked = false
	select {
	case present := <-probes:
		if present {
			t.Fatal("stopped dispatcher still reported a source")
		}
	case <-time.After(time.Second):
		t.Fatal("probe did not resume after Stop")
	}
}

func TestSourcePresenceUsesCapturedUUIDWhileLookupDrains(t *testing.T) {
	d := limitedDispatcher()
	active, _, _, _ := forceTrackedLink(t, d, 1, "127.0.0.2", nil, nil)
	d.mu.Lock()
	d.emailToUID = map[string]int{}
	d.mu.Unlock()
	if !d.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("removed identity lookup hid a draining connection")
	}
	active.close()
	if d.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("closed captured source remained present")
	}
}

func TestSourcePresenceConcurrentCloseAndProbe(t *testing.T) {
	d := limitedDispatcher()
	x := New(config.KernelConfig{Type: "xray"})
	x.limitDispatcher = d
	active, _, _, _ := forceTrackedLink(t, d, 1, "127.0.0.2", nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				x.HasUserSourceIP("uuid-1", "127.0.0.2")
			}
		}()
	}
	active.close()
	wg.Wait()
	if x.HasUserSourceIP("uuid-1", "127.0.0.2") {
		t.Fatal("closed source remained present")
	}
}
