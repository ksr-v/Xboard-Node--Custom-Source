package deviceadmission

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRetainingClient struct {
	*fakeClient
	supported bool
	retained  func(context.Context, string, string, string) error
}

func (f *fakeRetainingClient) SupportsRetainedDeviceRelease() bool { return f.supported }
func (f *fakeRetainingClient) ReleaseDeviceRetainingIP(ctx context.Context, uuid, ip, token string) error {
	return f.retained(ctx, uuid, ip, token)
}

func TestUnlimitedToLimitedCloseRetainsExistingSourceIP(t *testing.T) {
	var legacyConnections atomic.Int64
	legacyConnections.Store(1) // This pre-existing unlimited link has no Manager reference.
	fast, retained := make(chan struct{}, 1), make(chan string, 1)
	var acquired string
	client := &fakeRetainingClient{
		fakeClient: &fakeClient{
			acquire: func(_ context.Context, _, _, token string, _ int) error { acquired = token; return nil },
			release: func(context.Context, string, string, string) error { fast <- struct{}{}; return nil },
		},
		supported: true,
		retained:  func(_ context.Context, _, _, token string) error { retained <- token; return nil },
	}
	manager := New(client, 5, func(string, string) bool { return legacyConnections.Load() > 0 })
	shortConnection, err := manager.Acquire("user", "same-ip")
	if err != nil {
		t.Fatal(err)
	}
	shortConnection()
	select {
	case token := <-retained:
		if token != acquired {
			t.Fatal("retained release changed generation")
		}
	case <-time.After(time.Second):
		t.Fatal("live legacy IP did not retain its panel shadow")
	}
	if len(fast) != 0 {
		t.Fatal("short limited link removed a still-live unlimited IP")
	}
}

func TestNoRemainingSourceUsesNormalFastRelease(t *testing.T) {
	fast := make(chan struct{}, 1)
	client := &fakeRetainingClient{
		fakeClient: &fakeClient{
			acquire: func(context.Context, string, string, string, int) error { return nil },
			release: func(context.Context, string, string, string) error { fast <- struct{}{}; return nil },
		},
		supported: true,
		retained:  func(context.Context, string, string, string) error { t.Error("empty IP was retained"); return nil },
	}
	manager := New(client, 5, func(string, string) bool { return false })
	release, err := manager.Acquire("user", "ip")
	if err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-fast:
	case <-time.After(time.Second):
		t.Fatal("normal release lost its fast path")
	}
}

func TestPresenceProbeRunsOutsideManagerLocksAndCloseCall(t *testing.T) {
	probeStarted, kernelUnlocked := make(chan struct{}), make(chan struct{})
	retained := make(chan struct{}, 1)
	client := &fakeRetainingClient{
		fakeClient: &fakeClient{
			acquire: func(context.Context, string, string, string, int) error { return nil },
			release: func(context.Context, string, string, string) error { return nil },
		},
		supported: true,
		retained:  func(context.Context, string, string, string) error { retained <- struct{}{}; return nil },
	}
	var manager *Manager
	var oldEntry *entry
	manager = New(client, 5, func(string, string) bool {
		close(probeStarted)
		<-kernelUnlocked // Simulate Stop/Reload still owning the kernel's outer mutex.
		if !manager.mu.TryLock() {
			t.Error("probe ran under Manager map mutex")
		} else {
			manager.mu.Unlock()
		}
		if !oldEntry.mu.TryLock() {
			t.Error("probe ran under entry mutex")
		} else {
			oldEntry.mu.Unlock()
		}
		return true
	})
	release, err := manager.Acquire("user", "ip")
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	oldEntry = manager.entries[key{"user", "ip"}]
	manager.mu.Unlock()
	returned := make(chan struct{})
	go func() { release(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		close(kernelUnlocked)
		t.Fatal("Close blocked on the kernel presence probe")
	}
	<-probeStarted
	close(kernelUnlocked)
	select {
	case <-retained:
	case <-time.After(time.Second):
		t.Fatal("probe did not complete after the outer kernel mutex was released")
	}
}

func TestRetainingDecisionIsStableAcrossSameGenerationRetries(t *testing.T) {
	var probes, attempts atomic.Int64
	var legacy atomic.Bool
	legacy.Store(true)
	finished := make(chan struct{})
	client := &fakeRetainingClient{
		fakeClient: &fakeClient{
			acquire: func(context.Context, string, string, string, int) error { return nil },
			release: func(context.Context, string, string, string) error {
				t.Error("retain retry changed to destructive release")
				return nil
			},
		},
		supported: true,
		retained: func(context.Context, string, string, string) error {
			legacy.Store(false)
			if attempts.Add(1) < 2 {
				return errors.New("transient")
			}
			close(finished)
			return nil
		},
	}
	manager := New(client, 5, func(string, string) bool { probes.Add(1); return legacy.Load() })
	release, err := manager.Acquire("user", "ip")
	if err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("retained release did not retry")
	}
	if probes.Load() != 1 || attempts.Load() != 2 {
		t.Fatalf("probes=%d attempts=%d", probes.Load(), attempts.Load())
	}
}

func TestLegacyAdmissionPanelDoesNotDestructivelyReleaseLiveIP(t *testing.T) {
	probed := make(chan struct{})
	var released atomic.Int64
	client := &fakeClient{
		acquire: func(context.Context, string, string, string, int) error { return nil },
		release: func(context.Context, string, string, string) error { released.Add(1); return nil },
	}
	manager := New(client, 5, func(string, string) bool { close(probed); return true })
	release, err := manager.Acquire("user", "ip")
	if err != nil {
		t.Fatal(err)
	}
	release()
	<-probed
	// Unsupported peers are left to their complete snapshots/lease expiry.
	if released.Load() != 0 {
		t.Fatal("old panel was instructed to delete a live IP")
	}
}

func TestUnnegotiatedRetainingClientKeepsLiveIPLease(t *testing.T) {
	probed := make(chan struct{})
	released := make(chan struct{}, 1)
	client := &fakeRetainingClient{
		fakeClient: &fakeClient{
			acquire: func(context.Context, string, string, string, int) error { return nil },
			release: func(context.Context, string, string, string) error { released <- struct{}{}; return nil },
		},
		supported: false,
		retained:  func(context.Context, string, string, string) error { released <- struct{}{}; return nil },
	}
	manager := New(client, 5, func(string, string) bool { close(probed); return true })
	release, err := manager.Acquire("user", "ip")
	if err != nil {
		t.Fatal(err)
	}
	release()
	<-probed
	select {
	case <-released:
		t.Fatal("peer without retain capability was asked to release a live IP")
	case <-time.After(20 * time.Millisecond):
	}
}
