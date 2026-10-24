package limiter

import (
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/time/rate"
)

func TestSpeedTracker_UpdateBuckets(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)

	users := []model.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 3, DeviceLimit: 0},  // 3 Mbps
		{ID: 2, UUID: "u2", SpeedLimit: 0, DeviceLimit: 0},  // unlimited
		{ID: 3, UUID: "u3", SpeedLimit: 10, DeviceLimit: 2}, // 10 Mbps
	}
	l.UpdateUsers(users)
	st.UpdateBuckets()

	// User 1: 3 Mbps = 375000 bytes/sec
	b1 := st.GetLimiter("u1")
	if b1 == nil {
		t.Fatal("expected bucket for user 1")
	}
	expectedRate := float64(3 * 1000000 / 8)
	if float64(b1.Limit()) != expectedRate {
		t.Errorf("user 1 rate: got %v, want %v", float64(b1.Limit()), expectedRate)
	}
	// Burst should be max(bytesPerSec, 64KB) = max(375000, 65536) = 375000
	expectedBurst := 3 * 1000000 / 8
	if b1.Burst() != expectedBurst {
		t.Errorf("user 1 burst: got %v, want %v", b1.Burst(), expectedBurst)
	}

	// Unlimited users retain a handle so existing streams can be limited later.
	b2 := st.GetLimiter("u2")
	if b2 == nil || b2.Limit() != rate.Inf {
		t.Fatal("expected unlimited bucket for user 2")
	}
	if !st.HasLimits() || st.LimitedUserCount() != 2 {
		t.Fatal("configured limit counts must exclude unlimited handles")
	}

	// User 3: 10 Mbps = 1250000 bytes/sec
	b3 := st.GetLimiter("u3")
	if b3 == nil {
		t.Fatal("expected bucket for user 3")
	}
	expectedRate3 := float64(10 * 1000000 / 8)
	if float64(b3.Limit()) != expectedRate3 {
		t.Errorf("user 3 rate: got %v, want %v", float64(b3.Limit()), expectedRate3)
	}
	// Burst should be max(1250000, 64KB) = 1250000
	expectedBurst3 := 10 * 1000000 / 8
	if b3.Burst() != expectedBurst3 {
		t.Errorf("user 3 burst: got %v, want %v", b3.Burst(), expectedBurst3)
	}
}

func TestSpeedTrackerExistingHandleSurvivesEnableAndDisable(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)
	update := func(speed int) {
		l.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "u1", SpeedLimit: speed}})
		st.UpdateBuckets()
	}
	update(0)
	existing := st.GetLimiter("u1")
	if existing == nil || existing.Limit() != rate.Inf || st.HasLimits() || st.LimitedUserCount() != 0 {
		t.Fatal("unlimited user's stable handle/count is incorrect")
	}
	for _, speed := range []int{8, 16, 0, 8, 0} {
		update(speed)
		if st.GetLimiter("u1") != existing {
			t.Fatal("changing speed replaced a handle cached by an existing stream")
		}
		if speed == 0 {
			if existing.Limit() != rate.Inf || st.HasLimits() || st.LimitedUserCount() != 0 {
				t.Fatal("disabling speed must update existing handle and configured counts")
			}
		} else if existing.Limit() != rate.Limit(speed*125_000) || !st.HasLimits() || st.LimitedUserCount() != 1 {
			t.Fatal("enabling speed must update existing handle and configured counts")
		}
	}
}

func TestSpeedTrackerConcurrentLookupAndUpdates(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)
	l.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "u1"}})
	st.UpdateBuckets()
	existing := st.GetLimiter("u1")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if st.GetLimiter("u1") != existing {
					t.Error("lookup lost stable handle")
				}
				_ = existing.Limit()
				_ = existing.Burst()
				_ = st.HasLimits()
				_ = st.LimitedUserCount()
			}
		}()
	}
	for i := range 200 {
		l.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "u1", SpeedLimit: (i % 3) * 8}})
		st.UpdateBuckets()
	}
	wg.Wait()
}

func TestSpeedTracker_UpdateBuckets_PreservesExisting(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)

	users := []model.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 3, DeviceLimit: 0},
	}
	l.UpdateUsers(users)
	st.UpdateBuckets()

	b1 := st.GetLimiter("u1")
	if b1 == nil {
		t.Fatal("expected bucket for user 1")
	}

	// Update same user with different speed — should reuse same *rate.Limiter pointer
	users2 := []model.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 5, DeviceLimit: 0},
	}
	l.UpdateUsers(users2)
	st.UpdateBuckets()

	b1After := st.GetLimiter("u1")
	if b1After == nil {
		t.Fatal("expected bucket for user 1 after update")
	}
	if b1 != b1After {
		t.Error("expected same rate.Limiter instance to be reused")
	}

	// Rate should be updated
	expectedRate := float64(5 * 1000000 / 8)
	if float64(b1After.Limit()) != expectedRate {
		t.Errorf("user 1 updated rate: got %v, want %v", float64(b1After.Limit()), expectedRate)
	}
}

func TestSpeedTracker_UpdateBuckets_RemovesUsers(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)

	users := []model.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 3, DeviceLimit: 0},
		{ID: 2, UUID: "u2", SpeedLimit: 5, DeviceLimit: 0},
	}
	l.UpdateUsers(users)
	st.UpdateBuckets()

	if st.GetLimiter("u1") == nil || st.GetLimiter("u2") == nil {
		t.Fatal("expected buckets for both users")
	}

	// Remove user 2
	users2 := []model.UserSpec{
		{ID: 1, UUID: "u1", SpeedLimit: 3, DeviceLimit: 0},
	}
	l.UpdateUsers(users2)
	st.UpdateBuckets()

	if st.GetLimiter("u1") == nil {
		t.Fatal("expected bucket for user 1")
	}
	if st.GetLimiter("u2") != nil {
		t.Error("expected no bucket for removed user 2")
	}
}

// Regression: log callback must not run while UpdateBuckets holds t.mu.Lock,
// otherwise callbacks that call LimitedUserCount() self-deadlock on RWMutex.
func TestSpeedTracker_UpdateBuckets_LogCallbackMayCallLimitedUserCount(t *testing.T) {
	l := New()
	st := NewSpeedTracker(l)
	l.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "u1", SpeedLimit: 1}})
	st.SetLogCallback(func(msg string) {
		_ = st.LimitedUserCount()
	})

	done := make(chan struct{})
	go func() {
		st.UpdateBuckets()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock: UpdateBuckets did not finish (log callback vs RWMutex)")
	}
}
