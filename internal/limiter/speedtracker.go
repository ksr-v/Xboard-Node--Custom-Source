package limiter

import (
	"sync"
	"sync/atomic"

	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/time/rate"
)

// SpeedTrackerLogCallback is called when bucket updates occur.
type SpeedTrackerLogCallback func(msg string)

// SpeedTracker manages per-user token-bucket rate limiters.
// It does NOT wrap connections itself — instead, ConnTracker consults it
// via GetLimiter to embed rate limiting in the same tracked connection
// wrapper that does byte counting.
type SpeedTracker struct {
	limiter *Limiter
	mu      sync.RWMutex
	buckets map[int]*rate.Limiter // userID → shared rate limiter
	uuidMap map[string]int        // UUID → userID

	// These describe configured limits, not the number of stable bucket handles.
	hasLimits    atomic.Bool
	limitedUsers int

	// Optional callback for logging
	logFunc SpeedTrackerLogCallback
}

// NewSpeedTracker creates a bucket manager for per-user bandwidth throttling.
func NewSpeedTracker(l *Limiter) *SpeedTracker {
	return &SpeedTracker{
		limiter: l,
		buckets: make(map[int]*rate.Limiter),
		uuidMap: make(map[string]int),
	}
}

// SetLogCallback sets the logging callback.
func (t *SpeedTracker) SetLogCallback(f SpeedTrackerLogCallback) {
	t.logFunc = f
}

// UpdateBuckets updates the UUID→userID mapping and syncs existing limiters.
func (t *SpeedTracker) UpdateBuckets() {
	currentUsers := make([]model.UserSpec, 0, 32)
	t.limiter.mu.RLock()
	for _, u := range t.limiter.users {
		currentUsers = append(currentUsers, u)
	}
	t.limiter.mu.RUnlock()

	func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		newUUIDMap := make(map[string]int, len(currentUsers))
		activeIDs := make(map[int]struct{}, len(currentUsers))

		limitedUsers := 0
		for _, user := range currentUsers {
			activeIDs[user.ID] = struct{}{}
			if user.UUID != "" {
				newUUIDMap[user.UUID] = user.ID
			}

			limit, burst := rate.Inf, 64*1024
			if user.SpeedLimit > 0 {
				bytesPerSec := user.SpeedLimit * 125_000
				limit = rate.Limit(bytesPerSec)
				burst = max(bytesPerSec, 64*1024)
				limitedUsers++
			}
			// Every known user gets a stable handle, including unlimited users.
			// Existing TCP/UDP streams keep this pointer across 0 <-> positive
			// updates instead of retaining nil or an obsolete finite bucket.
			if lim, ok := t.buckets[user.ID]; ok {
				lim.SetBurst(burst)
				lim.SetLimit(limit)
			} else {
				t.buckets[user.ID] = rate.NewLimiter(limit, burst)
			}
		}

		// Clean up buckets for removed users
		for id := range t.buckets {
			if _, ok := activeIDs[id]; !ok {
				delete(t.buckets, id)
			}
		}

		t.uuidMap = newUUIDMap
		t.limitedUsers = limitedUsers
		t.hasLimits.Store(limitedUsers > 0)
	}()

	if t.logFunc != nil {
		t.logFunc("buckets updated")
	}
}

// GetLimiter returns a stable handle for a known user, or nil for an unknown
// user. An unlimited user's handle uses rate.Inf so existing streams can be
// throttled as soon as their settings change.
// Thread-safe.
func (t *SpeedTracker) GetLimiter(user string) *rate.Limiter {
	t.mu.RLock()
	defer t.mu.RUnlock()
	uid, exists := t.uuidMap[user]
	if !exists {
		return nil
	}
	return t.buckets[uid]
}

// HasLimits returns true if any user currently has a speed limit configured.
func (t *SpeedTracker) HasLimits() bool {
	return t.hasLimits.Load()
}

// LimitedUserCount returns the number of users with active speed limits.
func (t *SpeedTracker) LimitedUserCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.limitedUsers
}
