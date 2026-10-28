package service

import (
	"context"
	"sync"
	"time"
)

// Admission protocol v1 guarantees panel leases of at least 60 seconds. Stop
// forwarding after 55 seconds without an acknowledged full report, leaving a
// five-second margin before another node can reclaim that global slot.
const deviceLeaseAcknowledgementWindow = 55 * time.Second

type deviceLeaseGuard struct {
	mu               sync.Mutex
	lastAcknowledged time.Time // retains Go's monotonic clock component
}

func newDeviceLeaseGuard(now time.Time) *deviceLeaseGuard {
	return &deviceLeaseGuard{lastAcknowledged: now}
}

func (g *deviceLeaseGuard) acknowledge(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.After(g.lastAcknowledged) {
		g.lastAcknowledged = now
	}
}

func (g *deviceLeaseGuard) expired(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return now.Sub(g.lastAcknowledged) >= deviceLeaseAcknowledgementWindow
}

func (s *Service) acknowledgeDeviceReportAt(now time.Time) {
	if s.deviceLeaseGuard != nil {
		s.deviceLeaseGuard.acknowledge(now)
	}
}

func (s *Service) enforceDeviceLeaseAt(ctx context.Context, now time.Time) {
	if s.deviceLeaseGuard == nil || !s.deviceLeaseGuard.expired(now) {
		return
	}
	online := s.tracker.CurrentOnline()
	var users []string
	s.metricsMu.RLock()
	for _, user := range s.lastUsers {
		if user.DeviceLimit > 0 && online[user.ID] > 0 {
			users = append(users, user.UUID)
		}
	}
	s.metricsMu.RUnlock()
	for _, userUUID := range users {
		// Closing the live connection invokes its generation-aware release.
		// No UUID or admission credential is written to logs on this path.
		_ = s.kernel.CloseUserConnections(ctx, userUUID)
	}
}
