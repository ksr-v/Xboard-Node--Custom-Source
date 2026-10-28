// Package deviceadmission combines per-node connection reference counts with
// an atomic panel reservation, so source IP limits apply across nodes.
package deviceadmission

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type Client interface {
	AcquireDevice(context.Context, string, string, string, int) error
	ReleaseDevice(context.Context, string, string, string) error
}

// RetainingClient is optional: older panels may support atomic admission but
// not know how to retire a token without removing an IP's remaining shadow.
type RetainingClient interface {
	SupportsRetainedDeviceRelease() bool
	ReleaseDeviceRetainingIP(context.Context, string, string, string) error
}

type key struct{ userUUID, ip string }

type entry struct {
	mu        sync.Mutex
	refs      int
	token     string
	failedAt  time.Time
	lastError error
	borrowers int // guarded by Manager.mu, including callers waiting on entry.mu
}

type Manager struct {
	mu          sync.Mutex
	entries     map[key]*entry
	client      Client
	interval    int
	hasSourceIP func(string, string) bool
}

func New(client Client, reportInterval int, presence ...func(string, string) bool) *Manager {
	if reportInterval < 5 {
		reportInterval = 5
	}
	m := &Manager{entries: make(map[key]*entry), client: client, interval: reportInterval}
	if len(presence) > 0 {
		m.hasSourceIP = presence[0]
	}
	return m
}

// Acquire runs an RPC only for the first concurrent connection at this node's
// user/IP pair. The returned callback must be called when that connection closes.
// Network I/O is serialized by entry.mu, never by the manager-wide map lock.
func (m *Manager) Acquire(userUUID, ip string) (func(), error) {
	k := key{userUUID: userUUID, ip: ip}
	e := m.borrow(k)
	e.mu.Lock()
	if e.refs == 0 {
		// Share a failed in-flight decision with connections already queued for
		// the same IP. Otherwise N simultaneous callers can each spend another
		// two seconds retrying an unavailable panel in serial.
		if e.lastError != nil && time.Since(e.failedAt) < 500*time.Millisecond {
			err := e.lastError
			e.mu.Unlock()
			m.unborrow(k, e)
			return nil, err
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			e.mu.Unlock()
			m.unborrow(k, e)
			return nil, errors.New("device admission token unavailable")
		}
		token := hex.EncodeToString(random[:])
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := m.client.AcquireDevice(ctx, userUUID, ip, token, m.interval)
		cancel()
		if err != nil {
			e.lastError, e.failedAt = err, time.Now()
			e.mu.Unlock()
			m.unborrow(k, e)
			return nil, err
		}
		e.lastError = nil
		e.token = token
	}
	e.refs++
	token := e.token
	e.mu.Unlock()
	m.unborrow(k, e)
	var once sync.Once
	return func() { once.Do(func() { m.release(k, e, token) }) }, nil
}

func (m *Manager) borrow(k key) *entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[k]
	if e == nil {
		e = &entry{}
		m.entries[k] = e
	}
	e.borrowers++
	return e
}

func (m *Manager) unborrow(k key, e *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.borrowers--
	// No writer can touch refs with zero borrowers. Deleting only at this
	// boundary prevents a waiting Acquire from using an orphaned entry.
	if e.borrowers == 0 && e.refs == 0 && m.entries[k] == e {
		delete(m.entries, k)
	}
}

func (m *Manager) release(k key, expected *entry, token string) {
	m.mu.Lock()
	e := m.entries[k]
	if e != expected {
		m.mu.Unlock()
		return
	}
	e.borrowers++
	m.mu.Unlock()
	e.mu.Lock()
	release := e.refs > 0 && e.token == token
	if release {
		e.refs--
		release = e.refs == 0
		if release {
			e.token = ""
		}
	}
	e.mu.Unlock()
	m.unborrow(k, e)
	if release {
		go func() {
			// Query after local accounting has retired this connection, outside
			// both Manager locks and the synchronous Close/Stop call chain. A
			// legacy unlimited connection may still use this same user/IP.
			retainIP := m.hasSourceIP != nil && m.hasSourceIP(k.userUUID, k.ip)
			releaseDevice := m.client.ReleaseDevice
			if retainIP {
				retaining, ok := m.client.(RetainingClient)
				if !ok || !retaining.SupportsRetainedDeviceRelease() {
					// An old v1 panel would ignore retain_ip and delete a live IP.
					// Keep its lease until a full snapshot/expiry can reconcile it.
					return
				}
				releaseDevice = retaining.ReleaseDeviceRetainingIP
			}
			// Retry the same generation only. This avoids holding a closed IP for
			// the whole lease after a single lost packet, while CAS at the panel
			// protects a new connection that arrived during the bounded retries.
			backoff := []time.Duration{0, 250 * time.Millisecond, time.Second}
			for _, delay := range backoff {
				if delay > 0 {
					time.Sleep(delay)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err := releaseDevice(ctx, k.userUUID, k.ip, token)
				cancel()
				if err == nil {
					return
				}
			}
		}()
	}
}
