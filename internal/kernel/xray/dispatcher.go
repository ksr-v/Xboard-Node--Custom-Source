package xray

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Access xray's internal config creator registry so we can replace the
// default dispatcher factory with ours. This runs AFTER xray's init()
// functions because our package imports xray (dependency order guarantee).
//
//go:linkname typeCreatorRegistry github.com/xtls/xray-core/common.typeCreatorRegistry
var typeCreatorRegistry map[reflect.Type]common.ConfigCreator

var origDispatcherFactory common.ConfigCreator

// Build tooling must apply the checksum-verified maintained core patch.
const _ = xrayDispatcher.NodeEndpointBandwidthRevision

// globalLimitDispatcher is set when the factory creates a LimitDispatcher.
// The Xray kernel reads it to configure limits and get connections.
var globalLimitDispatcher atomic.Pointer[LimitDispatcher]

func init() {
	configType := reflect.TypeOf((*xrayDispatcher.Config)(nil))
	origDispatcherFactory = typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = limitDispatcherFactory
}

func limitDispatcherFactory(ctx context.Context, config interface{}) (interface{}, error) {
	orig, err := origDispatcherFactory(ctx, config)
	if err != nil {
		return nil, err
	}
	inner, ok := orig.(routing.Dispatcher)
	if !ok {
		return orig, nil
	}
	ld := &LimitDispatcher{
		inner:      orig,
		innerDisp:  inner,
		limitedIPs: make(map[string]map[string]int),
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

// LimitDispatcher wraps xray's DefaultDispatcher to enforce per-user
// admission checks before a request is dispatched into xray-core.
//
// Xray's mux/XUDP close path requires the original concrete *pipe.Reader.
// The maintained reader terminal callback and a forwarding Writer observer
// provide lifecycle bookkeeping without replacing that Reader.
type LimitDispatcher struct {
	inner     interface{}        // original DefaultDispatcher (Feature + Dispatcher)
	innerDisp routing.Dispatcher // same object, typed as Dispatcher

	// All admitted users share one refcount table. Limit changes must not lose
	// connections that were admitted while the user was unlimited.
	mu                  sync.RWMutex
	limitedIPs          map[string]map[string]int // email → sourceIP → refcount
	deviceLimits        map[string]int            // email → max devices
	emailToUID          map[string]int            // email → panel user ID
	emailToUUID         map[string]string
	globalDevices       map[int]map[string]bool
	globalLastUpdate    time.Time
	deviceAdmissionFunc func(uuid, sourceIP string) (release func(), err error)
	activeLinks         map[uint64]*activeLink
	linkCounter         atomic.Uint64
	closing             atomic.Bool
	userCloseGeneration map[string]uint64

	connCount atomic.Int64 // total active connections tracked by dispatcher
}

// ─── routing.Dispatcher ──────────────────────────────────────────────────────

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	identity := d.identityFromContext(ctx)
	email, sourceIP, _, release, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return nil, err
	}

	if email == "" {
		return d.innerDisp.Dispatch(ctx, dest)
	}
	active, child := d.beginLink(ctx, email, sourceIP, release, identity)
	if active.closed.Load() {
		return nil, context.Canceled
	}
	link, err := d.innerDisp.Dispatch(child, dest)
	if err != nil {
		active.close()
		return nil, err
	}
	if !active.attach(link) {
		return nil, context.Canceled
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	identity := d.identityFromContext(ctx)
	email, sourceIP, _, release, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return err
	}

	if email == "" {
		return d.innerDisp.DispatchLink(ctx, dest, link)
	}
	active, child := d.beginLink(ctx, email, sourceIP, release, identity)
	if !active.attach(link) {
		return context.Canceled
	}
	defer active.close()
	return d.innerDisp.DispatchLink(child, dest, link)
}

// identifyAndCheck extracts user identity from the session context, enforces
// device limits, and returns the user's email, source IP, and TCP flag.
// Returns a non-nil error only when the connection should be rejected.
func (d *LimitDispatcher) identifyAndCheck(ctx context.Context, dest net.Destination) (email, sourceIP string, isTCP bool, release func(), err error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || len(si.User.Email) == 0 {
		return "", "", false, nil, nil
	}
	email = si.User.Email
	sourceIP = si.Source.Address.IP().String()
	isTCP = dest.Network == net.Network_TCP

	d.mu.RLock()
	limit := d.deviceLimits[email]
	admission := d.deviceAdmissionFunc
	uuid := d.emailToUUID[email]
	uid := d.emailToUID[email]
	d.mu.RUnlock()
	if uuid == "" {
		return "", "", false, nil, errors.New("device identity unavailable")
	}
	central := false
	if limit > 0 && admission != nil {
		if uuid == "" {
			return "", "", false, nil, errors.New("device admission identity unavailable")
		}
		release, err = admission(uuid, sourceIP)
		if err != nil {
			return "", "", false, nil, errors.New("device admission rejected")
		}
		central = true
	}
	if d.checkDeviceLimitWithGlobal(email, sourceIP, !central) {
		if release != nil {
			release()
		}
		nlog.Core().Debug("xray: device limit exceeded", "email", email, "ip", sourceIP)
		return "", "", false, nil, errors.New("device limit exceeded")
	}
	if uid > 0 {
		email = userEmail(uid)
	}
	return email, sourceIP, isTCP, release, nil
}

// ─── features.Feature (delegated) ───────────────────────────────────────────

func (d *LimitDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *LimitDispatcher) Start() error {
	if s, ok := d.inner.(interface{ Start() error }); ok {
		return s.Start()
	}
	return nil
}

func (d *LimitDispatcher) Close() error {
	d.closing.Store(true)
	d.CloseAllLinks()
	if c, ok := d.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// ─── Limit management (called by Xray kernel) ──────────────────────────────

func (d *LimitDispatcher) UpdateLimits(emailToUID map[string]int, deviceLimits, _ map[string]int) {
	d.mu.Lock()
	d.emailToUID = emailToUID
	d.deviceLimits = deviceLimits
	d.mu.Unlock()

}

func (d *LimitDispatcher) SetDeviceAdmissionFunc(fn func(uuid, sourceIP string) (release func(), err error)) {
	d.mu.Lock()
	d.deviceAdmissionFunc = fn
	d.mu.Unlock()
}

func (d *LimitDispatcher) SetUserUUIDs(users map[string]string) {
	d.mu.Lock()
	if d.userCloseGeneration == nil {
		d.userCloseGeneration = make(map[string]uint64)
	}
	for email, uuid := range d.emailToUUID {
		if users[email] != uuid {
			d.userCloseGeneration[uuid]++
		}
	}
	d.emailToUUID = users
	var removed []*activeLink
	for _, active := range d.activeLinks {
		if users[active.email] != active.uuid {
			removed = append(removed, active)
		}
	}
	d.mu.Unlock()
	for _, active := range removed {
		active.close(true)
	}
}

func (d *LimitDispatcher) UpdateGlobalDevices(users map[int][]string) {
	devices := make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		devices[uid] = make(map[string]bool, len(ips))
		for _, ip := range ips {
			devices[uid][ip] = true
		}
	}
	d.mu.Lock()
	d.globalDevices = devices
	d.globalLastUpdate = time.Now()
	d.mu.Unlock()
}

func (d *LimitDispatcher) ClearGlobalDevices() {
	d.mu.Lock()
	d.globalDevices = nil
	d.globalLastUpdate = time.Time{}
	d.mu.Unlock()
}

func (d *LimitDispatcher) ResetConns() {
	d.CloseAllLinks()
	d.mu.Lock()
	d.limitedIPs = make(map[string]map[string]int)
	d.mu.Unlock()

	d.connCount.Store(0)
}

// GetConnectionState returns dispatcher-tracked alive IPs and connection count.
// Traffic bytes are intentionally left to xray's built-in stats pipeline.
func (d *LimitDispatcher) GetConnectionState() (aliveIPs map[int]map[string]bool, connCount int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	emailToUID := d.emailToUID
	limitedIPs := d.limitedIPs

	aliveIPs = make(map[int]map[string]bool)

	// Collect IPs from limited users (under RLock snapshot).
	for email, ipsMap := range limitedIPs {
		uid := emailToUID[email]
		if uid == 0 {
			continue
		}
		ipSet := make(map[string]bool, len(ipsMap))
		for ip := range ipsMap {
			ipSet[ip] = true
		}
		if len(ipSet) > 0 {
			aliveIPs[uid] = ipSet
		}
	}

	connCount = int(d.connCount.Load())
	return
}

// HasUserSourceIP reads the shared admission table for both unlimited and
// limited flows. Normal identity lookups stay O(1).
func (d *LimitDispatcher) HasUserSourceIP(uuid, sourceIP string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if uid := d.emailToUID[uuid]; uid > 0 {
		return d.limitedIPs[userEmail(uid)][sourceIP] > 0
	}
	// Removed/rotated identities can still be draining under their original
	// captured UUID. Do not confuse a removed lookup with a closed transport.
	for _, active := range d.activeLinks {
		if active.uuid == uuid && active.sourceIP == sourceIP && d.limitedIPs[active.email][sourceIP] > 0 {
			return true
		}
	}
	return false
}

// ─── Internal helpers ───────────────────────────────────────────────────────

// checkDeviceLimit atomically checks and registers one TCP/UDP logical link.
func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string, _ bool) bool {
	return d.checkDeviceLimitWithGlobal(email, sourceIP, true)
}

func (d *LimitDispatcher) checkDeviceLimitWithGlobal(email, sourceIP string, useGlobal bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	limit := d.deviceLimits[email]
	uid := d.emailToUID[email]
	if uid > 0 {
		email = userEmail(uid)
	}
	ips := d.limitedIPs[email]
	if limit > 0 && ips[sourceIP] <= 0 {
		count := len(ips)
		global := d.globalDevices[uid]
		if useGlobal && time.Since(d.globalLastUpdate) <= 60*time.Second {
			if !global[sourceIP] {
				for ip := range global {
					if ips[ip] <= 0 {
						count++
					}
				}
				if count >= limit {
					return true
				}
			}
		} else if count >= limit {
			return true
		}
	}
	if ips == nil {
		ips = make(map[string]int)
		if d.limitedIPs == nil {
			d.limitedIPs = make(map[string]map[string]int)
		}
		d.limitedIPs[email] = ips
	}
	ips[sourceIP]++
	return false
}

// delConn decrements the same admission table regardless of later limit edits.
func (d *LimitDispatcher) delConn(email, sourceIP string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if uid := d.emailToUID[email]; uid > 0 {
		email = userEmail(uid)
	}
	if ips, ok := d.limitedIPs[email]; ok && ips[sourceIP] > 0 {
		ips[sourceIP]--
		if ips[sourceIP] <= 0 {
			delete(ips, sourceIP)
		}
		if len(ips) == 0 {
			delete(d.limitedIPs, email)
		}
	}
}
