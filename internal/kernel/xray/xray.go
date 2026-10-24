package xray

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	xrayCore "github.com/xtls/xray-core/core"
	featurebandwidth "github.com/xtls/xray-core/features/bandwidth"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	xrayProxy "github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"golang.org/x/time/rate"

	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/geodata"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

const (
	// drainTimeout is how long Stop waits for in-flight connections to finish
	// before hard-killing the instance. Skipped during hot-reload for speed.
	drainTimeout = 5 * time.Second
	// startTimeout caps how long instance.Start() may block.
	startTimeout = 30 * time.Second
)

// Xray implements kernel.Kernel by embedding xray-core as a Go library.
//
// Lifecycle:  Start  →  running  →  Stop / Reload
//
// Lock discipline:
//   - mu is held only for brief field swaps (microseconds).
//   - instance.Start() and instance.Close() run OUTSIDE the lock.
//   - running (atomic) gates fast-path checks in IsRunning / GetConnections.
type Xray struct {
	cfg         config.KernelConfig
	lifecycleMu sync.Mutex // serializes instance replacement and shutdown

	// mu protects instance, limitDispatcher, users, protocol, inboundTag,
	// lastKernelHash, and cumTraffic. Never held during slow I/O.
	mu              sync.Mutex
	instance        *xrayCore.Instance
	limitDispatcher *LimitDispatcher
	users           []model.UserSpec
	nodeConfig      *model.NodeSpec
	tls             kernel.TLSCert
	protocol        string
	inboundTag      string
	lastKernelHash  string
	cumTraffic      map[int][2]int64
	speedLimitFunc  func(string) *rate.Limiter
	instanceCancel  context.CancelFunc
	activeConfig    []byte
	activePolicy    []byte

	// running is set after a successful Start and cleared before shutdown.
	// Atomic so IsRunning / GetConnections never block.
	running atomic.Bool
}

func New(cfg config.KernelConfig) *Xray {
	return &Xray{
		cfg:        cfg,
		cumTraffic: make(map[int][2]int64),
	}
}

func (x *Xray) Name() string { return "xray" }

func (x *Xray) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  true,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       false,
	}
}

func (x *Xray) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria",
	}
}

// ─── Lifecycle ──────────────────────────────────────────────────────────────

// Start prepares a replacement before disturbing the running instance. Once
// validation succeeds, close old listeners and flows before starting the new
// instance on the same port. A startup error restores the last applied config.
// Only this embedded kernel changes; the node process and panel channel remain.
func (x *Xray) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	x.lifecycleMu.Lock()
	defer x.lifecycleMu.Unlock()
	return x.startLocked(nodeConfig, users, tls)
}

type preparedXray struct {
	instance   *xrayCore.Instance
	dispatcher *LimitDispatcher
	cancel     context.CancelFunc
}

func prepareXray(data []byte, users []model.UserSpec, fn func(string) *rate.Limiter) (*preparedXray, error) {
	pbConfig, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse xray config: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	xrayCreationMu.Lock()
	globalLimitDispatcher.Store(nil)
	inst, err := xrayCore.NewWithContext(ctx, pbConfig)
	ld := globalLimitDispatcher.Load()
	xrayCreationMu.Unlock()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create xray: %w", err)
	}
	applyDispatcherLimits(ld, users)
	applyBandwidthLimits(inst, fn, users)
	return &preparedXray{instance: inst, dispatcher: ld, cancel: cancel}, nil
}

func (p *preparedXray) close() {
	p.cancel()
	_ = p.instance.Close()
}

func xrayPolicy(data []byte) ([]byte, error) {
	var cfg M
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	delete(cfg, "inbounds")
	delete(cfg, "log")
	return json.Marshal(cfg)
}

// UserManager changes do not regenerate the full config. Refresh only the
// listener/user section in the saved config; do not read an edited custom file
// and accidentally roll back to a policy that was never actually applied.
func (x *Xray) rollbackConfigLocked() ([]byte, error) {
	if x.instance == nil {
		return nil, nil
	}
	if len(x.activeConfig) == 0 {
		return marshalConfig(x.cfg, x.nodeConfig, x.users, x.tls)
	}
	var cfg M
	if err := json.Unmarshal(x.activeConfig, &cfg); err != nil {
		return nil, err
	}
	if inb := buildInbound(x.nodeConfig, x.users, x.tls); inb != nil {
		cfg["inbounds"] = []M{inb}
	}
	return json.Marshal(cfg)
}

func (x *Xray) installPreparedLocked(p *preparedXray, data, policy []byte, nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) {
	x.instance = p.instance
	x.limitDispatcher = p.dispatcher
	x.instanceCancel = p.cancel
	x.users = users
	x.nodeConfig = nc
	x.tls = tls
	x.protocol = nc.Protocol
	x.inboundTag = nc.Protocol + "-in"
	x.lastKernelHash = kernel.ComputeHash(nc, users)
	x.activeConfig = append([]byte(nil), data...)
	x.activePolicy = append([]byte(nil), policy...)
	x.running.Store(true)
}

func (x *Xray) startLocked(nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	x.ensureGeoData(nc)
	data, err := marshalConfig(x.cfg, nc, users, tls)
	if err != nil {
		return err
	}
	policy, err := xrayPolicy(data)
	if err != nil {
		return fmt.Errorf("parse routing policy: %w", err)
	}
	x.mu.Lock()
	old, oldLD, oldCancel := x.instance, x.limitDispatcher, x.instanceCancel
	oldNC, oldUsers, oldTLS := x.nodeConfig, append([]model.UserSpec(nil), x.users...), x.tls
	oldPolicy := append([]byte(nil), x.activePolicy...)
	oldData, snapshotErr := x.rollbackConfigLocked()
	fn := x.speedLimitFunc
	x.mu.Unlock()
	if snapshotErr != nil {
		return fmt.Errorf("snapshot running xray: %w", snapshotErr)
	}
	candidate, err := prepareXray(data, users, fn)
	if err != nil {
		return fmt.Errorf("prepare xray reload (running configuration retained): %w", err)
	}
	if old != nil {
		x.mu.Lock()
		x.running.Store(false)
		_, _ = x.aggregateStats()
		x.mu.Unlock()
		// Root cancellation reaches idle proxy tasks too; closing only their
		// listeners leaves established streams using the previous route.
		if oldCancel != nil {
			oldCancel()
		}
		_ = old.Close()
		if oldLD != nil {
			drainConns(oldLD, time.Second)
		}
		x.mu.Lock()
		_, _ = x.aggregateStats()
		x.instance = nil
		x.limitDispatcher = nil
		x.instanceCancel = nil
		x.mu.Unlock()
	}
	if err = startWithTimeout(candidate.instance, startTimeout); err != nil {
		candidate.close()
		if old == nil {
			return err
		}
		previous, rollbackErr := prepareXray(oldData, oldUsers, fn)
		if rollbackErr == nil {
			rollbackErr = startWithTimeout(previous.instance, startTimeout)
			if rollbackErr == nil {
				x.mu.Lock()
				x.installPreparedLocked(previous, oldData, oldPolicy, oldNC, oldUsers, oldTLS)
				x.mu.Unlock()
			} else {
				previous.close()
			}
		}
		if rollbackErr != nil {
			return fmt.Errorf("xray reload failed: %v; restoring previous configuration also failed: %w", err, rollbackErr)
		}
		return fmt.Errorf("xray reload failed; previous configuration restored: %w", err)
	}
	x.mu.Lock()
	x.installPreparedLocked(candidate, data, policy, nc, users, tls)
	x.mu.Unlock()
	nlog.Core().Info("xray kernel configuration applied; previous flows closed", "users", len(users), "protocol", nc.Protocol)
	return nil
}

// Reload leaves the kernel and active connections in place for limit-only
// changes. Configuration/policy changes close old flows before replacing this
// kernel so established connections cannot bypass a new blocking rule.
func (x *Xray) Reload(nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	x.lifecycleMu.Lock()
	defer x.lifecycleMu.Unlock()
	data, err := marshalConfig(x.cfg, nc, users, tls)
	if err != nil {
		return err
	}
	policy, err := xrayPolicy(data)
	if err != nil {
		return err
	}
	newHash := kernel.ComputeHash(nc, users)
	x.mu.Lock()
	same := x.instance != nil && x.lastKernelHash == newHash && tlsEqual(x.tls, tls) && bytes.Equal(x.activePolicy, policy)
	if same {
		x.users = users
	}
	x.mu.Unlock()
	if same {
		x.updateDispatcherLimits(users)
		x.updateBandwidthLimits(users)
		return nil
	}
	return x.startLocked(nc, users, tls)
}

func (x *Xray) Stop() {
	x.lifecycleMu.Lock()
	defer x.lifecycleMu.Unlock()
	x.running.Store(false)
	x.mu.Lock()
	inst, ld, cancel := x.instance, x.limitDispatcher, x.instanceCancel
	x.instance = nil
	x.limitDispatcher = nil
	x.instanceCancel = nil
	x.mu.Unlock()
	if ld != nil {
		drainConns(ld, drainTimeout)
	}
	if cancel != nil {
		cancel()
	}
	if inst != nil {
		_ = inst.Close()
	}
}

func (x *Xray) IsRunning() bool { return x.running.Load() }

func tlsEqual(a, b kernel.TLSCert) bool {
	return bytes.Equal(a.CertPEM, b.CertPEM) && bytes.Equal(a.KeyPEM, b.KeyPEM)
}

// ─── Observability ──────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic from xray's built-in
// stats pipeline and connection state from the admission dispatcher when
// available. The dispatcher intentionally no longer wraps transport links,
// so traffic accounting must come from xray-core itself.
func (x *Xray) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	if !x.running.Load() {
		return nil, nil, 0, nil
	}

	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return nil, nil, 0, nil
	}
	ld := x.limitDispatcher
	traffic, err = x.aggregateStats()
	x.mu.Unlock()
	if err != nil {
		return nil, nil, 0, err
	}

	if ld != nil {
		aliveIPs, connCount = ld.GetConnectionState()
	}
	return traffic, aliveIPs, connCount, nil
}

func (x *Xray) CloseConnection(_ context.Context, _ string) error {
	// No-op: xray doesn't support force-closing individual connections.
	// User removal goes through RemoveUsers which removes the inbound user.
	return nil
}

func (x *Xray) CloseUserConnections(_ context.Context, _ string) error {
	// No-op: handled by RemoveUsers at the xray core level.
	return nil
}

// SetSpeedLimitFunc wires xray's patched bandwidth feature to the shared
// per-user limiter callback used by the service layer. Unlike the old no-op
// behavior, xray now consumes this callback to support dynamic speed updates.
func (x *Xray) SetSpeedLimitFunc(fn func(string) *rate.Limiter) {
	x.mu.Lock()
	x.speedLimitFunc = fn
	x.mu.Unlock()
	x.updateBandwidthLimits(nil)
}

// SetDeviceLimitFunc is a no-op for xray — device limits are already
// gate-kept by LimitDispatcher.checkDeviceLimit at Dispatch time.
func (x *Xray) SetDeviceLimitFunc(_ func(string) (int, bool)) {}

// UpdateGlobalDevices is a no-op for xray — xray handles device limits differently.
func (x *Xray) UpdateGlobalDevices(_ map[int][]string) {}

// ClearGlobalDevices is a no-op for xray.
func (x *Xray) ClearGlobalDevices() {}

// ─── User management (non-disruptive where possible) ────────────────────────

// AddUsers adds new users to the running kernel via xray's UserManager API.
// For protocols that support UserManager (vmess, vless, trojan, shadowsocks),
// this is truly hitless — no restart, no connection disruption.
// For unsupported protocols (socks, http), falls back to full restart.
//
// Delta "add" events also carry property updates (speed/device limits) for
// existing users, so this method always merges properties and refreshes the
// dispatcher limits — even when no brand-new users need to be added.
func (x *Xray) AddUsers(users []model.UserSpec) (int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, fmt.Errorf("not running")
	}

	// Merge: overwrite existing users' properties, collect truly new ones.
	userMap := make(map[int]model.UserSpec, len(x.users))
	for _, u := range x.users {
		userMap[u.ID] = u
	}
	var toAdd []model.UserSpec
	for _, u := range users {
		if _, exists := userMap[u.ID]; !exists {
			toAdd = append(toAdd, u)
		}
		userMap[u.ID] = u // always overwrite properties
	}
	merged := make([]model.UserSpec, 0, len(userMap))
	for _, u := range userMap {
		merged = append(merged, u)
	}

	if len(toAdd) == 0 {
		// No new kernel users, but properties (limits) may have changed.
		x.users = merged
		x.lastKernelHash = kernel.ComputeHash(x.nodeConfig, merged)
		x.mu.Unlock()
		x.updateDispatcherLimits(merged)
		x.updateBandwidthLimits(merged)
		return 0, nil
	}

	um, err := x.getUserManager()
	if err != nil {
		// Protocol doesn't support UserManager → full restart
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: AddUsers fallback to restart", "reason", err)
		if err := x.Start(nc, merged, t); err != nil {
			return 0, err
		}
		return len(toAdd), nil
	}

	proto := x.protocol
	nc := x.nodeConfig
	x.mu.Unlock()

	ctx := context.Background()
	added := 0
	for _, u := range toAdd {
		mu, err := toMemoryUser(proto, nc, u)
		if err != nil {
			nlog.Core().Warn("xray: skip user, cannot build account", "user", u.ID, "error", err)
			continue
		}
		if err := um.AddUser(ctx, mu); err != nil {
			nlog.Core().Warn("xray: AddUser failed", "user", u.ID, "error", err)
			continue
		}
		added++
	}

	// Update bookkeeping with full merged list (new users + updated properties).
	x.mu.Lock()
	x.users = merged
	x.lastKernelHash = kernel.ComputeHash(x.nodeConfig, merged)
	x.mu.Unlock()
	x.updateDispatcherLimits(merged)
	x.updateBandwidthLimits(merged)

	nlog.Core().Info("xray: users added via UserManager", "added", added, "total", len(merged))
	return added, nil
}

// RemoveUsers removes users from the running kernel via xray's UserManager API.
// Truly hitless for supported protocols — remaining connections unaffected.
func (x *Xray) RemoveUsers(users []model.UserSpec) (int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, fmt.Errorf("not running")
	}
	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []model.UserSpec
	removed := 0
	for _, u := range x.users {
		if _, rm := removeSet[u.ID]; rm {
			removed++
		} else {
			kept = append(kept, u)
		}
	}
	if removed == 0 {
		x.mu.Unlock()
		return 0, nil
	}

	if len(kept) == 0 {
		x.mu.Unlock()
		x.Stop()
		return removed, nil
	}

	um, err := x.getUserManager()
	if err != nil {
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: RemoveUsers fallback to restart", "reason", err)
		if err := x.Start(nc, kept, t); err != nil {
			return 0, err
		}
		return removed, nil
	}
	x.mu.Unlock()

	ctx := context.Background()
	actualRemoved := 0
	for _, u := range users {
		email := userEmail(u.ID)
		if err := um.RemoveUser(ctx, email); err != nil {
			nlog.Core().Debug("xray: RemoveUser skipped", "user", u.ID, "error", err)
			continue
		}
		actualRemoved++
	}

	x.mu.Lock()
	x.users = kept
	x.lastKernelHash = kernel.ComputeHash(x.nodeConfig, kept)
	x.mu.Unlock()
	x.updateDispatcherLimits(kept)
	x.updateBandwidthLimits(kept)

	nlog.Core().Info("xray: users removed via UserManager", "removed", actualRemoved, "total", len(kept))
	return actualRemoved, nil
}

// UpdateUsers replaces the entire user set. If only speed/device limits
// changed, updates the dispatcher without restarting. Otherwise uses
// UserManager for hitless add/remove where supported.
func (x *Xray) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, 0, fmt.Errorf("not running")
	}
	toAdd, toRemove := kernel.UserDiff(x.users, users)
	added, removed = len(toAdd), len(toRemove)

	if added == 0 && removed == 0 {
		// Only limits changed — update dispatcher without restart.
		x.users = users
		x.lastKernelHash = kernel.ComputeHash(x.nodeConfig, users)
		x.mu.Unlock()
		x.updateDispatcherLimits(users)
		x.updateBandwidthLimits(users)
		nlog.Core().Info("xray: limits updated, kernel unchanged")
		return 0, 0, nil
	}

	um, umErr := x.getUserManager()
	if umErr != nil {
		// Protocol doesn't support UserManager → full restart
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: UpdateUsers fallback to restart", "reason", umErr)
		if err = x.Start(nc, users, t); err != nil {
			return 0, 0, err
		}
		return
	}

	proto := x.protocol
	nc := x.nodeConfig
	x.mu.Unlock()

	ctx := context.Background()

	// Remove first, then add (order matters for UUID changes on same ID)
	for _, u := range toRemove {
		email := userEmail(u.ID)
		if err := um.RemoveUser(ctx, email); err != nil {
			nlog.Core().Debug("xray: RemoveUser skipped in UpdateUsers", "user", u.ID, "error", err)
		}
	}
	for _, u := range toAdd {
		mu, err := toMemoryUser(proto, nc, u)
		if err != nil {
			nlog.Core().Warn("xray: skip user in UpdateUsers", "user", u.ID, "error", err)
			continue
		}
		if err := um.AddUser(ctx, mu); err != nil {
			nlog.Core().Warn("xray: AddUser failed in UpdateUsers", "user", u.ID, "error", err)
		}
	}

	x.mu.Lock()
	x.users = users
	x.lastKernelHash = kernel.ComputeHash(x.nodeConfig, users)
	x.mu.Unlock()
	x.updateDispatcherLimits(users)
	x.updateBandwidthLimits(users)

	nlog.Core().Info("xray: users updated via UserManager", "added", added, "removed", removed, "total", len(users))
	return
}

var _ kernel.Kernel = (*Xray)(nil)

// ─── Internal helpers ───────────────────────────────────────────────────────

// getUserManager extracts the UserManager from the running xray instance's
// inbound handler. Must be called with x.mu held.
// Returns error for protocols that don't support UserManager (socks, http).
func (x *Xray) getUserManager() (xrayProxy.UserManager, error) {
	if x.instance == nil {
		return nil, fmt.Errorf("instance is nil")
	}

	im := x.instance.GetFeature(inbound.ManagerType())
	if im == nil {
		return nil, fmt.Errorf("inbound manager not available")
	}
	inboundMgr, ok := im.(inbound.Manager)
	if !ok {
		return nil, fmt.Errorf("inbound manager type assertion failed")
	}

	handler, err := inboundMgr.GetHandler(context.Background(), x.inboundTag)
	if err != nil {
		return nil, fmt.Errorf("get handler %q: %w", x.inboundTag, err)
	}

	gi, ok := handler.(xrayProxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler does not implement GetInbound")
	}

	um, ok := gi.GetInbound().(xrayProxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("protocol %q does not support UserManager", x.protocol)
	}

	return um, nil
}

// toMemoryUser converts a model.UserSpec into an xray protocol.MemoryUser for the
// given protocol. Each protocol needs a different Account type.
func toMemoryUser(proto string, nc *model.NodeSpec, u model.UserSpec) (*protocol.MemoryUser, error) {
	email := userEmail(u.ID)
	mu := &protocol.MemoryUser{Email: email, Level: 0}

	switch proto {
	case "vmess":
		id, err := uuid.ParseString(u.UUID)
		if err != nil {
			return nil, fmt.Errorf("parse vmess UUID: %w", err)
		}
		mu.Account = &vmess.MemoryAccount{
			ID:       protocol.NewID(id),
			Security: protocol.SecurityType_AUTO,
		}

	case "vless":
		id, err := uuid.ParseString(u.UUID)
		if err != nil {
			return nil, fmt.Errorf("parse vless UUID: %w", err)
		}
		account := &vless.MemoryAccount{
			ID:         protocol.NewID(id),
			Encryption: "none",
		}
		if nc.Flow != "" {
			account.Flow = nc.Flow
		}
		mu.Account = account

	case "trojan":
		mu.Account = &trojan.MemoryAccount{
			Password: u.UUID,
			Key:      trojanHexSha224(u.UUID),
		}

	case "shadowsocks":
		if strings.HasPrefix(nc.Cipher, "2022-blake3-") {
			// 2022-blake3 multi-user mode
			mu.Account = &ss2022.MemoryAccount{Key: u.UUID}
		} else {
			// Traditional SS — build via getCipher path
			ct := parseCipherType(nc.Cipher)
			cipherObj, err := (&shadowsocks.Account{CipherType: ct, Password: u.UUID}).AsAccount()
			if err != nil {
				return nil, fmt.Errorf("build ss account: %w", err)
			}
			mu.Account = cipherObj
		}

	default:
		return nil, fmt.Errorf("protocol %q does not support MemoryUser", proto)
	}

	return mu, nil
}

// parseCipherType maps a cipher name string to the xray CipherType enum.
func parseCipherType(cipher string) shadowsocks.CipherType {
	switch cipher {
	case "aes-128-gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-ietf-poly1305", "xchacha20-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_AES_256_GCM
	}
}

// trojanHexSha224 computes the SHA-224 hex key used by trojan protocol.
func trojanHexSha224(password string) []byte {
	// Replicates the exact logic from xray-core/proxy/trojan/config.go hexSha224
	h := sha256.New224()
	h.Write([]byte(password))
	buf := make([]byte, 56)
	hexEncode(buf, h.Sum(nil))
	return buf
}

// hexEncode is a minimal hex encoder (avoids importing encoding/hex).
func hexEncode(dst, src []byte) {
	const hextable = "0123456789abcdef"
	for i, v := range src {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
}

// ensureGeoData downloads geo databases when routes reference geoip/geosite.
func (x *Xray) ensureGeoData(nc *model.NodeSpec) {
	needIP, needSite := kernel.NeedsGeoIP(nc.Routes), kernel.NeedsGeoSite(nc.Routes)
	if !needIP && !needSite {
		return
	}
	dir := x.cfg.GeoDataDir
	if err := geodata.Ensure(dir, needIP, needSite, "xray"); err != nil {
		nlog.Core().Warn("geo database unavailable", "error", err)
	}
	os.Setenv("XRAY_LOCATION_ASSET", dir)
}

// marshalConfig builds the xray JSON config and returns the raw bytes.
func marshalConfig(cfg config.KernelConfig, nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) ([]byte, error) {
	cfgMap := buildConfig(cfg, nc, users, tls)
	data, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	nlog.Core().Debug("xray config generated", "len", len(data))
	return data, nil
}

// startWithTimeout runs instance.Start() with a bounded deadline.
func startWithTimeout(inst *xrayCore.Instance, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- inst.Start() }()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("start xray: %w", err)
		}
		return nil
	case <-time.After(timeout):
		go inst.Close()
		return fmt.Errorf("start xray: timeout after %v", timeout)
	}
}

// drainConns waits up to timeout for the dispatcher's active connections to
// reach zero. During replacement cancellation happens first, so the bounded
// wait only collects final counters instead of allowing old routes to drain.
func drainConns(ld *LimitDispatcher, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ld.connCount.Load() == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// aggregateStats is a fallback path that reads xray's built-in stats counters
// when LimitDispatcher is not available. Returns per-user cumulative traffic.
// Must be called with x.mu held.
func (x *Xray) aggregateStats() (map[int][2]int64, error) {
	sm := x.instance.GetFeature(stats.ManagerType())
	if sm == nil {
		return nil, nil
	}
	mgr, ok := sm.(stats.Manager)
	if !ok {
		return nil, nil
	}

	traffic := make(map[int][2]int64)
	for _, u := range x.users {
		email := userEmail(u.ID)

		var dUp, dDown int64
		if c := mgr.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>uplink", email)); c != nil {
			dUp = c.Set(0)
		}
		if c := mgr.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>downlink", email)); c != nil {
			dDown = c.Set(0)
		}

		if dUp > 0 || dDown > 0 {
			cum := x.cumTraffic[u.ID]
			cum[0] += dUp
			cum[1] += dDown
			x.cumTraffic[u.ID] = cum
		}

		if cum := x.cumTraffic[u.ID]; cum[0] > 0 || cum[1] > 0 {
			traffic[u.ID] = cum
		}
	}
	return traffic, nil
}

// updateBandwidthLimits configures the patched xray-core bandwidth feature
// with per-user speed limits in bytes per second.
func (x *Xray) updateBandwidthLimits(users []model.UserSpec) {
	x.mu.Lock()
	inst := x.instance
	fn := x.speedLimitFunc
	currentUsers := x.users
	x.mu.Unlock()
	if users == nil {
		users = currentUsers
	}
	applyBandwidthLimits(inst, fn, users)
}

func applyBandwidthLimits(inst *xrayCore.Instance, fn func(string) *rate.Limiter, users []model.UserSpec) {
	if inst == nil {
		return
	}
	feat := inst.GetFeature(featurebandwidth.ManagerType())
	if feat == nil {
		return
	}
	bm, ok := feat.(featurebandwidth.Manager)
	if !ok {
		return
	}
	bm.Reset()
	for _, u := range users {
		email := userEmail(u.ID)
		if fn != nil {
			lim := fn(u.UUID)
			bm.SetUserLimiter(email, lim)
			bm.SetUserLimiter(u.UUID, lim)
			continue
		}
		bps := int64(u.SpeedLimit) * 1_000_000 / 8
		bm.SetUserLimit(email, bps)
		bm.SetUserLimit(u.UUID, bps)
	}
}

// updateDispatcherLimits configures the LimitDispatcher with per-user
// device-limit admission metadata only. Speed limits are enforced by the
// patched xray-core bandwidth feature.
func (x *Xray) updateDispatcherLimits(users []model.UserSpec) {
	x.mu.Lock()
	ld := x.limitDispatcher
	x.mu.Unlock()
	applyDispatcherLimits(ld, users)
}

func applyDispatcherLimits(ld *LimitDispatcher, users []model.UserSpec) {
	if ld == nil {
		return
	}

	emailToUID := make(map[string]int, len(users)*2)
	deviceLimits := make(map[string]int)

	for _, u := range users {
		email := userEmail(u.ID)
		emailToUID[email] = u.ID
		emailToUID[u.UUID] = u.ID
		if u.DeviceLimit > 0 {
			deviceLimits[email] = u.DeviceLimit
			deviceLimits[u.UUID] = u.DeviceLimit
		}
	}

	ld.UpdateLimits(emailToUID, deviceLimits, nil)
}

// xrayCreationMu serialises xrayCore.New() + globalLimitDispatcher capture
// so that concurrent Xray instances in multi-node mode each capture their
// own LimitDispatcher.
var xrayCreationMu sync.Mutex
