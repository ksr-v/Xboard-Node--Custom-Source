package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// drainTimeout is how long stop() waits for in-flight connections to finish
// naturally after closing all listen sockets, before hard-killing them.
const drainTimeout = 5 * time.Second

// SingBox implements kernel.Kernel by embedding sing-box as a Go library.
//
// Speed/device limit updates keep listeners and existing connections running.
// Identity changes replace the embedded kernel: the frozen dependency's native
// UpdateUsers methods mutate authentication state without synchronization.
type SingBox struct {
	cfg config.KernelConfig

	mu     sync.RWMutex
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc

	users      []model.UserSpec
	nodeConfig *model.NodeSpec
	tls        kernel.TLSCert

	// The last successfully applied generated configuration is also the rollback
	// source. Keep its compiled policy separately: rebuilding from a mutable
	// local custom-config file would lose the actual running policy on failure.
	activeConfig []byte
	activePolicy []byte

	// connTracker is our lightweight in-process byte/IP tracker.
	// Created fresh on every Start (full restart).
	// Survives Reload for cumulative accounting. Policy/listener/identity
	// changes close old flows; limit-only changes preserve them.
	connTracker *ConnTracker

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	// Set once by SetSpeedLimitFunc and forwarded to every new ConnTracker.
	speedLimitFunc func(string) *rate.Limiter

	// deviceLimitFunc resolves a user UUID to (limit, hasLimit) for gate-keeping.
	// Set once by SetDeviceLimitFunc and forwarded to every new ConnTracker.
	deviceLimitFunc func(string) (int, bool)

	// trackerRegistered prevents duplicate AppendTracker calls on the same
	// Router instance during Reload. Reset to false on full restart.
	trackerRegistered bool
}

func New(cfg config.KernelConfig) *SingBox {
	return &SingBox{cfg: cfg}
}

var _ kernel.Kernel = (*SingBox)(nil)

func (s *SingBox) Name() string { return "sing-box" }

func (s *SingBox) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  false,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       true,
	}
}

func (s *SingBox) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria", "hysteria2", "tuic", "naive", "socks", "http", "anytls", "mieru",
	}
}

func (s *SingBox) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	nlog.Core().Debug("sing-box config generated", "len", len(data))

	ctx, cancel := context.WithCancel(context.Background())
	ctx = include.Context(ctx)

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		cancel()
		return fmt.Errorf("parse sing-box options: %w", err)
	}

	// Save old state before creating the new instance.
	oldBox := s.box
	oldCancel := s.cancel
	oldCtx := s.ctx
	oldTracker := s.connTracker

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("create sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		return fmt.Errorf("start sing-box: %w", err)
	}

	// New instance started successfully — swap state.
	s.box = instance
	s.ctx = ctx
	s.cancel = cancel
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	s.activeConfig = append([]byte(nil), data...)
	s.activePolicy, _ = compiledPolicy(cfgMap)

	// Fresh tracker on full restart.
	s.connTracker = NewConnTracker(0)
	s.connTracker.SetUserMap(buildUserMap(users))
	if s.speedLimitFunc != nil {
		s.connTracker.SetSpeedLimitFunc(s.speedLimitFunc)
	}
	if s.deviceLimitFunc != nil {
		s.connTracker.SetDeviceLimitFunc(s.deviceLimitFunc)
	}

	s.trackerRegistered = false
	s.registerTracker(ctx)

	// Recycle old instance in background — drain then close.
	if oldBox != nil {
		go recycleOldBox(oldBox, oldCancel, oldCtx, oldTracker)
	}

	nlog.Core().Debug("sing-box started", "users", len(users))
	return nil
}

// recycleOldBox gracefully shuts down a previous sing-box instance in the
// background. It closes listen sockets first, waits for connections to drain,
// then hard-closes. This avoids blocking the new instance's startup.
func recycleOldBox(oldBox *box.Box, oldCancel context.CancelFunc, oldCtx context.Context, oldTracker *ConnTracker) {
	// Step 1: close listen sockets so no new connections arrive on old ports.
	if im := service.FromContext[adapter.InboundManager](oldCtx); im != nil {
		_ = im.Close()
	}

	// Step 2: drain in-flight connections (best-effort).
	if oldTracker != nil {
		deadline := time.Now().Add(drainTimeout)
		for time.Now().Before(deadline) {
			if oldTracker.ActiveCount() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Step 3: hard-close everything.
	oldBox.Close()
	if oldCancel != nil {
		oldCancel()
	}
	nlog.Core().Debug("sing-box: old instance recycled")
}

// Reload updates users in place when listeners and policy are unchanged.
// Other configuration changes replace only this embedded kernel, with a saved
// rollback configuration if the new listener or outbound cannot start.
// The Go process, panel connection, and cumulative traffic tracker stay alive.
func (s *SingBox) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return fmt.Errorf("not running")
	}

	tlsChanged := !bytes.Equal(s.tls.CertPEM, tls.CertPEM) || !bytes.Equal(s.tls.KeyPEM, tls.KeyPEM)
	configChanged := tlsChanged || s.nodeConfig == nil || kernel.ComputeHash(nodeConfig, nil) != kernel.ComputeHash(s.nodeConfig, nil)
	if !configChanged {
		// A user event must not also apply an edited local policy file. User
		// identity candidates below preserve all accepted non-inbound sections.
		if err := s.reloadInboundsLocked(users); err != nil {
			return err
		}
		s.users, s.nodeConfig, s.tls = users, nodeConfig, tls
		return nil
	}

	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	policy, err := compiledPolicy(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	return s.reloadConfigurationLocked(data, policy, nodeConfig, users, tls)
}

// compiledPolicy excludes users/listeners and logging. Include all remaining
// generated sections so custom DNS, detours, rule sets and outbounds are applied
// together; updating only Router.UpdateRules leaves outbound managers stale.
func compiledPolicy(cfg M) ([]byte, error) {
	policy := M{}
	for key, value := range cfg {
		if key != "inbounds" && key != "log" {
			policy[key] = value
		}
	}
	return json.Marshal(policy)
}

type preparedBox struct {
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc
}

// prepareBox parses and constructs the complete candidate while the running
// instance still accepts traffic. Binding/startup must happen after the old
// listeners close; if it fails reloadConfigurationLocked restores the saved config.
func prepareBox(data []byte, tracker *ConnTracker) (*preparedBox, error) {
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("parse options: %w", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create instance: %w", err)
	}
	if tracker != nil {
		if router := service.FromContext[adapter.Router](ctx); router != nil {
			router.AppendTracker(tracker)
		}
	}
	return &preparedBox{box: instance, ctx: ctx, cancel: cancel}, nil
}

func (p *preparedBox) close() {
	_ = p.box.Close()
	p.cancel()
}

func (s *SingBox) installPrepared(p *preparedBox) {
	s.box, s.ctx, s.cancel = p.box, p.ctx, p.cancel
	s.trackerRegistered = s.connTracker != nil
}

func (s *SingBox) reloadConfigurationLocked(data, policy []byte, nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	candidate, err := prepareBox(data, s.connTracker)
	if err != nil {
		return fmt.Errorf("prepare kernel reload (running configuration retained): %w", err)
	}

	// Stop acceptance first, then terminate both TCP and UDP immediately. Do not
	// use the ordinary graceful drain: old flows must not bypass a new block.
	if im := service.FromContext[adapter.InboundManager](s.ctx); im != nil {
		_ = im.Close()
	}
	if s.connTracker != nil {
		s.connTracker.CloseAll()
	}
	_ = s.box.Close()
	if s.cancel != nil {
		s.cancel()
	}
	s.box, s.ctx, s.cancel = nil, nil, nil
	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
	}

	if err = candidate.box.Start(); err != nil {
		candidate.close()
		if s.connTracker != nil {
			s.connTracker.SetUserMap(buildUserMap(s.users))
		}
		previous, rollbackErr := prepareBox(s.activeConfig, s.connTracker)
		if rollbackErr == nil {
			rollbackErr = previous.box.Start()
			if rollbackErr == nil {
				s.installPrepared(previous)
			} else {
				previous.close()
			}
		}
		if rollbackErr != nil {
			return fmt.Errorf("kernel reload failed: %v; restoring previous configuration also failed: %w", err, rollbackErr)
		}
		return fmt.Errorf("kernel reload failed; previous configuration restored: %w", err)
	}

	s.installPrepared(candidate)
	s.users, s.nodeConfig, s.tls = users, nc, tls
	s.activeConfig = append([]byte(nil), data...)
	s.activePolicy = append([]byte(nil), policy...)
	nlog.Core().Debug("sing-box kernel configuration replaced; existing flows closed")
	return nil
}

// registerTracker wires the ConnTracker to the current Router exactly once.
// The ConnTracker handles both byte counting and optional rate limiting
// in a single wrapper, so no additional trackers are needed.
func (s *SingBox) registerTracker(ctx context.Context) {
	if s.trackerRegistered {
		return
	}
	router := service.FromContext[adapter.Router](ctx)
	if router == nil {
		return
	}
	if s.connTracker != nil {
		router.AppendTracker(s.connTracker)
	}
	s.trackerRegistered = true
}

func (s *SingBox) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop()
}

func (s *SingBox) stop() {
	if s.box == nil {
		return
	}

	// Step 1: close all listen sockets so no new connections are accepted.
	// im.Close() sets m.started=false so the subsequent box.Close() call is a no-op
	// for inbounds (avoids double-close), but box.Close() still tears down routers
	// and outbounds.
	if im := service.FromContext[adapter.InboundManager](s.ctx); im != nil {
		_ = im.Close()
	}

	// Step 2: wait for in-flight connections to drain naturally (best-effort).
	if s.connTracker != nil {
		deadline := time.Now().Add(drainTimeout)
		for time.Now().Before(deadline) {
			if s.connTracker.ActiveCount() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Step 3: hard-close everything that is still open.
	s.box.Close()
	s.box = nil
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.ctx = nil
}

func (s *SingBox) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.box != nil
}

// connTrackerLocked returns the connTracker under a read-optimised lock.
func (s *SingBox) connTrackerSafe() *ConnTracker {
	s.mu.Lock()
	ct := s.connTracker
	s.mu.Unlock()
	return ct
}

// SetSpeedLimitFunc configures per-user bandwidth throttling.
func (s *SingBox) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.speedLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetSpeedLimitFunc(fn)
	}
}

// SetDeviceLimitFunc configures per-user device limit gate-keeping.
// Connections exceeding the limit are rejected at connect time.
func (s *SingBox) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetDeviceLimitFunc(fn)
	}
}

// UpdateGlobalDevices updates the global device state from panel (for multi-node).
func (s *SingBox) UpdateGlobalDevices(users map[int][]string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connTracker != nil {
		s.connTracker.UpdateGlobalDevices(users)
	}
}

// ClearGlobalDevices clears the global device state (on WS disconnect).
func (s *SingBox) ClearGlobalDevices() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connTracker != nil {
		s.connTracker.ClearGlobalDevices()
	}
}

// User management preserves flows for limit-only updates.

// AddUsers merges identities and properties. Changed identities use the safe
// candidate/rollback path; changed limits alone leave existing flows running.
func (s *SingBox) AddUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	merged := append([]model.UserSpec(nil), s.users...)
	existing := make(map[int]int, len(merged))
	for index, u := range merged {
		existing[u.ID] = index
	}
	added := 0
	for _, u := range users {
		if index, found := existing[u.ID]; found {
			merged[index] = u
		} else {
			existing[u.ID] = len(merged)
			merged = append(merged, u)
			added++
		}
	}
	if err := s.reloadInboundsLocked(merged); err != nil {
		return 0, err
	}
	s.users = merged
	return added, nil
}

// RemoveUsers applies the changed identity set with candidate/rollback support.
// Existing flows close when a successfully prepared replacement is installed.
func (s *SingBox) RemoveUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []model.UserSpec
	removed := 0
	for _, u := range s.users {
		if _, rm := removeSet[u.ID]; rm {
			removed++
		} else {
			kept = append(kept, u)
		}
	}
	if removed == 0 {
		return 0, nil
	}

	if err := s.reloadInboundsLocked(kept); err != nil {
		return 0, err
	}
	s.users = kept
	return removed, nil
}

// UpdateUsers applies changed limits in place and changed identities with a
// complete candidate. Never mutate authentication state under active handlers.
func (s *SingBox) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, 0, fmt.Errorf("not running")
	}

	toAdd, toRemove := kernel.UserDiff(s.users, users)
	added, removed = len(toAdd), len(toRemove)

	if err = s.reloadInboundsLocked(users); err != nil {
		return 0, 0, err
	}
	s.users = users
	return
}

// reloadInboundsLocked never calls the frozen dependency's unsynchronized
// UpdateUsers methods. Identical identities need only bookkeeping; additions,
// removals or changed credentials use the full candidate/rollback lifecycle.
// Must be called with s.mu held.
func (s *SingBox) reloadInboundsLocked(users []model.UserSpec) error {
	toAdd, toRemove := kernel.UserDiff(s.users, users)
	if len(toAdd) == 0 && len(toRemove) == 0 {
		if s.connTracker != nil {
			s.connTracker.SetUserMap(buildUserMap(users))
		}
		return nil
	}
	// This path applies inbounds only. A custom-config file may have changed
	// since the last policy reload, so do not snapshot its unapplied policy as
	// if it were running. Preserve the actual active sections for rollback.
	var applied M
	if err := json.Unmarshal(s.activeConfig, &applied); err != nil {
		return fmt.Errorf("parse running configuration snapshot: %w", err)
	}
	if inbound := buildInbound(s.nodeConfig, users, s.tls); inbound != nil {
		applied["inbounds"] = []M{inbound}
	} else {
		delete(applied, "inbounds")
	}
	appliedData, err := json.Marshal(applied)
	if err != nil {
		return fmt.Errorf("snapshot updated users: %w", err)
	}

	return s.reloadConfigurationLocked(appliedData, s.activePolicy, s.nodeConfig, users, s.tls)
}

// ─── Observability ──────────────────────────────────────────────────────────
func (s *SingBox) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil, nil, 0, nil
	}
	traffic, aliveIPs, connCount = ct.GetUserTraffic()
	return traffic, aliveIPs, connCount, nil
}

// CloseConnection force-closes a specific connection by its ID.
func (s *SingBox) CloseConnection(_ context.Context, connID string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return fmt.Errorf("not running")
	}
	if !ct.CloseByID(connID) {
		nlog.Core().Debug("CloseConnection: connection not found (already closed?)", "id", connID)
	}
	return nil
}

// CloseUserConnections terminates all connections for a user UUID.
func (s *SingBox) CloseUserConnections(_ context.Context, uuid string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil
	}
	ct.CloseByUUID(uuid)
	return nil
}

// buildUserMap creates a UUID→userID mapping used by ConnTracker to attribute
// connections to the correct user. All sing-box protocols use the user's UUID
// as the inbound name/username, so this covers every protocol.
func buildUserMap(users []model.UserSpec) map[string]int {
	m := make(map[string]int, len(users))
	for _, u := range users {
		m[u.UUID] = u.ID
	}
	return m
}
