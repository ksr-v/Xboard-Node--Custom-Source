package singbox

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// ipPool caches ipSnapshot maps to reduce allocations.
var ipPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]struct{}, 16)
	},
}

// ─── Per-user statistics ────────────────────────────────────────────────────

// userStats holds per-user traffic counters and alive IP tracking.
// Traffic counters are lock-free atomics (read on every packet).
// IP tracking uses a lightweight mutex (only touched at connect/disconnect).
type userStats struct {
	upload   atomic.Int64
	download atomic.Int64

	mu        sync.RWMutex   // RWMutex for concurrent reads
	ips       map[string]int // sourceIP → refcount (number of active conns from that IP)
	connCount int            // total active connections
}

// addConn registers a new connection from sourceIP.
func (u *userStats) addConn(sourceIP string) {
	u.mu.Lock()
	u.connCount++
	u.ips[sourceIP]++
	u.mu.Unlock()
}

// removeConn unregisters a connection from sourceIP.
func (u *userStats) removeConn(sourceIP string) {
	u.mu.Lock()
	u.connCount--
	u.ips[sourceIP]--
	if u.ips[sourceIP] <= 0 {
		delete(u.ips, sourceIP)
	}
	u.mu.Unlock()
}

// distinctIPs returns the number of distinct IPs currently connected.
func (u *userStats) distinctIPs() int {
	u.mu.Lock()
	n := len(u.ips)
	u.mu.Unlock()
	return n
}

// ipSnapshot returns a pooled copy of the current IP set.
func (u *userStats) ipSnapshot() map[string]struct{} {
	cp := ipPool.Get().(map[string]struct{})
	for k := range cp {
		delete(cp, k)
	}
	u.mu.Lock()
	for ip := range u.ips {
		cp[ip] = struct{}{}
	}
	u.mu.Unlock()
	return cp
}

// releaseIPSnapshot returns the snapshot to pool.
// Large maps are discarded to prevent memory bloat.
func releaseIPSnapshot(m map[string]struct{}) {
	// Discard large maps to prevent pool memory bloat
	if len(m) > 64 {
		return
	}
	ipPool.Put(m)
}

// aliveIPList returns the set of alive IPs as a boolean map (for reporting).
func (u *userStats) aliveIPList() map[string]bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.ips) == 0 {
		return nil
	}
	result := make(map[string]bool, len(u.ips))
	for ip := range u.ips {
		result[ip] = true
	}
	return result
}

// ─── ConnTracker ────────────────────────────────────────────────────────────

// ConnTracker provides per-user traffic counting, alive IP tracking, device
// limit gate-keeping, and per-user speed limiting for the sing-box kernel.
//
// Traffic accounting uses per-user atomic counters and IP refcount sets.
// A separate connection registry supports immediate policy invalidation.
// This means:
//   - GetUserTraffic is O(users), not O(connections)
//   - No Snapshot/pending buffer needed
//   - Bytes are counted directly into per-user atomics
//
// The per-connection wrapper (trackedConn) is still needed for:
//   - Keeping live I/O gates in place across unlimited/limited changes
//   - Close callback to decrement IP refcounts
//   - Bounded reservations shared across all connections of the same user
type ConnTracker struct {
	usersMu             sync.RWMutex
	users               map[int]*userStats   // userID → stats
	uuidMap             map[string]int       // UUID → userID (for lookup in RoutedConnection)
	connMap             map[string]io.Closer // connID → conn (only for force-close support)
	userCloseGeneration map[string]uint64

	idCounter atomic.Int64

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	speedLimitFunc atomic.Pointer[func(uuid string) *rate.Limiter]

	// deviceLimitFunc resolves a user UUID to their device limit.
	deviceLimitFunc     atomic.Pointer[func(uuid string) (int, bool)]
	deviceAdmissionFunc atomic.Pointer[func(uuid, sourceIP string) (release func(), err error)]

	// Multi-node device state from panel
	globalDevices    map[int]map[string]bool // userID → IP → exists
	globalMu         sync.RWMutex
	globalLastUpdate time.Time
}

// NewConnTracker creates a tracker.
func NewConnTracker(_ int) *ConnTracker {
	return &ConnTracker{
		users:               make(map[int]*userStats),
		uuidMap:             make(map[string]int),
		connMap:             make(map[string]io.Closer),
		userCloseGeneration: make(map[string]uint64),
		globalDevices:       make(map[int]map[string]bool),
	}
}

// SetSpeedLimitFunc configures the per-user speed limit lookup.
func (t *ConnTracker) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	t.speedLimitFunc.Store(&fn)
}

// SetDeviceLimitFunc configures the per-user device limit lookup for gate-keeping.
func (t *ConnTracker) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	t.deviceLimitFunc.Store(&fn)
}

func (t *ConnTracker) SetDeviceAdmissionFunc(fn func(uuid, sourceIP string) (release func(), err error)) {
	if fn == nil {
		t.deviceAdmissionFunc.Store(nil)
		return
	}
	t.deviceAdmissionFunc.Store(&fn)
}

// SetUserMap replaces the UUID→userID mapping and ensures per-user stats
// structs exist for all users. Old users that are no longer present keep
// their stats until their connections drain.
func (t *ConnTracker) SetUserMap(m map[string]int) {
	t.usersMu.Lock()
	var removed []string
	for uuid, uid := range t.uuidMap {
		if m[uuid] != uid {
			removed = append(removed, uuid)
		}
	}
	t.uuidMap = m
	for _, uid := range m {
		if _, ok := t.users[uid]; !ok {
			t.users[uid] = &userStats{ips: make(map[string]int)}
		}
	}
	t.usersMu.Unlock()
	for _, uuid := range removed {
		t.CloseByUUID(uuid)
	}
}

// UpdateGlobalDevices syncs global device state from panel.
func (t *ConnTracker) UpdateGlobalDevices(users map[int][]string) {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		m := make(map[string]bool, len(ips))
		for _, ip := range ips {
			m[ip] = true
		}
		t.globalDevices[uid] = m
	}
	t.globalLastUpdate = time.Now()
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state updated", "users", len(users))
}

// ClearGlobalDevices resets global device state (on WS disconnect).
func (t *ConnTracker) ClearGlobalDevices() {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool)
	t.globalLastUpdate = time.Time{}
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state cleared")
}

// ─── adapter.ConnectionTracker ──────────────────────────────────────────────

// RoutedConnection wraps a TCP conn to count bytes per-user, track IPs,
// and optionally rate-limit. Gate-keeps device limits at connection time.
func (t *ConnTracker) RoutedConnection(
	ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	generation := t.userCloseGeneration[uuid]
	t.usersMu.RUnlock()
	if uuid != "" && uid == 0 {
		conn.Close()
		return conn
	}

	release, admitted := t.admitConnection(uuid, us, uid, sourceIP)
	if !admitted {
		conn.Close()
		return conn
	}

	connID := t.nextID()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	ctx, cancel := context.WithCancel(ctx)
	tracked := &trackedConn{
		Conn:             conn,
		tracker:          t,
		us:               us,
		userID:           uid,
		connID:           connID,
		sourceIP:         sourceIP,
		userUUID:         uuid,
		limiter:          lim,
		ctx:              ctx,
		cancel:           cancel,
		releaseAdmission: release,
	}
	t.usersMu.Lock()
	if t.userCloseGeneration[uuid] != generation || t.uuidMap[uuid] != uid {
		t.usersMu.Unlock()
		_ = tracked.Close()
		return tracked
	}
	t.connMap[connID] = tracked
	t.usersMu.Unlock()
	return tracked
}

// RoutedPacketConnection tracks UDP alongside TCP so a routing change can
// close every old flow before accepting traffic under the new policy.
func (t *ConnTracker) RoutedPacketConnection(
	ctx context.Context, conn N.PacketConn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	t.usersMu.RLock()
	uid := t.uuidMap[uuid]
	us := t.users[uid]
	generation := t.userCloseGeneration[uuid]
	t.usersMu.RUnlock()
	if uuid != "" && uid == 0 {
		conn.Close()
		return conn
	}

	release, admitted := t.admitConnection(uuid, us, uid, sourceIP)
	if !admitted {
		conn.Close()
		return conn
	}

	connID := t.nextID()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	ctx, cancel := context.WithCancel(ctx)
	tracked := &trackedPacketConn{
		PacketConn:       conn,
		tracker:          t,
		us:               us,
		userID:           uid,
		connID:           connID,
		sourceIP:         sourceIP,
		userUUID:         uuid,
		limiter:          lim,
		ctx:              ctx,
		cancel:           cancel,
		releaseAdmission: release,
	}
	t.usersMu.Lock()
	if t.userCloseGeneration[uuid] != generation || t.uuidMap[uuid] != uid {
		t.usersMu.Unlock()
		_ = tracked.Close()
		return tracked
	}
	t.connMap[connID] = tracked
	t.usersMu.Unlock()
	return tracked
}

// admitConnection performs remote admission without holding a user lock, then
// atomically checks and registers the local slot. A newer/smaller IP never
// displaces an established connection. Central admission, when configured,
// supersedes the eventually consistent global snapshot.
func (t *ConnTracker) admitConnection(uuid string, us *userStats, userID int, sourceIP string) (func(), bool) {
	limit := 0
	if lookup := t.deviceLimitFunc.Load(); lookup != nil {
		if value, limited := (*lookup)(uuid); limited {
			limit = value
		}
	}
	var release func()
	central := false
	if admission := t.deviceAdmissionFunc.Load(); limit > 0 && admission != nil {
		var err error
		release, err = (*admission)(uuid, sourceIP)
		if err != nil {
			return nil, false
		}
		central = true
	}
	if us != nil {
		us.mu.Lock()
		if t.deviceGateLocked(us, userID, sourceIP, limit, !central) {
			us.mu.Unlock()
			if release != nil {
				release()
			}
			return nil, false
		}
		us.connCount++
		us.ips[sourceIP]++
		us.mu.Unlock()
	}
	return release, true
}

func (t *ConnTracker) checkDeviceGate(us *userStats, userID int, sourceIP string, limit int) bool {
	if us == nil {
		return false
	}
	us.mu.RLock()
	defer us.mu.RUnlock()
	return t.deviceGateLocked(us, userID, sourceIP, limit, true)
}

// deviceGateLocked requires us.mu. Known IPs may open concurrent connections;
// unknown IPs must fit in the union of locally held and fresh global slots.
func (t *ConnTracker) deviceGateLocked(us *userStats, userID int, sourceIP string, limit int, useGlobal bool) bool {
	if limit <= 0 || us.ips[sourceIP] > 0 {
		return false
	}
	if !useGlobal {
		return len(us.ips) >= limit
	}
	t.globalMu.RLock()
	defer t.globalMu.RUnlock()
	globalIPs := t.globalDevices[userID]
	if time.Since(t.globalLastUpdate) > 60*time.Second || globalIPs == nil {
		return len(us.ips) >= limit
	}
	if globalIPs[sourceIP] {
		return false
	}
	count := len(us.ips)
	for ip := range globalIPs {
		if us.ips[ip] <= 0 {
			count++
		}
	}
	return count >= limit
}

func (t *ConnTracker) nextID() string {
	return "sb-" + formatInt36(t.idCounter.Add(1))
}

func formatInt36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [13]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	return string(buf[i:])
}

// ─── Public API ─────────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic and alive IPs.
// This is O(users), not O(connections).
func (t *ConnTracker) GetUserTraffic() (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int) {
	t.usersMu.RLock()
	traffic = make(map[int][2]int64, len(t.users))
	aliveIPs = make(map[int]map[string]bool, len(t.users))
	for uid, us := range t.users {
		up := us.upload.Load()
		down := us.download.Load()
		if up > 0 || down > 0 {
			traffic[uid] = [2]int64{up, down}
		}

		ips := us.aliveIPList()
		if ips != nil {
			aliveIPs[uid] = ips
		}

		us.mu.Lock()
		connCount += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return
}

// HasUserSourceIP includes every locally held connection, including a flow
// created before a later unlimited-to-limited plan change.
func (t *ConnTracker) HasUserSourceIP(uuid, sourceIP string) bool {
	t.usersMu.RLock()
	defer t.usersMu.RUnlock()
	if uid, known := t.uuidMap[uuid]; known {
		if user := t.users[uid]; user != nil {
			user.mu.RLock()
			present := user.ips[sourceIP] > 0
			user.mu.RUnlock()
			return present
		}
		return false
	}
	// An identity replacement can remove the lookup before old flows finish
	// closing. Keep their captured identity conservative during that interval.
	for _, conn := range t.connMap {
		var user *userStats
		switch active := conn.(type) {
		case *trackedConn:
			if active.userUUID == uuid && active.sourceIP == sourceIP {
				user = active.us
			}
		case *trackedPacketConn:
			if active.userUUID == uuid && active.sourceIP == sourceIP {
				user = active.us
			}
		}
		if user != nil {
			user.mu.RLock()
			present := user.ips[sourceIP] > 0
			user.mu.RUnlock()
			if present {
				return true
			}
		}
	}
	return false
}

// CloseByID force-closes a connection by its ID.
func (t *ConnTracker) CloseByID(id string) bool {
	t.usersMu.RLock()
	conn, ok := t.connMap[id]
	t.usersMu.RUnlock()
	if !ok {
		return false
	}
	if conn != nil {
		conn.Close()
	}
	return true
}

// CloseAll invalidates both TCP and UDP flows after a routing policy change.
// Close may re-enter removeConnRef, so invoke it outside usersMu.
func (t *ConnTracker) CloseAll() int {
	t.usersMu.Lock()
	conns := make([]io.Closer, 0, len(t.connMap))
	for _, conn := range t.connMap {
		conns = append(conns, conn)
	}
	clear(t.connMap)
	t.usersMu.Unlock()
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
	return len(conns)
}

// CloseByUUID force-closes ALL connections for a given user UUID.
func (t *ConnTracker) CloseByUUID(uuid string) int {
	t.usersMu.Lock()
	t.userCloseGeneration[uuid]++
	var conns []io.Closer
	for _, conn := range t.connMap {
		switch active := conn.(type) {
		case *trackedConn:
			if active.userUUID == uuid {
				conns = append(conns, active)
			}
		case *trackedPacketConn:
			if active.userUUID == uuid {
				conns = append(conns, active)
			}
		}
	}
	t.usersMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return len(conns)
}

// ActiveCount returns the total number of active connections.
func (t *ConnTracker) ActiveCount() int {
	t.usersMu.RLock()
	total := 0
	for _, us := range t.users {
		us.mu.Lock()
		total += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return total
}

// removeConnRef removes the connection reference from connMap on close.
func (t *ConnTracker) removeConnRef(connID string) {
	t.usersMu.Lock()
	delete(t.connMap, connID)
	t.usersMu.Unlock()
}

// ─── trackedConn (TCP) ──────────────────────────────────────────────────────

// RateLimitedWriter wraps a writer with a shared, dynamically updated bucket.
type RateLimitedWriter struct {
	writer  io.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

func (w *RateLimitedWriter) Write(b []byte) (int, error) {
	return writeLimited(w.ctx, w.writer, w.limiter, b)
}

// writeLimited preserves io.Writer's full-write contract while bounding each
// forwarded block. A burst change cannot produce a short successful write.
func writeLimited(ctx context.Context, writer io.Writer, lim *rate.Limiter, b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		chunk := b[:min(len(b), 16*1024)]
		if err := limiter.WaitN(ctx, lim, int64(len(chunk))); err != nil {
			return written, err
		}
		n, err := writer.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		if n != len(chunk) {
			return written, io.ErrShortWrite
		}
		b = b[n:]
	}
	return written, nil
}

// RateLimitedReadCloser wraps a reader with a shared, dynamic bucket.
type RateLimitedReadCloser struct {
	reader  io.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

func (r *RateLimitedReadCloser) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	if n > 0 {
		if waitErr := limiter.WaitN(r.ctx, r.limiter, int64(n)); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

type trackedConn struct {
	net.Conn
	tracker          *ConnTracker
	us               *userStats // per-user stats (upload/download atomics + IP tracking)
	userID           int        // user ID for device tracking
	connID           string
	sourceIP         string
	userUUID         string
	limiter          *rate.Limiter
	ctx              context.Context
	cancel           context.CancelFunc
	closed           atomic.Bool
	releaseAdmission func()
}

func (c *trackedConn) Read(b []byte) (int, error) {
	// Bound an in-flight read even while currently unlimited. Existing streams
	// must retain this gate when a limit is enabled later.
	if c.limiter != nil && len(b) > 16*1024 {
		b = b[:16*1024]
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		if c.us != nil {
			c.us.upload.Add(int64(n))
		}
		if waitErr := limiter.WaitN(c.ctx, c.limiter, int64(n)); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	n, err := writeLimited(c.ctx, c.Conn, c.limiter, b)
	if n > 0 && c.us != nil {
		c.us.download.Add(int64(n))
	}
	return n, err
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.cancel != nil {
			c.cancel()
		}
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.connID)
		if c.releaseAdmission != nil {
			c.releaseAdmission()
		}
	}
	return c.Conn.Close()
}

// makeCountFunc builds a CountFunc for zero-copy byte counting via sing's
// ReadCounter/WriteCounter unwrap interfaces.
func (c *trackedConn) makeCountFunc(counter *atomic.Int64) N.CountFunc {
	return func(n int64) {
		counter.Add(n)
		// CountFunc cannot return an error; cancellation stops the wait and
		// the closing transport terminates its copy loop.
		_ = limiter.WaitN(c.ctx, c.limiter, n)
	}
}

func (c *trackedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if c.limiter != nil {
		return trackedReaderView{c}, nil
	}
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.upload)} // 从入站读取 = 用户上传
}

func (c *trackedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if c.limiter != nil {
		return trackedWriterView{c}, nil
	}
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.download)} // 向入站写入 = 用户下载
}

func (c *trackedConn) Upstream() any           { return c.Conn }
func (c *trackedConn) ReaderReplaceable() bool { return c.limiter == nil }
func (c *trackedConn) WriterReplaceable() bool { return c.limiter == nil }

// Counter callbacks run after splice has already forwarded the bytes. These
// opaque views preserve the actual I/O gates, including for unlimited streams
// that may be limited later, without exposing another unwrap/counter layer.
type trackedReaderView struct{ conn *trackedConn }

func (v trackedReaderView) Read(b []byte) (int, error) { return v.conn.Read(b) }

type trackedWriterView struct{ conn *trackedConn }

func (v trackedWriterView) Write(b []byte) (int, error) { return v.conn.Write(b) }

// ─── trackedPacketConn (UDP / QUIC) ─────────────────────────────────────────

type trackedPacketConn struct {
	N.PacketConn
	tracker          *ConnTracker
	us               *userStats
	userID           int
	connID           string
	sourceIP         string
	userUUID         string
	limiter          *rate.Limiter
	ctx              context.Context
	cancel           context.CancelFunc
	closed           atomic.Bool
	releaseAdmission func()
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (singM.Socksaddr, error) {
	dest, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		n := int64(buffer.Len())
		if c.us != nil {
			c.us.upload.Add(n)
		}
		if waitErr := limiter.WaitN(c.ctx, c.limiter, n); waitErr != nil {
			return dest, waitErr
		}
	}
	return dest, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, dest singM.Socksaddr) error {
	n := int64(buffer.Len())
	if err := limiter.WaitN(c.ctx, c.limiter, n); err != nil {
		return err
	}
	err := c.PacketConn.WritePacket(buffer, dest)
	if err == nil && c.us != nil {
		c.us.download.Add(n)
	}
	return err
}

func (c *trackedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.cancel != nil {
			c.cancel()
		}
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.connID)
		if c.releaseAdmission != nil {
			c.releaseAdmission()
		}
	}
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) makeCountFunc(counter *atomic.Int64) N.CountFunc {
	return func(n int64) {
		counter.Add(n)
		// CountFunc cannot return an error; cancellation stops the wait and
		// the closing transport terminates its copy loop.
		_ = limiter.WaitN(c.ctx, c.limiter, n)
	}
}

func (c *trackedPacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	if c.limiter != nil {
		return trackedPacketReaderView{c}, nil
	}
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.download)}
}

func (c *trackedPacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	if c.limiter != nil {
		return trackedPacketWriterView{c}, nil
	}
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.upload)}
}

func (c *trackedPacketConn) Upstream() any           { return c.PacketConn }
func (c *trackedPacketConn) ReaderReplaceable() bool { return c.limiter == nil }
func (c *trackedPacketConn) WriterReplaceable() bool { return c.limiter == nil }

type trackedPacketReaderView struct{ conn *trackedPacketConn }

func (v trackedPacketReaderView) ReadPacket(b *buf.Buffer) (singM.Socksaddr, error) {
	return v.conn.ReadPacket(b)
}

type trackedPacketWriterView struct{ conn *trackedPacketConn }

func (v trackedPacketWriterView) WritePacket(b *buf.Buffer, destination singM.Socksaddr) error {
	return v.conn.WritePacket(b, destination)
}
