package xray

import (
	"context"
	"io"
	stdnet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type forceEndpoint struct {
	done       chan struct{}
	once       sync.Once
	interrupts atomic.Int64
}

func newForceEndpoint() *forceEndpoint { return &forceEndpoint{done: make(chan struct{})} }
func (e *forceEndpoint) Interrupt()    { e.once.Do(func() { e.interrupts.Add(1); close(e.done) }) }
func (e *forceEndpoint) Close() error  { e.Interrupt(); return nil }
func (e *forceEndpoint) ReadMultiBuffer() (buf.MultiBuffer, error) {
	<-e.done
	return nil, io.ErrClosedPipe
}
func (e *forceEndpoint) WriteMultiBuffer(value buf.MultiBuffer) error {
	<-e.done
	buf.ReleaseMulti(value)
	return io.ErrClosedPipe
}

func forceTrackedLink(t *testing.T, d *LimitDispatcher, uid int, ip string, conn stdnet.Conn, release func()) (*activeLink, context.Context, *forceEndpoint, *forceEndpoint) {
	t.Helper()
	email := userEmail(uid)
	if d.checkDeviceLimit(email, ip, true) {
		t.Fatal("fixture device rejected")
	}
	parent, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	parent = session.ContextWithInbound(parent, &session.Inbound{User: &protocol.MemoryUser{Email: email}, Conn: conn})
	active, child := d.beginLink(parent, email, ip, release)
	reader, writer := newForceEndpoint(), newForceEndpoint()
	if !active.attach(&transport.Link{Reader: reader, Writer: writer}) {
		t.Fatal("fixture link closed early")
	}
	t.Cleanup(func() { active.close() })
	return active, child, reader, writer
}

func awaitClosed(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("force-close left I/O blocked")
	}
}

func TestForceCloseUserStopsBothDirectionsAndRealInbound(t *testing.T) {
	d := limitedDispatcher()
	applyDispatcherLimits(d, []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1}, {ID: 2, UUID: "uuid-2", DeviceLimit: 1}})
	inbound, peer := stdnet.Pipe()
	defer peer.Close()
	var releases atomic.Int64
	_, child, reader, writer := forceTrackedLink(t, d, 1, "127.0.0.2", inbound, func() { releases.Add(1) })
	_, otherChild, otherReader, otherWriter := forceTrackedLink(t, d, 2, "127.0.0.3", nil, nil)
	readDone, writeDone, socketDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() { _, _ = reader.ReadMultiBuffer(); close(readDone) }()
	go func() {
		_ = writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("held response"))})
		close(writeDone)
	}()
	go func() { _, _ = peer.Read(make([]byte, 1)); close(socketDone) }()
	x := New(config.KernelConfig{Type: "xray"})
	x.limitDispatcher = d
	if err := x.CloseUserConnections(context.Background(), "uuid-1"); err != nil {
		t.Fatal(err)
	}
	awaitClosed(t, child.Done())
	awaitClosed(t, readDone)
	awaitClosed(t, writeDone)
	awaitClosed(t, socketDone)
	if releases.Load() != 1 || reader.interrupts.Load() != 1 || writer.interrupts.Load() != 1 {
		t.Fatal("force-close did not release exactly once")
	}
	select {
	case <-otherChild.Done():
		t.Fatal("another user was canceled")
	default:
	}
	if otherReader.interrupts.Load() != 0 || otherWriter.interrupts.Load() != 0 {
		t.Fatal("another user's endpoints were interrupted")
	}
	if d.CloseByUUID("uuid-1") != 0 {
		t.Fatal("repeated close found an old active link")
	}
	if ips, count := d.GetConnectionState(); count != 1 || len(ips[1]) != 0 || !ips[2]["127.0.0.3"] {
		t.Fatalf("incorrect remaining devices: %v, %d", ips, count)
	}
}

func TestForceCloseKeepsReadHalfTrackedAfterWriterHalfCloses(t *testing.T) {
	d := limitedDispatcher()
	var releases atomic.Int64
	_, _, reader, writer := forceTrackedLink(t, d, 1, "127.0.0.2", nil, func() { releases.Add(1) })
	_ = writer.Close()
	if releases.Load() != 0 {
		t.Fatal("writable half-close prematurely released a live request")
	}
	if ips, count := d.GetConnectionState(); count != 1 || !ips[1]["127.0.0.2"] {
		t.Fatal("held read half disappeared from tracking")
	}
	d.CloseByUUID("uuid-1")
	if reader.interrupts.Load() != 1 || writer.interrupts.Load() != 1 || releases.Load() != 1 {
		t.Fatal("watchdog did not kill retained read half exactly once")
	}
}

type waitingForceDispatcher struct {
	entered        chan context.Context
	resume         chan struct{}
	reader, writer *forceEndpoint
}

func (w *waitingForceDispatcher) Dispatch(ctx context.Context, _ xnet.Destination) (*transport.Link, error) {
	w.entered <- ctx
	<-w.resume
	return &transport.Link{Reader: w.reader, Writer: w.writer}, nil
}
func (w *waitingForceDispatcher) DispatchLink(ctx context.Context, _ xnet.Destination, _ *transport.Link) error {
	w.entered <- ctx
	<-ctx.Done()
	return ctx.Err()
}
func (*waitingForceDispatcher) Type() interface{} { return nil }
func (*waitingForceDispatcher) Start() error      { return nil }
func (*waitingForceDispatcher) Close() error      { return nil }

func TestForceClosePendingDispatchCancelsAndInterruptsLateLink(t *testing.T) {
	d := limitedDispatcher()
	w := &waitingForceDispatcher{entered: make(chan context.Context, 1), resume: make(chan struct{}), reader: newForceEndpoint(), writer: newForceEndpoint()}
	d.innerDisp = w
	var releases atomic.Int64
	d.SetDeviceAdmissionFunc(func(string, string) (func(), error) { return func() { releases.Add(1) }, nil })
	ctx, dest := admissionContext("127.0.0.2")
	finished := make(chan error, 1)
	go func() { _, err := d.Dispatch(ctx, dest); finished <- err }()
	child := <-w.entered
	if d.CloseByUUID("uuid-1") != 1 {
		t.Fatal("pending dispatch was not registered")
	}
	awaitClosed(t, child.Done())
	close(w.resume)
	if err := <-finished; err == nil {
		t.Fatal("late closed link was returned as usable")
	}
	if w.reader.interrupts.Load() != 1 || w.writer.interrupts.Load() != 1 || releases.Load() != 1 {
		t.Fatal("late link leaked endpoints or admission")
	}
}

func TestForceCloseInvalidatesPendingAdmissionGeneration(t *testing.T) {
	d := limitedDispatcher()
	entered, resume := make(chan struct{}), make(chan struct{})
	var releases atomic.Int64
	d.SetDeviceAdmissionFunc(func(string, string) (func(), error) { close(entered); <-resume; return func() { releases.Add(1) }, nil })
	d.innerDisp = failedAdmissionDispatcher{}
	ctx, dest := admissionContext("127.0.0.2")
	finished := make(chan error, 1)
	go func() { _, err := d.Dispatch(ctx, dest); finished <- err }()
	<-entered
	d.CloseByUUID("uuid-1")
	close(resume)
	if err := <-finished; err != context.Canceled {
		t.Fatalf("pending admission was revived after forced close: %v", err)
	}
	if ips, count := d.GetConnectionState(); count != 0 || len(ips) != 0 || releases.Load() != 1 {
		t.Fatal("late admission leaked")
	}
}

func TestForceCloseUserIdentityChangeAndKernelCloseReleaseAll(t *testing.T) {
	d := limitedDispatcher()
	users := []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1}, {ID: 2, UUID: "uuid-2", DeviceLimit: 1}}
	applyDispatcherLimits(d, users)
	var releases atomic.Int64
	_, first, _, _ := forceTrackedLink(t, d, 1, "127.0.0.2", nil, func() { releases.Add(1) })
	_, second, _, _ := forceTrackedLink(t, d, 2, "127.0.0.3", nil, func() { releases.Add(1) })
	users[0].UUID = "uuid-replaced"
	applyDispatcherLimits(d, users)
	awaitClosed(t, first.Done())
	select {
	case <-second.Done():
		t.Fatal("identity update closed another user")
	default:
	}
	_ = d.Close()
	_ = d.Close()
	awaitClosed(t, second.Done())
	if releases.Load() != 2 {
		t.Fatalf("released %d times", releases.Load())
	}
}

func TestForceCloseConcurrentCancelReleasesOnce(t *testing.T) {
	d := limitedDispatcher()
	var releases atomic.Int64
	a, _, _, _ := forceTrackedLink(t, d, 1, "127.0.0.2", nil, func() { releases.Add(1) })
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); d.CloseByUUID("uuid-1"); a.close() }()
	}
	wg.Wait()
	d.ResetConns()
	if releases.Load() != 1 || d.connCount.Load() != 0 {
		t.Fatalf("releases=%d conns=%d", releases.Load(), d.connCount.Load())
	}
}

type forceCountingConn struct {
	stdnet.Conn
	closes atomic.Int64
}

func (c *forceCountingConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestMuxSharedParentCompletesOneStreamWithoutClosingAnother(t *testing.T) {
	d := limitedDispatcher()
	inbound, peer := stdnet.Pipe()
	defer peer.Close()
	physical := &forceCountingConn{Conn: inbound}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	parent = session.ContextWithInbound(parent, &session.Inbound{User: &protocol.MemoryUser{Email: userEmail(1)}, Conn: physical})
	var releases atomic.Int64
	var first, second *activeLink
	var firstChild, secondChild context.Context
	var firstLink, secondLink *transport.Link
	var firstDownWriter *pipe.Writer
	for i := 0; i < 2; i++ {
		if d.checkDeviceLimit(userEmail(1), "127.0.0.2", true) {
			t.Fatal("same IP rejected")
		}
		a, child := d.beginLink(parent, userEmail(1), "127.0.0.2", func() { releases.Add(1) })
		reader, downWriter := pipe.New()
		_, upWriter := pipe.New()
		link := &transport.Link{Reader: reader, Writer: upWriter}
		a.attach(link)
		if i == 0 {
			first, firstChild, firstLink, firstDownWriter = a, child, link, downWriter
		} else {
			second, secondChild, secondLink = a, child, link
		}
	}
	_ = firstDownWriter.Close()
	_, _ = firstLink.Reader.ReadMultiBuffer()
	_ = firstLink.Writer.(*closeTrackingWriter).Close()
	awaitClosed(t, firstChild.Done())
	if !first.closed.Load() || second.closed.Load() || physical.closes.Load() != 0 || parent.Err() != nil {
		t.Fatal("normal stream completion affected the shared physical parent")
	}
	select {
	case <-secondChild.Done():
		t.Fatal("another logical stream was canceled")
	default:
	}
	d.mu.RLock()
	remaining := len(d.activeLinks)
	d.mu.RUnlock()
	if remaining != 1 || releases.Load() != 1 {
		t.Fatalf("ended mux stream leaked: remaining=%d released=%d", remaining, releases.Load())
	}
	readDone := make(chan struct{})
	go func() { _, _ = secondLink.Reader.ReadMultiBuffer(); close(readDone) }()
	d.CloseByUUID("uuid-1")
	awaitClosed(t, readDone)
	awaitClosed(t, secondChild.Done())
	if physical.closes.Load() != 1 || releases.Load() != 2 {
		t.Fatal("force-close failed to terminate the remaining shared stream")
	}
}

func TestAsyncLinkWaitsForBothHalfCloses(t *testing.T) {
	for _, readerFirst := range []bool{true, false} {
		d := limitedDispatcher()
		if d.checkDeviceLimit(userEmail(1), "127.0.0.2", true) {
			t.Fatal("fixture rejected")
		}
		var releases atomic.Int64
		a, _ := d.beginLink(context.Background(), userEmail(1), "127.0.0.2", func() { releases.Add(1) })
		reader, downWriter := pipe.New()
		_, upWriter := pipe.New()
		link := &transport.Link{Reader: reader, Writer: upWriter}
		a.attach(link)
		readEnd := func() { _ = downWriter.Close(); _, _ = reader.ReadMultiBuffer() }
		writeEnd := func() { _ = link.Writer.(*closeTrackingWriter).Close() }
		if readerFirst {
			readEnd()
		} else {
			writeEnd()
		}
		if a.closed.Load() || releases.Load() != 0 || d.connCount.Load() != 1 {
			t.Fatal("one half-close prematurely freed a live device")
		}
		if readerFirst {
			writeEnd()
		} else {
			readEnd()
		}
		if !a.closed.Load() || releases.Load() != 1 || d.connCount.Load() != 0 {
			t.Fatal("both ends completed without cleanup")
		}
	}
}

func TestMaintainedReaderTerminalObserverLateRegistrationAndTransientXUDP(t *testing.T) {
	reader, writer := pipe.New()
	reader.ReturnAnError(io.EOF)
	if _, err := reader.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("temporary EOF=%v", err)
	}
	var notices atomic.Int64
	reader.SetCloseHandler(func() { notices.Add(1) })
	if notices.Load() != 0 {
		t.Fatal("temporary XUDP detach was treated as terminal")
	}
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("reused"))}); err != nil {
		t.Fatal(err)
	}
	value, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	buf.ReleaseMulti(value)
	_ = writer.Close()
	_, _ = reader.ReadMultiBuffer()
	reader.Interrupt()
	_, _ = reader.ReadMultiBuffer()
	if notices.Load() != 1 {
		t.Fatalf("terminal notified %d times", notices.Load())
	}
	late, _ := pipe.New()
	late.Interrupt()
	var lateNotices atomic.Int64
	late.SetCloseHandler(func() { lateNotices.Add(1); late.Interrupt(); _, _ = late.ReadMultiBuffer() })
	if lateNotices.Load() != 1 {
		t.Fatal("late terminal registration lost notification or reentered its handler")
	}
	timed, _ := pipe.New()
	var timedNotices atomic.Int64
	timed.SetCloseHandler(func() { timedNotices.Add(1) })
	_, _ = timed.ReadMultiBufferTimeout(time.Millisecond)
	if timedNotices.Load() != 0 {
		t.Fatal("read timeout was treated as terminal")
	}
	timed.Interrupt()
	if timedNotices.Load() != 1 {
		t.Fatal("interrupt did not terminate timeout-capable reader")
	}
}
