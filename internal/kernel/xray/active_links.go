package xray

import (
	"context"
	stdnet "net"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var _ interface{ SetCloseHandler(func()) } = (*pipe.Reader)(nil)

// activeLink owns a complete logical request, not just its writable half.
// Reader stays concrete for mux/XUDP; Writer forwards I/O and observes only
// closure so both halves can finish before normal admission cleanup.
type activeLink struct {
	dispatcher            *LimitDispatcher
	id                    uint64
	uuid, email, sourceIP string
	cancel                context.CancelFunc
	release               func()
	closed                atomic.Bool
	abortOnce             sync.Once
	done                  chan struct{}
	mu                    sync.Mutex
	reader                buf.Reader
	writer                buf.Writer
	inbound               stdnet.Conn
	readDone, writeDone   bool
}

type linkIdentity struct {
	uuid       string
	generation uint64
}

func (d *LimitDispatcher) identityFromContext(ctx context.Context) linkIdentity {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		uuid := d.emailToUUID[inbound.User.Email]
		return linkIdentity{uuid, d.userCloseGeneration[uuid]}
	}
	return linkIdentity{}
}

func (d *LimitDispatcher) beginLink(parent context.Context, email, sourceIP string, release func(), captured ...linkIdentity) (*activeLink, context.Context) {
	child, cancel := context.WithCancel(parent)
	active := &activeLink{dispatcher: d, id: d.linkCounter.Add(1), email: email, sourceIP: sourceIP, cancel: cancel, release: release, done: make(chan struct{})}
	if inbound := session.InboundFromContext(parent); inbound != nil {
		active.inbound = inbound.Conn
	}
	d.mu.Lock()
	active.uuid = d.emailToUUID[email]
	changed := false
	if len(captured) != 0 {
		active.uuid = captured[0].uuid
		changed = active.uuid == "" || d.emailToUUID[email] != active.uuid || d.userCloseGeneration[active.uuid] != captured[0].generation
	}
	if d.activeLinks == nil {
		d.activeLinks = make(map[uint64]*activeLink)
	}
	d.activeLinks[active.id] = active
	d.connCount.Add(1)
	d.mu.Unlock()
	// Workers cancel their parent context when the inbound request ends.
	// This also reclaims asynchronous Dispatch links after both halves finish.
	context.AfterFunc(child, func() { active.close() })
	if changed || d.closing.Load() {
		active.close()
	}
	return active, child
}

func (a *activeLink) attach(link *transport.Link) bool {
	a.mu.Lock()
	if a.closed.Load() {
		a.mu.Unlock()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return false
	}
	a.reader, a.writer = link.Reader, link.Writer
	link.Writer = &closeTrackingWriter{Writer: link.Writer, onClose: a.writerClosed}
	a.mu.Unlock()
	if reader, ok := link.Reader.(interface{ SetCloseHandler(func()) }); ok {
		reader.SetCloseHandler(a.readerClosed)
	}
	return true
}

func (a *activeLink) readerClosed() { a.halfClosed(true) }
func (a *activeLink) writerClosed() { a.halfClosed(false) }
func (a *activeLink) halfClosed(read bool) {
	a.mu.Lock()
	if read {
		a.readDone = true
	} else {
		a.writeDone = true
	}
	complete := a.readDone && a.writeDone
	a.mu.Unlock()
	if complete {
		a.close()
	}
}

func (a *activeLink) abort() {
	a.abortOnce.Do(func() {
		a.mu.Lock()
		reader, writer, inbound := a.reader, a.writer, a.inbound
		a.mu.Unlock()
		// Closing the inbound socket is necessary for direct/splice paths; merely
		// closing a pipe writer can leave an origin response flowing downstream.
		if inbound != nil {
			_ = inbound.Close()
		}
		common.Interrupt(reader)
		common.Interrupt(writer)
	})
}

func (a *activeLink) close(force ...bool) bool {
	first := a.closed.CompareAndSwap(false, true)
	if len(force) > 0 && force[0] {
		a.abort()
	}
	if !first {
		return false
	}
	a.cancel()
	d := a.dispatcher
	d.delConn(a.email, a.sourceIP)
	d.connCount.Add(-1)
	d.mu.Lock()
	delete(d.activeLinks, a.id)
	d.mu.Unlock()
	if a.release != nil {
		a.release()
	}
	close(a.done)
	return true
}

func (d *LimitDispatcher) CloseByUUID(uuid string) int {
	d.mu.Lock()
	if d.userCloseGeneration == nil {
		d.userCloseGeneration = make(map[string]uint64)
	}
	d.userCloseGeneration[uuid]++
	var active []*activeLink
	for _, link := range d.activeLinks {
		if link.uuid == uuid {
			active = append(active, link)
		}
	}
	d.mu.Unlock()
	closed := 0
	for _, link := range active {
		if link.close(true) {
			closed++
		}
		<-link.done
	}
	return closed
}

func (d *LimitDispatcher) CloseAllLinks() int {
	d.mu.RLock()
	active := make([]*activeLink, 0, len(d.activeLinks))
	for _, link := range d.activeLinks {
		active = append(active, link)
	}
	d.mu.RUnlock()
	closed := 0
	for _, link := range active {
		if link.close(true) {
			closed++
		}
		<-link.done
	}
	return closed
}

type closeTrackingWriter struct {
	buf.Writer
	onClose func()
	closed  atomic.Bool
}

func (w *closeTrackingWriter) Close() error {
	err := common.Close(w.Writer)
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	return err
}
func (w *closeTrackingWriter) Interrupt() {
	common.Interrupt(w.Writer)
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
}
