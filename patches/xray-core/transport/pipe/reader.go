package pipe

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// Reader is a buf.Reader that reads content from a pipe.
type Reader struct {
	pipe          *pipe
	closeMu       sync.Mutex
	closeHandler  func()
	terminal      bool
	closeNotified bool
}

// SetCloseHandler observes the terminal read side without replacing the
// concrete Reader required by mux/reverse. Each installed handler is notified
// once, including a handler installed after terminal EOF or Interrupt.
func (r *Reader) SetCloseHandler(handler func()) {
	r.closeMu.Lock()
	r.closeHandler = handler
	r.closeNotified = false
	notify := r.terminal && handler != nil
	if notify {
		r.closeNotified = true
	}
	r.closeMu.Unlock()
	if notify {
		handler()
	}
}

func (r *Reader) notifyTerminal() {
	r.closeMu.Lock()
	r.terminal = true
	handler := r.closeHandler
	notify := handler != nil && !r.closeNotified
	if notify {
		r.closeNotified = true
	}
	r.closeMu.Unlock()
	if notify {
		handler()
	}
}

func (r *Reader) observeReadError(err error) {
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		return
	}
	// XUDP injects temporary EOF through ReturnAnError while the pipe remains
	// open. That detach must not terminate or de-register its reusable session.
	r.pipe.Lock()
	terminal := r.pipe.state != open
	r.pipe.Unlock()
	if terminal {
		r.notifyTerminal()
	}
}

// ReadMultiBuffer implements buf.Reader.
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	value, err := r.pipe.ReadMultiBuffer()
	r.observeReadError(err)
	return value, err
}

// ReadMultiBufferTimeout reads content from a pipe within the given duration, or returns buf.ErrTimeout otherwise.
func (r *Reader) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	value, err := r.pipe.ReadMultiBufferTimeout(d)
	r.observeReadError(err)
	return value, err
}

// Interrupt implements common.Interruptible.
func (r *Reader) Interrupt() {
	r.pipe.Interrupt()
	r.notifyTerminal()
}

// ReturnAnError makes ReadMultiBuffer return an error, only once.
func (r *Reader) ReturnAnError(err error) {
	r.pipe.errChan <- err
}

// Recover catches an error set by ReturnAnError, if exists.
func (r *Reader) Recover() (err error) {
	select {
	case err = <-r.pipe.errChan:
	default:
	}
	return
}
