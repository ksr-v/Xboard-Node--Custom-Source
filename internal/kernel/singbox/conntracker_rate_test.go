package singbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	"golang.org/x/time/rate"
)

func TestCountFuncHandlesSpliceLargerThanBurst(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := &trackedConn{ctx: ctx, limiter: rate.NewLimiter(1_000_000, 1_000_000)}
	var counter atomic.Int64
	start := time.Now()
	c.makeCountFunc(&counter)(1_048_576)
	if err := ctx.Err(); err != nil {
		t.Fatalf("8 Mbps splice callback waited until cancellation: %v", err)
	}
	if counter.Load() != 1_048_576 || time.Since(start) < 30*time.Millisecond {
		t.Fatal("splice callback must count and throttle the full large transfer")
	}
}

func TestExistingUnwrappedStreamFollowsEnableAndDisable(t *testing.T) {
	l := limiter.New()
	st := limiter.NewSpeedTracker(l)
	update := func(speed int) {
		l.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "u1", SpeedLimit: speed}})
		st.UpdateBuckets()
	}
	update(0)
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"u1": 1})
	tracker.SetSpeedLimitFunc(st.GetLimiter)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := tracker.RoutedConnection(ctx, &testConn{}, testInboundContext("u1", "1.1.1.1"), nil, nil).(*trackedConn)
	defer c.Close()
	writer, counters := c.UnwrapWriter()
	if len(counters) != 0 || c.ReaderReplaceable() || c.WriterReplaceable() {
		t.Fatal("known user's gate must not be bypassed by post-copy counters or raw socket unwrapping")
	}
	count := func(n int64) {
		if _, err := writer.Write(make([]byte, int(n))); err != nil {
			t.Fatal(err)
		}
	}
	count(1024)
	update(1)
	if !c.limiter.AllowN(time.Now(), int(c.limiter.Tokens())) {
		t.Fatal("failed to consume newly enabled limiter's available tokens")
	}
	start := time.Now()
	count(64 * 1024)
	if time.Since(start) < 450*time.Millisecond {
		t.Fatal("already established stream ignored the enabled speed limit")
	}
	update(0)
	start = time.Now()
	count(1 << 20)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("already established stream retained its disabled speed limit")
	}
}

func TestLimitedWriterDoesNotSilentlyTruncateLargeWrites(t *testing.T) {
	var got bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	w := RateLimitedWriter{writer: &got, ctx: ctx, limiter: rate.NewLimiter(1_000_000, 1_000_000)}
	want := bytes.Repeat([]byte("x"), 1_048_576)
	if n, err := w.Write(want); err != nil || n != len(want) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(want))
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("writer dropped bytes above the configured burst")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func TestLimitedWriterReportsUnderlyingShortWrite(t *testing.T) {
	w := RateLimitedWriter{writer: shortWriter{}, ctx: context.Background()}
	if n, err := w.Write([]byte("abc")); n != 2 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() = (%d, %v), want (2, io.ErrShortWrite)", n, err)
	}
}

type closeablePacketConn struct {
	closed atomic.Bool
}

func (c *closeablePacketConn) Close() error                     { c.closed.Store(true); return nil }
func (c *closeablePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *closeablePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *closeablePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeablePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *closeablePacketConn) ReadPacket(*buf.Buffer) (singM.Socksaddr, error) {
	return singM.Socksaddr{}, io.EOF
}
func (c *closeablePacketConn) WritePacket(*buf.Buffer, singM.Socksaddr) error { return nil }

func TestCloseAllClosesTCPUDPAndCancelsPendingWaits(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"u1": 1})
	lim := rate.NewLimiter(1, 1)
	_ = lim.Allow()
	tracker.SetSpeedLimitFunc(func(string) *rate.Limiter { return lim })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	base := &testConn{}
	tcp := tracker.RoutedConnection(ctx, base, testInboundContext("u1", "1.1.1.1"), nil, nil).(*trackedConn)
	packet := &closeablePacketConn{}
	udp := tracker.RoutedPacketConnection(ctx, packet, testInboundContext("u1", "1.1.1.1"), nil, nil).(*trackedPacketConn)
	waitDone := make(chan struct{})
	go func() {
		writer, _ := tcp.UnwrapWriter()
		_, _ = writer.Write(make([]byte, 1<<20))
		close(waitDone)
	}()
	deadline := time.Now().Add(time.Second)
	for lim.Tokens() >= 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	closed := make(chan int, 1)
	go func() { closed <- tracker.CloseAll() }()
	select {
	case count := <-closed:
		if count != 2 || !base.closed || !packet.closed.Load() {
			t.Fatal("routing invalidation did not close both TCP and UDP transports")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("CloseAll deadlocked while tracked Close re-entered the registry")
	}
	select {
	case <-waitDone:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("closed transport retained its pending bandwidth reservation")
	}
	if tcp.ctx.Err() == nil || udp.ctx.Err() == nil || tracker.ActiveCount() != 0 || tracker.CloseAll() != 0 {
		t.Fatal("routing invalidation did not release connection state")
	}
}
