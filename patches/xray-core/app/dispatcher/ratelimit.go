package dispatcher

import (
	"context"
	"fmt"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// NodeEndpointBandwidthRevision lets the embedding application reject an
// accidental build against the unpatched historical dependency.
const NodeEndpointBandwidthRevision = 1

// waitBandwidth bounds reservations so large MultiBuffers cannot exceed burst,
// and observes in-place limit changes while an existing stream is waiting.
func waitBandwidth(ctx context.Context, lim *rate.Limiter, n int64) error {
	if lim == nil || n <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for n > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		limit, burst := lim.Limit(), lim.Burst()
		if limit == rate.Inf {
			return nil
		}
		if burst <= 0 || limit <= 0 {
			return fmt.Errorf("invalid bandwidth limiter")
		}
		count := int64(16 * 1024)
		if count > int64(burst) {
			count = int64(burst)
		}
		if count > n {
			count = n
		}
		reservation := lim.ReserveN(time.Now(), int(count))
		if !reservation.OK() {
			// A concurrent burst reduction can invalidate this snapshot.
			continue
		}
		changed := false
		deadline := time.Now().Add(reservation.Delay())
		for delay := time.Until(deadline); delay > 0; delay = time.Until(deadline) {
			if delay > 20*time.Millisecond {
				delay = 20 * time.Millisecond
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				reservation.Cancel()
				return ctx.Err()
			case <-timer.C:
			}
			if lim.Limit() != limit || lim.Burst() != burst {
				reservation.Cancel()
				changed = true
				break
			}
		}
		if !changed {
			n -= count
		}
	}
	return nil
}

type RateLimitWriter struct {
	Writer  buf.Writer
	Limiter *rate.Limiter
	Context context.Context
}

func (w *RateLimitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.Limiter != nil {
		ctx := w.Context
		if ctx == nil {
			ctx = context.Background()
		}
		if err := waitBandwidth(ctx, w.Limiter, int64(mb.Len())); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *RateLimitWriter) Close() error { return common.Close(w.Writer) }
func (w *RateLimitWriter) Interrupt()   { common.Interrupt(w.Writer) }
