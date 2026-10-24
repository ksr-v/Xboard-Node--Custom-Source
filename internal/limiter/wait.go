package limiter

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

// LimitUpdateInterval bounds how long a pending bandwidth wait can retain an
// old rate after an administrator changes it. This is independent of the panel
// notification/poll interval.
const LimitUpdateInterval = 20 * time.Millisecond

const reservationChunk = 16 * 1024

// WaitN accounts for arbitrary-sized transfers against a shared user bucket.
// Unlike rate.WaitN, it supports n > burst (Linux splice callbacks can exceed
// a megabyte) and re-evaluates pending reservations when limits are changed.
// Keeping reservations small also bounds work attributed to a superseded rate.
func WaitN(ctx context.Context, lim *rate.Limiter, n int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for n > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if lim == nil || lim.Limit() == rate.Inf {
			return nil
		}
		limit, burst := lim.Limit(), lim.Burst()
		if burst <= 0 {
			if err := waitForUpdate(ctx); err != nil {
				return err
			}
			continue
		}
		chunk := int(min(n, int64(min(burst, reservationChunk))))
		r := lim.ReserveN(time.Now(), chunk)
		if !r.OK() {
			// Burst may shrink between the snapshot and ReserveN. Never wait
			// on a failed reservation's InfDuration.
			if err := waitForUpdate(ctx); err != nil {
				return err
			}
			continue
		}
		if delay := r.Delay(); delay > 0 {
			timer := time.NewTimer(delay)
			ticker := time.NewTicker(LimitUpdateInterval)
			changed, err := waitReservation(ctx, timer, ticker, lim, limit, burst)
			timer.Stop()
			ticker.Stop()
			if err != nil || changed {
				r.Cancel()
				if err != nil {
					return err
				}
				continue
			}
		}
		n -= int64(chunk)
	}
	return nil
}

func waitReservation(ctx context.Context, timer *time.Timer, ticker *time.Ticker, lim *rate.Limiter, limit rate.Limit, burst int) (bool, error) {
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
			if lim.Limit() != limit || lim.Burst() != burst {
				return true, nil
			}
		case <-timer.C:
			return lim.Limit() != limit || lim.Burst() != burst, nil
		}
	}
}

func waitForUpdate(ctx context.Context) error {
	timer := time.NewTimer(LimitUpdateInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
