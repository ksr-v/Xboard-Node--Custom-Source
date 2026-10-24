package limiter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestWaitNSpliceLargerThanEightMbpsBurst(t *testing.T) {
	lim := rate.NewLimiter(1_000_000, 1_000_000)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	// The Linux splice callback which previously waited for InfDuration.
	if err := WaitN(ctx, lim, 1_048_576); err != nil {
		t.Fatalf("large splice callback did not complete: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond || elapsed > time.Second {
		t.Fatalf("large callback duration = %v, expected finite token wait", elapsed)
	}
}

func TestWaitNSmallBurstLargeTransfer(t *testing.T) {
	lim := rate.NewLimiter(64*1024, 256)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := WaitN(ctx, lim, 16*1024); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("splitting larger-than-burst transfer bypassed the configured rate")
	}
}

func waitUntilReserved(t *testing.T, lim *rate.Limiter) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if lim.Tokens() < 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("worker did not reserve tokens")
}

func TestWaitNDisableWakesExistingReservation(t *testing.T) {
	lim := rate.NewLimiter(1, 1)
	if !lim.Allow() {
		t.Fatal("initial token missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- WaitN(ctx, lim, 1<<20) }()
	waitUntilReserved(t, lim)
	start := time.Now()
	lim.SetLimit(rate.Inf)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > 200*time.Millisecond {
			t.Fatal("existing wait retained the disabled rate")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("disabled rate did not wake the existing stream promptly")
	}
}

func TestWaitNRateIncreaseReevaluatesExistingReservation(t *testing.T) {
	lim := rate.NewLimiter(1, 1)
	_ = lim.Allow()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- WaitN(ctx, lim, 100) }()
	waitUntilReserved(t, lim)
	lim.SetBurst(1024)
	lim.SetLimit(1_000_000)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("existing reservation kept the old one-byte-per-second delay")
	}
}

func TestWaitNRateDecreaseReevaluatesExistingReservation(t *testing.T) {
	lim := rate.NewLimiter(64*1024, 64*1024)
	_ = lim.AllowN(time.Now(), lim.Burst())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- WaitN(ctx, lim, 16*1024) }()
	waitUntilReserved(t, lim)
	lim.SetLimit(16 * 1024)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 800*time.Millisecond {
		t.Fatal("pending transfer used the old, faster reservation after a decrease")
	}
}

func TestWaitNCancellationRefundsReservation(t *testing.T) {
	lim := rate.NewLimiter(1, 1)
	_ = lim.Allow()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- WaitN(ctx, lim, 100) }()
	waitUntilReserved(t, lim)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitN() = %v, want context canceled", err)
	}
	if lim.Tokens() < -0.1 {
		t.Fatal("cancelled transfer left its reservation debt in the user bucket")
	}
}

func TestWaitNConcurrentStreamsShareOneBucket(t *testing.T) {
	const bytesPerSecond = 256 * 1024
	lim := rate.NewLimiter(bytesPerSecond, 1024)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := WaitN(ctx, lim, 32*1024); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed < 450*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("four streams duration = %v, want shared 256 KiB/sec budget", elapsed)
	}
}
