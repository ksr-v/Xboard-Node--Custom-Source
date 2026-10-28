package deviceadmission

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClient struct {
	acquire func(context.Context, string, string, string, int) error
	release func(context.Context, string, string, string) error
}

func (f *fakeClient) AcquireDevice(ctx context.Context, uuid, ip, token string, interval int) error {
	return f.acquire(ctx, uuid, ip, token, interval)
}
func (f *fakeClient) ReleaseDevice(ctx context.Context, uuid, ip, token string) error {
	return f.release(ctx, uuid, ip, token)
}

func TestSameIPConcurrentConnectionsShareOneReservation(t *testing.T) {
	var mu sync.Mutex
	acquires := 0
	released := make(chan string, 2)
	client := &fakeClient{
		acquire: func(_ context.Context, uuid, ip, token string, interval int) error {
			mu.Lock()
			defer mu.Unlock()
			acquires++
			if len(token) != 32 || uuid != "user" || ip != "127.0.0.2" || interval != 5 {
				t.Errorf("unexpected reservation request")
			}
			return nil
		},
		release: func(_ context.Context, _, _, token string) error { released <- token; return nil },
	}
	manager := New(client, 5)
	const connections = 64
	releases := make([]func(), connections)
	var wg sync.WaitGroup
	for i := range releases {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			release, err := manager.Acquire("user", "127.0.0.2")
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			releases[index] = release
		}(i)
	}
	wg.Wait()
	if acquires != 1 {
		t.Fatalf("same IP made %d reservations; want 1", acquires)
	}
	for _, release := range releases[:connections-1] {
		release()
		release()
	}
	select {
	case <-released:
		t.Fatal("released reservation while one same-IP connection remained")
	default:
	}
	releases[connections-1]()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("last connection did not release reservation")
	}
	manager.mu.Lock()
	remaining := len(manager.entries)
	manager.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("unused reservation entries leaked: %d", remaining)
	}
}

func TestSlowIPDoesNotBlockUnrelatedIP(t *testing.T) {
	started, unblock := make(chan struct{}), make(chan struct{})
	client := &fakeClient{
		acquire: func(ctx context.Context, _, ip, _ string, _ int) error {
			if ip == "slow" {
				close(started)
				select {
				case <-unblock:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
		release: func(context.Context, string, string, string) error { return nil },
	}
	manager := New(client, 5)
	firstDone := make(chan error, 1)
	go func() {
		release, err := manager.Acquire("user", "slow")
		if release != nil {
			release()
		}
		firstDone <- err
	}()
	<-started
	secondDone := make(chan error, 1)
	go func() {
		release, err := manager.Acquire("user", "fast")
		if release != nil {
			release()
		}
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("unrelated IP blocked behind network I/O")
	}
	close(unblock)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestLateReleaseKeepsNewGeneration(t *testing.T) {
	var mu sync.Mutex
	var current string
	var tokens []string
	oldStarted, finishOld, oldFinished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	client := &fakeClient{
		acquire: func(_ context.Context, _, _, token string, _ int) error {
			mu.Lock()
			defer mu.Unlock()
			current = token
			tokens = append(tokens, token)
			return nil
		},
		release: func(_ context.Context, _, _, token string) error {
			mu.Lock()
			old := token == tokens[0]
			mu.Unlock()
			if old {
				close(oldStarted)
				<-finishOld
			}
			mu.Lock()
			if current == token {
				current = ""
			}
			mu.Unlock()
			if old {
				close(oldFinished)
			}
			return nil
		},
	}
	manager := New(client, 5)
	first, err := manager.Acquire("user", "same-ip")
	if err != nil {
		t.Fatal(err)
	}
	first()
	<-oldStarted
	second, err := manager.Acquire("user", "same-ip")
	if err != nil {
		t.Fatal(err)
	}
	defer second()
	mu.Lock()
	if len(tokens) != 2 || tokens[0] == tokens[1] {
		t.Fatal("reconnected IP did not receive a new generation")
	}
	newToken := tokens[1]
	mu.Unlock()
	close(finishOld)
	<-oldFinished
	mu.Lock()
	defer mu.Unlock()
	if current != newToken {
		t.Fatal("late release removed the newer connection")
	}
}

func TestDeniedAcquireDoesNotCreateLocalReservation(t *testing.T) {
	client := &fakeClient{
		acquire: func(context.Context, string, string, string, int) error { return errors.New("denied") },
		release: func(context.Context, string, string, string) error { t.Error("denied acquire released"); return nil },
	}
	manager := New(client, 5)
	for i := 0; i < 2; i++ {
		if release, err := manager.Acquire("user", "ip"); err == nil || release != nil {
			t.Fatal("denied IP acquired a local connection")
		}
	}
	if len(manager.entries) != 0 {
		t.Fatal("denied reservation remained cached")
	}
}

func TestQueuedSameIPConnectionsShareUnavailableDecision(t *testing.T) {
	started, fail := make(chan struct{}), make(chan struct{})
	var calls int
	var callsMu sync.Mutex
	client := &fakeClient{
		acquire: func(context.Context, string, string, string, int) error {
			callsMu.Lock()
			calls++
			first := calls == 1
			callsMu.Unlock()
			if first {
				close(started)
				<-fail
			}
			return errors.New("unavailable")
		},
		release: func(context.Context, string, string, string) error { return nil },
	}
	manager := New(client, 5)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := manager.Acquire("user", "ip"); err == nil {
				t.Error("unavailable decision accepted")
			}
		}()
	}
	<-started
	deadline := time.Now().Add(time.Second)
	for {
		manager.mu.Lock()
		borrowers := manager.entries[key{"user", "ip"}].borrowers
		manager.mu.Unlock()
		if borrowers == 32 {
			break
		}
		if time.Now().After(deadline) {
			close(fail)
			t.Fatal("concurrent callers did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	close(fail)
	wg.Wait()
	if calls != 1 {
		t.Fatalf("same-IP failure caused %d serial RPCs; want 1", calls)
	}
}

func TestReleaseRetriesSameGenerationAfterTransientFailures(t *testing.T) {
	var acquiredToken string
	var attempts atomic.Int64
	finished := make(chan struct{})
	client := &fakeClient{
		acquire: func(_ context.Context, _, _, token string, _ int) error {
			acquiredToken = token
			return nil
		},
		release: func(ctx context.Context, _, _, token string) error {
			if token != acquiredToken {
				t.Error("release retry changed generation")
			}
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Second {
				t.Error("release RPC is not bounded by two seconds")
			}
			if attempts.Add(1) < 3 {
				return errors.New("lost packet")
			}
			close(finished)
			return nil
		},
	}
	manager := New(client, 5)
	release, err := manager.Acquire("user", "ip")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	release()
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("connection close blocked on release retries")
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("bounded release retries did not recover")
	}
	if attempts.Load() != 3 {
		t.Fatalf("release attempts = %d; want 3", attempts.Load())
	}
}
