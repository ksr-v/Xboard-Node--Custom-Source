package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func admissionTracker() *ConnTracker {
	t := NewConnTracker(0)
	t.SetUserMap(map[string]int{"uuid-1": 1})
	t.SetDeviceLimitFunc(func(string) (int, bool) { return 1, true })
	return t
}

func TestAdmissionRejectsLowerIPAndKeepsEstablishedSlot(t *testing.T) {
	tracker := admissionTracker()
	first := tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "127.0.0.3"), nil, nil)
	defer first.Close()
	second := &testConn{}
	tracker.RoutedConnection(context.Background(), second, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	if !second.closed {
		t.Fatal("smaller IP bypassed the established slot")
	}
	_, ips, count := tracker.GetUserTraffic()
	if count != 1 || len(ips[1]) != 1 || !ips[1]["127.0.0.3"] {
		t.Fatalf("existing slot changed: %v, %d", ips, count)
	}
}

func TestAdmissionSimultaneousDistinctIPsNeverOverbook(t *testing.T) {
	tracker := admissionTracker()
	var wg sync.WaitGroup
	start := make(chan struct{})
	accepted := make(chan net.Conn, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			base := &testConn{}
			conn := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", fmt.Sprintf("127.0.0.%d", i+2)), nil, nil)
			if !base.closed {
				accepted <- conn
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(accepted)
	if len(accepted) != 1 {
		t.Fatalf("accepted %d distinct IPs at limit 1", len(accepted))
	}
	for conn := range accepted {
		_ = conn.Close()
	}
	_, ips, count := tracker.GetUserTraffic()
	if count != 0 || len(ips) != 0 {
		t.Fatalf("slots did not release: %v, %d", ips, count)
	}
}

func TestAdmissionCentralReleaseIsOnceAndLocalRejectionCompensates(t *testing.T) {
	tracker := admissionTracker()
	var acquired, released atomic.Int64
	tracker.SetDeviceAdmissionFunc(func(uuid, ip string) (func(), error) {
		if uuid != "uuid-1" || ip == "" {
			t.Error("incorrect admission identity")
		}
		acquired.Add(1)
		return func() { released.Add(1) }, nil
	})
	first := tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "127.0.0.3"), nil, nil)
	second := &testConn{}
	tracker.RoutedConnection(context.Background(), second, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	if !second.closed || acquired.Load() != 2 || released.Load() != 1 {
		t.Fatal("local rejection did not compensate admission")
	}
	_ = first.Close()
	_ = first.Close()
	if released.Load() != 2 {
		t.Fatalf("release called %d times", released.Load())
	}
}

func TestAdmissionCentralFailureDoesNotTakeLocalSlot(t *testing.T) {
	tracker := admissionTracker()
	tracker.SetDeviceAdmissionFunc(func(string, string) (func(), error) { return nil, errors.New("panel unavailable") })
	base := &testConn{}
	tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	if !base.closed {
		t.Fatal("failed central admission was accepted")
	}
	_, ips, count := tracker.GetUserTraffic()
	if len(ips) != 0 || count != 0 {
		t.Fatal("failed request registered a local device")
	}
}

func TestAdmissionRemoteCallDoesNotHoldStatisticsLocks(t *testing.T) {
	tracker := admissionTracker()
	entered, unblock, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	tracker.SetDeviceAdmissionFunc(func(string, string) (func(), error) {
		close(entered)
		<-unblock
		return nil, errors.New("timeout")
	})
	go func() {
		tracker.RoutedConnection(context.Background(), &testConn{}, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
		close(finished)
	}()
	<-entered
	read := make(chan struct{})
	go func() { tracker.GetUserTraffic(); close(read) }()
	select {
	case <-read:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("remote RPC held statistics locks")
	}
	close(unblock)
	<-finished
}

func TestAdmissionUDPAndTCPShareOneDeviceLimit(t *testing.T) {
	tracker := admissionTracker()
	udp := tracker.RoutedPacketConnection(context.Background(), &closeablePacketConn{}, testInboundContext("uuid-1", "127.0.0.3"), nil, nil)
	tcp := &testConn{}
	tracker.RoutedConnection(context.Background(), tcp, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	if !tcp.closed {
		t.Fatal("UDP slot did not constrain another source IP over TCP")
	}
	_ = udp.Close()
	base := &testConn{}
	conn := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	defer conn.Close()
	if base.closed {
		t.Fatal("UDP close did not free the device slot")
	}
}
