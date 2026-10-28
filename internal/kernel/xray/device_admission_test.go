package xray

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

func limitedDispatcher() *LimitDispatcher {
	ld := newTestDispatcher()
	applyDispatcherLimits(ld, []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1}})
	return ld
}

func TestAdmissionRejectsLowerIPAndIdentityAliasesShareSlots(t *testing.T) {
	ld := limitedDispatcher()
	if ld.checkDeviceLimit(userEmail(1), "127.0.0.3", true) {
		t.Fatal("first IP rejected")
	}
	if !ld.checkDeviceLimit("uuid-1", "127.0.0.2", true) {
		t.Fatal("lower IP or UUID alias bypassed limit")
	}
	if ld.checkDeviceLimit("uuid-1", "127.0.0.3", true) {
		t.Fatal("same source IP rejected")
	}
	ld.delConn("uuid-1", "127.0.0.3")
	if !ld.checkDeviceLimit(userEmail(1), "127.0.0.2", true) {
		t.Fatal("one close freed another held connection")
	}
	ld.delConn(userEmail(1), "127.0.0.3")
	if ld.checkDeviceLimit(userEmail(1), "127.0.0.2", true) {
		t.Fatal("last close failed to release slot")
	}
}

func TestAdmissionSimultaneousDistinctIPsNeverOverbook(t *testing.T) {
	ld := limitedDispatcher()
	var wg sync.WaitGroup
	var accepted atomic.Int64
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if !ld.checkDeviceLimit(userEmail(1), fmt.Sprintf("127.0.0.%d", i+2), true) {
				accepted.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d IPs at limit 1", accepted.Load())
	}
}

func TestAdmissionLimitChangesKeepExistingUnlimitedConnections(t *testing.T) {
	ld := limitedDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, nil)
	ld.checkDeviceLimit(userEmail(1), "127.0.0.2", true)
	ld.checkDeviceLimit(userEmail(1), "127.0.0.3", true)
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, map[string]int{userEmail(1): 1}, nil)
	if !ld.checkDeviceLimit(userEmail(1), "127.0.0.4", true) {
		t.Fatal("pre-existing unlimited IPs were lost")
	}
	ld.delConn(userEmail(1), "127.0.0.2")
	ld.delConn(userEmail(1), "127.0.0.3")
	if ld.checkDeviceLimit(userEmail(1), "127.0.0.4", true) {
		t.Fatal("old unlimited connections did not release")
	}
}

func TestAdmissionUsesGlobalSnapshotWithoutIPOrderDisplacement(t *testing.T) {
	ld := limitedDispatcher()
	ld.UpdateGlobalDevices(map[int][]string{1: {"127.0.0.3"}})
	if !ld.checkDeviceLimit(userEmail(1), "127.0.0.2", true) {
		t.Fatal("new lower IP displaced global slot")
	}
	if ld.checkDeviceLimit(userEmail(1), "127.0.0.3", true) {
		t.Fatal("globally admitted IP was rejected")
	}
	ld.delConn(userEmail(1), "127.0.0.3")
	ld.ClearGlobalDevices()
	if ld.checkDeviceLimit(userEmail(1), "127.0.0.2", true) {
		t.Fatal("cleared global snapshot remained active")
	}
}

func admissionContext(ip string) (context.Context, xnet.Destination) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		User:   &protocol.MemoryUser{Email: userEmail(1)},
		Source: xnet.TCPDestination(xnet.ParseAddress(ip), xnet.Port(12345)),
	})
	return ctx, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(80))
}

func TestAdmissionCentralUsesRealUUIDAndReleasesExactlyOnce(t *testing.T) {
	ld := limitedDispatcher()
	var released atomic.Int64
	ld.SetDeviceAdmissionFunc(func(uuid, ip string) (func(), error) {
		if uuid != "uuid-1" || ip != "127.0.0.2" {
			t.Errorf("incorrect identity: %q %q", uuid, ip)
		}
		return func() { released.Add(1) }, nil
	})
	ctx, dest := admissionContext("127.0.0.2")
	email, ip, _, release, err := ld.identifyAndCheck(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	link := &transport.Link{Reader: nopReader{}, Writer: buf.Discard}
	active, _ := ld.beginLink(ctx, email, ip, release)
	active.attach(link)
	active.close()
	active.close()
	ld.CloseByUUID("uuid-1")
	if released.Load() != 1 {
		t.Fatalf("released %d times", released.Load())
	}
	if ips, _ := ld.GetConnectionState(); len(ips) != 0 {
		t.Fatalf("closed device still tracked: %v", ips)
	}
}

type failedAdmissionDispatcher struct{}

func (failedAdmissionDispatcher) Type() interface{} { return routing.DispatcherType() }
func (failedAdmissionDispatcher) Start() error      { return nil }
func (failedAdmissionDispatcher) Close() error      { return nil }
func (failedAdmissionDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, errors.New("dial failed")
}
func (failedAdmissionDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("dial failed")
}

func TestAdmissionFailedInnerDispatchCompensatesCentralAndLocal(t *testing.T) {
	for _, withLink := range []bool{false, true} {
		ld := limitedDispatcher()
		ld.innerDisp = failedAdmissionDispatcher{}
		var released atomic.Int64
		ld.SetDeviceAdmissionFunc(func(string, string) (func(), error) { return func() { released.Add(1) }, nil })
		ctx, dest := admissionContext("127.0.0.2")
		var err error
		if withLink {
			err = ld.DispatchLink(ctx, dest, &transport.Link{Reader: nopReader{}, Writer: buf.Discard})
		} else {
			_, err = ld.Dispatch(ctx, dest)
		}
		if err == nil || released.Load() != 1 {
			t.Fatalf("withLink=%v: err=%v releases=%d", withLink, err, released.Load())
		}
		if ips, _ := ld.GetConnectionState(); len(ips) != 0 {
			t.Fatalf("failed inner dispatch leaked slot: %v", ips)
		}
	}
}

func TestAdmissionCentralErrorFailsClosed(t *testing.T) {
	ld := limitedDispatcher()
	ld.SetDeviceAdmissionFunc(func(string, string) (func(), error) { return nil, errors.New("timeout") })
	ctx, dest := admissionContext("127.0.0.2")
	if _, _, _, _, err := ld.identifyAndCheck(ctx, dest); err == nil {
		t.Fatal("central timeout was allowed")
	}
	if ips, _ := ld.GetConnectionState(); len(ips) != 0 {
		t.Fatal("central timeout took a local slot")
	}
}

func TestAdmissionUDPAndTCPShareOneDeviceLimit(t *testing.T) {
	ld := limitedDispatcher()
	if ld.checkDeviceLimit(userEmail(1), "127.0.0.3", false) {
		t.Fatal("first UDP IP rejected")
	}
	if !ld.checkDeviceLimit(userEmail(1), "127.0.0.2", true) {
		t.Fatal("TCP bypassed held UDP device")
	}
	ld.delConn(userEmail(1), "127.0.0.3")
	if ld.checkDeviceLimit(userEmail(1), "127.0.0.2", false) {
		t.Fatal("UDP close did not release slot")
	}
}

func TestAdmissionSnapshotsAreSafeDuringConcurrentClose(t *testing.T) {
	ld := limitedDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ip := fmt.Sprintf("127.0.0.%d", i+2)
				ld.checkDeviceLimit(userEmail(1), ip, true)
				ld.GetConnectionState()
				ld.delConn(userEmail(1), ip)
			}
		}(i)
	}
	wg.Wait()
}
