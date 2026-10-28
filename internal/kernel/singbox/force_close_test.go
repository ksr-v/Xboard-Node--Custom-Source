package singbox

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestForceCloseUserClosesTCPUDPAndKeepsOtherUsers(t *testing.T) {
	tracker := admissionTracker()
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})
	var releases atomic.Int64
	tracker.SetDeviceAdmissionFunc(func(string, string) (func(), error) { return func() { releases.Add(1) }, nil })
	server, peer := net.Pipe()
	defer peer.Close()
	tcp := tracker.RoutedConnection(context.Background(), server, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	packet := &closeablePacketConn{}
	udp := tracker.RoutedPacketConnection(context.Background(), packet, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	otherBase := &testConn{}
	other := tracker.RoutedConnection(context.Background(), otherBase, testInboundContext("uuid-2", "127.0.0.3"), nil, nil)
	defer other.Close()
	readDone, writeDone := make(chan struct{}), make(chan struct{})
	go func() { _, _ = peer.Read(make([]byte, 1)); close(readDone) }()
	go func() { _, _ = peer.Write([]byte("held response")); close(writeDone) }()
	s := New(config.KernelConfig{})
	s.connTracker = tracker
	if err := s.CloseUserConnections(context.Background(), "uuid-1"); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan struct{}{readDone, writeDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("TCP direction remained blocked")
		}
	}
	if !packet.closed.Load() || otherBase.closed || releases.Load() != 2 {
		t.Fatal("selective close or release count incorrect")
	}
	_ = tcp.Close()
	_ = udp.Close()
	if tracker.CloseByUUID("uuid-1") != 0 || releases.Load() != 2 {
		t.Fatal("repeated close released admission twice")
	}
	if _, ips, count := tracker.GetUserTraffic(); count != 1 || len(ips[1]) != 0 || !ips[2]["127.0.0.3"] {
		t.Fatalf("wrong remaining users: %v %d", ips, count)
	}
}

func TestForceCloseInvalidatesPendingAdmissionAndRemovedIdentity(t *testing.T) {
	tracker := admissionTracker()
	entered, resume := make(chan struct{}), make(chan struct{})
	var releases atomic.Int64
	tracker.SetDeviceAdmissionFunc(func(string, string) (func(), error) { close(entered); <-resume; return func() { releases.Add(1) }, nil })
	base := &testConn{}
	finished := make(chan struct{})
	go func() {
		tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
		close(finished)
	}()
	<-entered
	tracker.CloseByUUID("uuid-1")
	close(resume)
	<-finished
	if !base.closed || releases.Load() != 1 || tracker.ActiveCount() != 0 {
		t.Fatal("pending admission survived forced close")
	}
	tracker.SetDeviceAdmissionFunc(nil)
	old := &testConn{}
	tracker.RoutedConnection(context.Background(), old, testInboundContext("uuid-1", "127.0.0.2"), nil, nil)
	tracker.SetUserMap(map[string]int{"uuid-replaced": 1})
	if !old.closed || tracker.ActiveCount() != 0 {
		t.Fatal("identity replacement left an old connection alive")
	}
}
