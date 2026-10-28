package singbox

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/sys/unix"
)

func socketPort(sa unix.Sockaddr) int {
	switch address := sa.(type) {
	case *unix.SockaddrInet4:
		return address.Port
	case *unix.SockaddrInet6:
		return address.Port
	default:
		return 0
	}
}

func TestAcceptedTCPSocketUsesNativeKeepalive(t *testing.T) {
	echo := policyEcho(t)
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	nc := &model.NodeSpec{Protocol: "socks", ServerPort: policyFreePort(t), CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "direct"}}}}
	s := New(config.KernelConfig{LogLevel: "error"})
	if err := s.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	conn := policyDial(t, nc.ServerPort, users[0].UUID, echo.Addr().String())
	policyExchange(t, conn, "ping")
	peerPort := conn.LocalAddr().(*net.TCPAddr).Port
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		files, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			fd, err := strconv.Atoi(file.Name())
			if err != nil {
				continue
			}
			local, err := unix.Getsockname(fd)
			if err != nil || socketPort(local) != nc.ServerPort {
				continue
			}
			peer, err := unix.Getpeername(fd)
			if err != nil || socketPort(peer) != peerPort {
				continue
			}
			enabled, e1 := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE)
			idle, e2 := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)
			interval, e3 := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL)
			probes, e4 := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_KEEPCNT)
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || enabled != 1 || idle != 10 || interval != 3 || probes <= 0 || probes > 9 {
				t.Fatalf("native options: enabled=%d idle=%d interval=%d probes=%d errors=%v/%v/%v/%v", enabled, idle, interval, probes, e1, e2, e3, e4)
			}
			t.Logf("accepted socket: keepalive idle=%ds interval=%ds probes=%d", idle, interval, probes)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("accepted TCP socket was not found")
}
