package singbox

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestSingleUserOneMbpsDownloadIsGatedBeforeForward(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, e := target.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		var command [1]byte
		io.ReadFull(c, command[:])
		_, _ = c.Write(make([]byte, 1024*1024))
	}()
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444", SpeedLimit: 1}}
	l := limiter.New()
	l.UpdateUsers(users)
	st := limiter.NewSpeedTracker(l)
	st.UpdateBuckets()
	s := New(config.KernelConfig{LogLevel: "error"})
	s.SetSpeedLimitFunc(st.GetLimiter)
	nc := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: policyFreePort(t), CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "direct"}}}}
	if err := s.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	c := policyDial(t, nc.ServerPort, users[0].UUID, target.Addr().String())
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	started := time.Now()
	c.Write([]byte{1})
	if _, err := io.ReadFull(c, make([]byte, 1024*1024)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 6*time.Second {
		t.Fatalf("single-user 1Mbps download bypassed the gate: %v", elapsed)
	}
	traffic, _, _, err := s.GetUserTraffic(context.Background())
	if err != nil || traffic[1][1] < 1024*1024 {
		t.Fatalf("traffic accounting missing: %v %v", traffic, err)
	}
}
