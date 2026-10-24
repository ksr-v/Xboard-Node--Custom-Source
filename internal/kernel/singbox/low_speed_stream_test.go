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
	const payloadSize = 1024 * 1024
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- func() error {
			c, err := target.Accept()
			if err != nil {
				return err
			}
			defer c.Close()
			if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
				return err
			}
			var command [1]byte
			if _, err := io.ReadFull(c, command[:]); err != nil {
				return err
			}
			n, err := c.Write(make([]byte, payloadSize))
			if err != nil {
				return err
			}
			if n != payloadSize {
				return io.ErrShortWrite
			}
			return c.Close()
		}()
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
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if n, err := c.Write([]byte{1}); err != nil || n != 1 {
		t.Fatalf("write download command: n=%d err=%v", n, err)
	}
	if _, err := io.ReadFull(c, make([]byte, payloadSize)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 6*time.Second {
		t.Fatalf("single-user 1Mbps download bypassed the gate: %v", elapsed)
	}
	// Receiving the last byte can precede the proxy writer's return and its
	// counter update. The target writer must finish successfully, then the
	// proxy must propagate EOF after completing that final tracked write.
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("target writer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target writer did not finish")
	}
	var tail [1]byte
	if n, err := c.Read(tail[:]); n != 0 || err != io.EOF {
		t.Fatalf("download did not end at EOF: n=%d err=%v", n, err)
	}
	traffic, _, _, err := s.GetUserTraffic(context.Background())
	if err != nil || traffic[1][1] < payloadSize {
		t.Fatalf("traffic accounting missing: %v %v", traffic, err)
	}
}
