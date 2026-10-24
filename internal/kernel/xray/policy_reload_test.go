package xray

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	vencoding "github.com/xtls/xray-core/proxy/vless/encoding"
)

func xrayPolicyListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func xrayPolicyEcho(t *testing.T) net.Listener {
	l := xrayPolicyListener(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l
}

func xrayPolicyDial(t *testing.T, port int, uuid, target string) net.Conn {
	return xrayPolicyDialCommand(t, port, uuid, target, protocol.RequestCommandTCP)
}

func xrayPolicyDialCommand(t *testing.T, port int, uuid, target string, command protocol.RequestCommand) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	targetPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	user, err := toMemoryUser("vless", &model.NodeSpec{Protocol: "vless"}, model.UserSpec{ID: 1, UUID: uuid})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := vencoding.EncodeRequestHeader(c, &protocol.RequestHeader{Version: 0, Command: command, Address: xnet.ParseAddress(host), Port: xnet.Port(targetPort), User: user}, &vencoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	return &xrayPolicyVLESSConn{Conn: c}
}

func TestXrayPolicyReloadClosesIdleUDPAssociation(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		b := make([]byte, 1024)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(b[:n], a)
		}
	}()
	nc, users := xrayPolicyNode(t)
	x := New(config.KernelConfig{Type: "xray", LogLevel: "error"})
	if err := x.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.Stop)
	live := xrayPolicyDialCommand(t, nc.ServerPort, users[0].UUID, udp.LocalAddr().String(), protocol.RequestCommandUDP)
	if _, err := live.Write([]byte{0, 4, 'p', 'i', 'n', 'g'}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	if _, err := io.ReadFull(live, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != string([]byte{0, 4, 'p', 'i', 'n', 'g'}) {
		t.Fatalf("unexpected UDP response: %v", b)
	}
	blocked := *nc
	blocked.CustomRouteRules = []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "block"}}}
	if err := x.Reload(&blocked, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	_ = live.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := live.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("old UDP association survived: n=%d err=%v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("old UDP association remained open")
	}
}

type xrayPolicyVLESSConn struct {
	net.Conn
	responseRead bool
}

func (c *xrayPolicyVLESSConn) Read(b []byte) (int, error) {
	if !c.responseRead {
		h := make([]byte, 2)
		if _, err := io.ReadFull(c.Conn, h); err != nil {
			return 0, err
		}
		if h[1] > 0 {
			if _, err := io.CopyN(io.Discard, c.Conn, int64(h[1])); err != nil {
				return 0, err
			}
		}
		c.responseRead = true
	}
	return c.Conn.Read(b)
}

func xrayPolicyExchange(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "ping" {
		t.Fatalf("unexpected echo: %q", b)
	}
}

func xrayPolicyNode(t *testing.T) (*model.NodeSpec, []model.UserSpec) {
	l := xrayPolicyListener(t)
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port, CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "direct"}}}}, []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
}

func TestXrayPolicyReloadClosesIdleFlowAndPreservesCounters(t *testing.T) {
	echo := xrayPolicyEcho(t)
	nc, users := xrayPolicyNode(t)
	x := New(config.KernelConfig{Type: "xray", LogLevel: "error"})
	if err := x.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.Stop)
	live := xrayPolicyDial(t, nc.ServerPort, users[0].UUID, echo.Addr().String())
	xrayPolicyExchange(t, live)
	old := x.instance
	before, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before[1][0] == 0 || before[1][1] == 0 {
		t.Fatalf("expected measured traffic in both directions, got %v", before)
	}
	// Leave additional bytes uncollected in the old core's counters.
	xrayPolicyExchange(t, live)
	blocked := *nc
	blocked.CustomRouteRules = []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "block"}}}
	start := time.Now()
	if err := x.Reload(&blocked, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("policy replacement waited %v", elapsed)
	}
	if x.instance == old {
		t.Fatal("policy update kept old kernel")
	}
	_ = live.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := live.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("idle old flow survived: n=%d err=%v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("cancelled old flow did not close while idle")
	}
	after, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after[1][0] <= before[1][0] || after[1][1] <= before[1][1] {
		t.Fatalf("cumulative traffic lost: before=%v after=%v", before, after)
	}
	if err := x.Reload(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	live = xrayPolicyDial(t, nc.ServerPort, users[0].UUID, echo.Addr().String())
	xrayPolicyExchange(t, live)
	old = x.instance
	users[0].SpeedLimit = 8
	if err := x.Reload(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	if x.instance != old {
		t.Fatal("limit-only update replaced the kernel")
	}
	xrayPolicyExchange(t, live)
}

func TestXrayPolicyStartupFailureRestoresLatestUsersAndRunningPolicy(t *testing.T) {
	echo := xrayPolicyEcho(t)
	nc, users := xrayPolicyNode(t)
	x := New(config.KernelConfig{Type: "xray", LogLevel: "error"})
	if err := x.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.Stop)
	// Unapplied edits in a local custom file must not replace the saved policy
	// when refreshing rollback credentials after a UserManager update.
	x.cfg.CustomConfig = filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(x.cfg.CustomConfig, []byte(`{"routing":{"rules":[{"type":"field","ip":["127.0.0.0/8"],"outboundTag":"block"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	u := model.UserSpec{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888"}
	if _, err := x.AddUsers([]model.UserSpec{u}); err != nil {
		t.Fatal(err)
	}
	users = append(users, u)
	live := xrayPolicyDial(t, nc.ServerPort, u.UUID, echo.Addr().String())
	xrayPolicyExchange(t, live)
	bad := *nc
	// Reserved documentation address is not assigned to any test interface.
	// Parsing succeeds, then the real listener bind fails and exercises rollback.
	bad.ListenIP = "192.0.2.254"
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range ifaces {
		if strings.HasPrefix(a.String(), bad.ListenIP+"/") {
			t.Skip("documentation IP is assigned locally")
		}
	}
	err = x.Reload(&bad, users, kernel.TLSCert{})
	if err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
		t.Fatalf("expected explicit successful rollback, got %v", err)
	}
	if !x.IsRunning() {
		t.Fatal("previous kernel was not restored")
	}
	live = xrayPolicyDial(t, nc.ServerPort, u.UUID, echo.Addr().String())
	xrayPolicyExchange(t, live)
}

func TestXrayPolicyInvalidCandidatePreservesLiveFlow(t *testing.T) {
	echo := xrayPolicyEcho(t)
	nc, users := xrayPolicyNode(t)
	x := New(config.KernelConfig{Type: "xray", LogLevel: "error"})
	if err := x.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.Stop)
	live := xrayPolicyDial(t, nc.ServerPort, users[0].UUID, echo.Addr().String())
	xrayPolicyExchange(t, live)
	old := x.instance
	invalid := *nc
	invalid.CustomOutbounds = []model.OutboundConfig{{Tag: "invalid", Protocol: "not-a-real-protocol"}}
	if err := x.Reload(&invalid, users, kernel.TLSCert{}); err == nil {
		t.Fatal("invalid outbound accepted")
	}
	if x.instance != old {
		t.Fatal("invalid candidate disrupted old kernel")
	}
	xrayPolicyExchange(t, live)
}
