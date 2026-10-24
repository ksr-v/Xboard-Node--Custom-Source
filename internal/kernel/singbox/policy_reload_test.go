package singbox

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/net/proxy"
)

// Every endpoint in these tests is a process-local loopback listener. No public
// DNS, proxy service, dependency download, or privileged port is involved.
func policyListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func policyPort(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }

func policyFreePort(t *testing.T) int {
	l := policyListener(t)
	p := policyPort(l)
	_ = l.Close()
	return p
}

func policyEcho(t *testing.T) net.Listener {
	l := policyListener(t)
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

// policyOutbound is a tiny SOCKS endpoint that echoes its identity for every
// received byte, allowing tests to observe the selected outbound directly.
func policyOutbound(t *testing.T, marker byte) net.Listener {
	l := policyListener(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				h := make([]byte, 2)
				if _, err := io.ReadFull(c, h); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(h[1])); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				h = make([]byte, 4)
				if _, err := io.ReadFull(c, h); err != nil {
					return
				}
				var n int
				switch h[3] {
				case 1:
					n = 4
				case 4:
					n = 16
				case 3:
					b := make([]byte, 1)
					if _, err := io.ReadFull(c, b); err != nil {
						return
					}
					n = int(b[0])
				default:
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(n+2)); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, e := c.Write(bytes.Repeat([]byte{marker}, n)); e != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return l
}

func policyDial(t *testing.T, port int, uuid, target string) net.Conn {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &proxy.Auth{User: uuid, Password: uuid}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	return c
}

func policyExchange(t *testing.T, c net.Conn, want string) {
	t.Helper()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Fatalf("outbound returned %q; want %q", b, want)
	}
}

func policyClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1)
	if n, err := c.Read(b); n != 0 || err == nil {
		t.Fatalf("previous flow survived routing update: n=%d err=%v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("previous flow remained open after routing update")
	}
}

func TestPolicyReloadAddsChangesRemovesOutboundsAndBlocksLiveFlow(t *testing.T) {
	echo := policyEcho(t)
	a, b := policyOutbound(t, 'A'), policyOutbound(t, 'B')
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	initial := &model.NodeSpec{Protocol: "socks", ServerPort: policyFreePort(t), CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "direct"}}}}
	s := New(config.KernelConfig{LogLevel: "error"})
	if err := s.Start(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	tracker := s.connTracker
	live := policyDial(t, initial.ServerPort, users[0].UUID, echo.Addr().String())
	policyExchange(t, live, "ping")
	before, _, _ := tracker.GetUserTraffic()
	for _, tc := range []struct {
		port int
		want string
	}{{policyPort(a), "AAAA"}, {policyPort(b), "BBBB"}} {
		next := *initial
		next.CustomOutbounds = []model.OutboundConfig{{Tag: "test-hop", Protocol: "socks", Settings: map[string]any{"server": "127.0.0.1", "server_port": tc.port, "version": "5"}}}
		next.CustomRouteRules = []model.CustomRouteRule{{Match: model.RouteMatch{Ports: []string{fmt.Sprint(policyPort(echo))}}, Action: model.RouteAction{Type: "route", Target: "test-hop"}}}
		oldBox := s.box
		started := time.Now()
		if err := s.Reload(&next, users, kernel.TLSCert{}); err != nil {
			t.Fatal(err)
		}
		if time.Since(started) > 2*time.Second {
			t.Fatal("routing reload waited for graceful drain")
		}
		if s.box == oldBox {
			t.Fatal("routing change retained stale outbound manager")
		}
		policyClosed(t, live)
		live = policyDial(t, initial.ServerPort, users[0].UUID, echo.Addr().String())
		policyExchange(t, live, tc.want)
	}
	if err := s.Reload(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	policyClosed(t, live)
	live = policyDial(t, initial.ServerPort, users[0].UUID, echo.Addr().String())
	policyExchange(t, live, "ping")
	if s.connTracker != tracker {
		t.Fatal("routing reload reset cumulative tracker")
	}
	after, _, _ := tracker.GetUserTraffic()
	if after[1][0] < before[1][0] || after[1][1] < before[1][1] {
		t.Fatal("routing reload lost traffic counters")
	}
	blocked := *initial
	blocked.CustomRouteRules = []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "block"}}}
	if err := s.Reload(&blocked, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	policyClosed(t, live)
	// SOCKS may acknowledge before asynchronous routing rejects; either an
	// immediate dial error or closed stream is valid, but an echo is not.
	d, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", initial.ServerPort), &proxy.Auth{User: users[0].UUID, Password: users[0].UUID}, &net.Dialer{Timeout: time.Second})
	c, err := d.Dial("tcp", echo.Addr().String())
	if err == nil {
		defer c.Close()
		policyClosed(t, c)
	}
}

func TestPolicyReloadStartupFailureRestoresPreviousConfigAndLatestUsers(t *testing.T) {
	t.Run("missing-outbound-dependency", func(t *testing.T) { policyRollback(t, false) })
	t.Run("occupied-listen-port", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows permits socket reuse; conflicting bind is covered on Linux")
		}
		policyRollback(t, true)
	})
}

func policyRollback(t *testing.T, failBind bool) {
	echo := policyEcho(t)
	// The generated inbound listens on IPv6 wildcard. Occupy that exact socket
	// family rather than an IPv4 loopback port (which may coexist on Windows).
	occupied, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	initial := &model.NodeSpec{Protocol: "socks", ServerPort: policyFreePort(t), CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "direct"}}}}
	s := New(config.KernelConfig{LogLevel: "error"})
	if err := s.Start(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	additional := model.UserSpec{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888"}
	// User-only hot updates must not mark a changed custom file's policy as
	// already applied. A failed later full reload must restore the real policy.
	s.cfg.CustomConfig = filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(s.cfg.CustomConfig, []byte(`{"route":{"rules":[{"ip_cidr":["127.0.0.0/8"],"outbound":"block"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUsers([]model.UserSpec{additional}); err != nil {
		t.Fatal(err)
	}
	users = append(users, additional)
	oldPolicy := append([]byte(nil), s.activePolicy...)
	bad := *initial
	if failBind {
		bad.ServerPort = policyPort(occupied)
	} else {
		bad.CustomOutbounds = []model.OutboundConfig{{Tag: "broken-hop", Protocol: "socks", Settings: map[string]any{"server": "127.0.0.1", "server_port": 1, "version": "5", "detour": "missing-hop"}}}
	}
	bad.CustomRouteRules = []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "block"}}}
	err = s.Reload(&bad, users, kernel.TLSCert{})
	if err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
		t.Fatalf("expected explicit rollback result, got %v", err)
	}
	if !s.IsRunning() || !bytes.Equal(oldPolicy, s.activePolicy) {
		t.Fatal("failed reload replaced running policy")
	}
	live := policyDial(t, initial.ServerPort, additional.UUID, echo.Addr().String())
	policyExchange(t, live, "ping")
}

func TestPolicyReloadInvalidCandidateLeavesLiveConnectionUntouched(t *testing.T) {
	echo := policyEcho(t)
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	initial := &model.NodeSpec{Protocol: "socks", ServerPort: policyFreePort(t), CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "direct"}}}}
	s := New(config.KernelConfig{LogLevel: "error"})
	if err := s.Start(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	live := policyDial(t, initial.ServerPort, users[0].UUID, echo.Addr().String())
	policyExchange(t, live, "ping")
	oldBox := s.box
	bad := *initial
	bad.CustomOutbounds = []model.OutboundConfig{{Tag: "invalid", Protocol: "not-a-real-outbound"}}
	if err := s.Reload(&bad, users, kernel.TLSCert{}); err == nil {
		t.Fatal("invalid outbound accepted")
	}
	if s.box != oldBox {
		t.Fatal("invalid candidate disrupted the running kernel")
	}
	policyExchange(t, live, "ping")
	if err := s.Reload(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	if s.box != oldBox {
		t.Fatal("unchanged policy restarted the kernel")
	}
}
