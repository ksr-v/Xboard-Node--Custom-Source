package singbox

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func inboundReloadNode(protocol string, port int) *model.NodeSpec {
	return &model.NodeSpec{Protocol: protocol, ServerPort: port, CustomRouteRules: []model.CustomRouteRule{{
		Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8"}}, Action: model.RouteAction{Type: "direct"},
	}}}
}

func inboundUnappliedLocalPolicy(t *testing.T, s *SingBox) {
	t.Helper()
	s.cfg.CustomConfig = filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(s.cfg.CustomConfig, []byte(`{"route":{"rules":[{"ip_cidr":["127.0.0.0/8"],"outbound":"block"}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
}

func inboundHTTPTunnel(t *testing.T, port int, uuid, target string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte(uuid + ":" + uuid))
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, auth); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP proxy returned %s", response.Status)
	}
	return c
}

// A bad TLS replacement used to remove the working listener before discovering
// the error, while IsRunning still returned true. Real existing/new TCP flows
// must both keep working when candidate construction fails.
func TestInboundOnlyReloadInvalidTLSRetainsLiveListener(t *testing.T) {
	echo := policyEcho(t)
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	initial := inboundReloadNode("http", policyFreePort(t))
	s := New(config.KernelConfig{LogLevel: "error"})
	if err := s.Start(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	live := inboundHTTPTunnel(t, initial.ServerPort, users[0].UUID, echo.Addr().String())
	policyExchange(t, live, "ping")
	oldBox := s.box
	oldConfig := append([]byte(nil), s.activeConfig...)
	bad := *initial
	bad.TLS = 1
	err := s.Reload(&bad, users, kernel.TLSCert{CertPEM: []byte("invalid certificate"), KeyPEM: []byte("invalid key")})
	if err == nil {
		t.Fatal("invalid TLS replacement accepted")
	}
	if s.box != oldBox || !s.IsRunning() || !bytes.Equal(s.activeConfig, oldConfig) {
		t.Fatal("invalid TLS replacement disturbed the accepted configuration")
	}
	policyExchange(t, live, "ping")
	policyExchange(t, inboundHTTPTunnel(t, initial.ServerPort, users[0].UUID, echo.Addr().String()), "ping")
}

func TestInboundOnlyReloadStartupFailureRestoresListenerAndLatestUsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permits socket reuse; conflicting bind requires Linux")
	}
	echo := policyEcho(t)
	occupied, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	initial := inboundReloadNode("socks", policyFreePort(t))
	s := New(config.KernelConfig{LogLevel: "error"})
	if err := s.Start(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	additional := model.UserSpec{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888"}
	if _, err := s.AddUsers([]model.UserSpec{additional}); err != nil {
		t.Fatal(err)
	}
	users = append(users, additional)
	live := policyDial(t, initial.ServerPort, additional.UUID, echo.Addr().String())
	policyExchange(t, live, "ping")
	bad := *initial
	bad.ServerPort = policyPort(occupied)
	err = s.Reload(&bad, users, kernel.TLSCert{})
	if err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
		t.Fatalf("expected explicit listener rollback, got %v", err)
	}
	if !s.IsRunning() || s.nodeConfig.ServerPort != initial.ServerPort {
		t.Fatal("failed listener reload did not restore the accepted configuration")
	}
	policyClosed(t, live)
	policyExchange(t, policyDial(t, initial.ServerPort, additional.UUID, echo.Addr().String()), "ping")
}

func TestInboundOnlyReloadPortChangeUsesSafeCandidatePath(t *testing.T) {
	echo := policyEcho(t)
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	initial := inboundReloadNode("socks", policyFreePort(t))
	s := New(config.KernelConfig{LogLevel: "error"})
	if err := s.Start(initial, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	live := policyDial(t, initial.ServerPort, users[0].UUID, echo.Addr().String())
	policyExchange(t, live, "ping")
	oldBox, tracker := s.box, s.connTracker
	next := *initial
	next.ServerPort = policyFreePort(t)
	if err := s.Reload(&next, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	if s.box == oldBox || s.connTracker != tracker {
		t.Fatal("listener change did not use the candidate path with cumulative tracking")
	}
	policyClosed(t, live)
	policyExchange(t, policyDial(t, next.ServerPort, users[0].UUID, echo.Addr().String()), "ping")
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", initial.ServerPort), 100*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("previous listener remained active after port change")
	}
}

func TestLimitOnlyUpdatesRetainKernelAndLiveFlow(t *testing.T) {
	echo := policyEcho(t)
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	nc := inboundReloadNode("socks", policyFreePort(t))
	s := New(config.KernelConfig{LogLevel: "error"})
	if err := s.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	live := policyDial(t, nc.ServerPort, users[0].UUID, echo.Addr().String())
	policyExchange(t, live, "ping")
	oldBox := s.box
	inboundUnappliedLocalPolicy(t, s)
	for _, entry := range []string{"add-properties", "update", "reload", "remove-absent"} {
		users = append([]model.UserSpec(nil), users...)
		users[0].SpeedLimit++
		users[0].DeviceLimit++
		var err error
		switch entry {
		case "add-properties":
			_, err = s.AddUsers(users)
		case "update":
			_, _, err = s.UpdateUsers(users)
		case "reload":
			err = s.Reload(nc, users, kernel.TLSCert{})
		case "remove-absent":
			_, err = s.RemoveUsers([]model.UserSpec{{ID: 999, UUID: "absent"}})
		}
		if err != nil {
			t.Fatalf("%s: %v", entry, err)
		}
		if s.box != oldBox {
			t.Fatalf("%s limit-only update replaced the embedded kernel", entry)
		}
		policyExchange(t, live, "ping")
		policyExchange(t, policyDial(t, nc.ServerPort, users[0].UUID, echo.Addr().String()), "ping")
	}
}

// The frozen SOCKS/HTTP authenticators have no synchronization around their
// replacement pointer. Exercise every identity-update entry point against real
// sockets instead of calling those unsafe UpdateUsers methods under handlers.
func TestIdentityChangesReplaceKernelWithoutMutatingLiveAuthenticator(t *testing.T) {
	for _, protocol := range []string{"socks", "http"} {
		for _, entry := range []string{"add", "add-uuid-change", "remove", "update-uuid-change", "reload"} {
			t.Run(protocol+"/"+entry, func(t *testing.T) {
				echo := policyEcho(t)
				users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}, {ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888"}}
				nc := inboundReloadNode(protocol, policyFreePort(t))
				s := New(config.KernelConfig{LogLevel: "error"})
				if err := s.Start(nc, users, kernel.TLSCert{}); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(s.Stop)
				dial := policyDial
				if protocol == "http" {
					dial = inboundHTTPTunnel
				}
				live := dial(t, nc.ServerPort, users[0].UUID, echo.Addr().String())
				policyExchange(t, live, "ping")
				oldBox, tracker := s.box, s.connTracker
				oldPolicy := append([]byte(nil), s.activePolicy...)
				inboundUnappliedLocalPolicy(t, s)
				before, _, _ := tracker.GetUserTraffic()
				additional := model.UserSpec{ID: 3, UUID: "cccccccc-9999-aaaa-bbbb-cccccccccccc"}
				changed := users[1]
				changed.UUID = "dddddddd-1111-aaaa-2222-bbbbbbbbbbbb"
				var err error
				checkUser := users[0]
				switch entry {
				case "add":
					_, err = s.AddUsers([]model.UserSpec{additional})
					checkUser = additional
				case "add-uuid-change":
					_, err = s.AddUsers([]model.UserSpec{changed})
					checkUser = changed
				case "remove":
					_, err = s.RemoveUsers(users[1:])
				case "update-uuid-change":
					_, _, err = s.UpdateUsers([]model.UserSpec{users[0], changed})
					checkUser = changed
				case "reload":
					err = s.Reload(nc, append(users, additional), kernel.TLSCert{})
					checkUser = additional
				}
				if err != nil {
					t.Fatal(err)
				}
				if s.box == oldBox || s.connTracker != tracker || !bytes.Equal(oldPolicy, s.activePolicy) {
					t.Fatal("identity update did not replace the kernel with cumulative tracking")
				}
				policyClosed(t, live)
				policyExchange(t, dial(t, nc.ServerPort, checkUser.UUID, echo.Addr().String()), "ping")
				after, _, _ := tracker.GetUserTraffic()
				if after[1][0] < before[1][0] || after[1][1] < before[1][1] {
					t.Fatal("identity update lost cumulative traffic")
				}
			})
		}
	}
}
