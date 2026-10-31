package singbox

import (
	"encoding/json"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestGeneratedSingBoxRuntimeListeners(t *testing.T) {
	for _, tc := range []struct {
		protocol   string
		version    int
		transports int
	}{{"vless", 0, 1}, {"vmess", 0, 1}, {"trojan", 0, 1}, {"shadowsocks", 0, 2}, {"hysteria", 2, 1}, {"tuic", 0, 1}, {"socks", 0, 1}} {
		t.Run(tc.protocol, func(t *testing.T) {
			n := &model.NodeSpec{Protocol: tc.protocol, Version: tc.version, ServerPort: 19277, ListenIP: "127.0.0.2"}
			data, err := json.Marshal(buildConfig(config.KernelConfig{}, n, []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}, kernel.TLSCert{}))
			if err != nil {
				t.Fatal(err)
			}
			listeners, err := kernel.ParseRuntimeInbounds("sing-box", data)
			if err != nil || len(listeners) != tc.transports {
				t.Fatalf("listeners=%#v error=%v", listeners, err)
			}
			for _, listener := range listeners {
				if listener.ListenPort != 19277 || listener.ListenAddress != "127.0.0.2" {
					t.Fatalf("wrong generated listener %#v", listener)
				}
			}
		})
	}
}

func TestSingBoxRuntimeUsesAcceptedSnapshotAndStops(t *testing.T) {
	s := New(config.KernelConfig{LogLevel: "error"})
	n := &model.NodeSpec{Protocol: "http", ServerPort: policyFreePort(t), ListenIP: "127.0.0.1"}
	users := []model.UserSpec{{ID: 1, UUID: "fixture"}}
	if err := s.Start(n, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	accepted := n.ServerPort
	n.ServerPort++ // The panel object can mutate; the applied JSON is immutable.
	listeners, err := s.RuntimeInbounds()
	if err != nil || len(listeners) != 1 || listeners[0].ListenPort != accepted {
		t.Fatalf("runtime followed mutable panel config: %#v %v", listeners, err)
	}
	bad := *n
	bad.TLS = 1
	if err := s.Reload(&bad, users, kernel.TLSCert{CertPEM: []byte("invalid"), KeyPEM: []byte("invalid")}); err == nil {
		t.Fatal("invalid replacement unexpectedly started")
	}
	listeners, err = s.RuntimeInbounds()
	if err != nil || len(listeners) != 1 || listeners[0].ListenPort != accepted {
		t.Fatal("failed replacement changed reported runtime listener")
	}
	s.Stop()
	listeners, err = s.RuntimeInbounds()
	if err != nil || len(listeners) != 0 {
		t.Fatal("stopped kernel reported listeners")
	}
}
