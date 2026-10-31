package xray

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestGeneratedXrayRuntimeListeners(t *testing.T) {
	for _, tc := range []struct {
		protocol   string
		version    int
		transports int
	}{{"vless", 0, 1}, {"vmess", 0, 1}, {"trojan", 0, 1}, {"shadowsocks", 0, 2}, {"hysteria", 2, 1}, {"socks", 0, 2}} {
		t.Run(tc.protocol, func(t *testing.T) {
			n := &model.NodeSpec{Protocol: tc.protocol, Version: tc.version, ServerPort: 19377, ListenIP: "::1", Cipher: "aes-128-gcm"}
			data, err := json.Marshal(buildConfig(config.KernelConfig{}, n, []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}, kernel.TLSCert{}))
			if err != nil {
				t.Fatal(err)
			}
			listeners, err := kernel.ParseRuntimeInbounds("xray", data)
			if err != nil || len(listeners) != tc.transports {
				t.Fatalf("listeners=%#v error=%v", listeners, err)
			}
			for _, listener := range listeners {
				if listener.ListenPort != 19377 || listener.ListenAddress != "::1" {
					t.Fatalf("wrong generated listener %#v", listener)
				}
			}
		})
	}
}

func TestXrayRuntimeUsesAcceptedSnapshotAndStops(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	x := New(config.KernelConfig{LogLevel: "error"})
	n := &model.NodeSpec{Protocol: "vless", ServerPort: port, ListenIP: "127.0.0.1"}
	if err = x.Start(n, []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer x.Stop()
	n.ServerPort++
	listeners, err := x.RuntimeInbounds()
	if err != nil || len(listeners) != 1 || listeners[0].ListenPort != port {
		t.Fatalf("runtime followed mutable panel config: %#v %v", listeners, err)
	}
	bad := *n
	bad.Network = "unsupported-runtime-test"
	if err := x.Reload(&bad, []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}, kernel.TLSCert{CertPEM: []byte("invalid"), KeyPEM: []byte("invalid")}); err == nil {
		t.Fatal("invalid replacement unexpectedly started")
	}
	listeners, err = x.RuntimeInbounds()
	if err != nil || len(listeners) != 1 || listeners[0].ListenPort != port {
		t.Fatal("failed replacement changed reported runtime listener")
	}
	x.Stop()
	listeners, err = x.RuntimeInbounds()
	if err != nil || len(listeners) != 0 {
		t.Fatal("stopped kernel reported listeners")
	}
}
