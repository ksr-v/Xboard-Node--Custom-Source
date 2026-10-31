package kernel

import (
	"reflect"
	"testing"
)

func TestParseRuntimeInboundsTransportAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name, backend, data string
		transports          []string
		bad                 bool
	}{
		{"singbox-vless", "sing-box", `{"inbounds":[{"type":"vless","listen_port":18443,"transport":{"type":"ws"}}]}`, []string{"tcp"}, false},
		{"singbox-ss", "sing-box", `{"inbounds":[{"type":"shadowsocks","listen_port":18443}]}`, []string{"tcp", "udp"}, false},
		{"xray-ss", "xray", `{"inbounds":[{"protocol":"shadowsocks","port":18443,"settings":{"network":"udp"}}]}`, []string{"udp"}, false},
		{"xray-socks", "xray", `{"inbounds":[{"protocol":"socks","port":18443,"settings":{"udp":true}}]}`, []string{"tcp", "udp"}, false},
		{"xray-kcp", "xray", `{"inbounds":[{"protocol":"vless","port":18443,"streamSettings":{"network":"kcp"}}]}`, []string{"udp"}, false},
		{"singbox-hy2", "sing-box", `{"inbounds":[{"type":"hysteria2","listen_port":18443}]}`, []string{"udp"}, false},
		{"singbox-tuic", "sing-box", `{"inbounds":[{"type":"tuic","listen_port":18443}]}`, []string{"udp"}, false},
		{"singbox-socks", "sing-box", `{"inbounds":[{"type":"socks","listen_port":18443}]}`, []string{"tcp"}, false},
		{"singbox-naive-uncertain", "sing-box", `{"inbounds":[{"type":"naive","listen_port":18443}]}`, nil, true},
		{"unknown-protocol", "sing-box", `{"inbounds":[{"type":"future","listen_port":18443}]}`, nil, true},
		{"unknown-transport", "xray", `{"inbounds":[{"protocol":"vless","port":18443,"streamSettings":{"network":"future"}}]}`, nil, true},
		{"invalid-port", "sing-box", `{"inbounds":[{"type":"http","listen_port":0}]}`, nil, true},
		{"invalid-listen", "sing-box", `{"inbounds":[{"type":"http","listen_port":18443,"listen":"localhost"}]}`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRuntimeInbounds(tc.backend, []byte(tc.data))
			if (err != nil) != tc.bad {
				t.Fatalf("error=%v", err)
			}
			var transports []string
			for _, inbound := range got {
				transports = append(transports, inbound.Transport)
				if inbound.ListenAddress != "::" || inbound.ListenPort != 18443 {
					t.Fatalf("wrong listener: %#v", inbound)
				}
			}
			if !reflect.DeepEqual(transports, tc.transports) {
				t.Fatalf("transports=%v want %v", transports, tc.transports)
			}
		})
	}
}
