package singbox

import (
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"testing"
)

func TestInboundUsesActualConfiguredListenIP(t *testing.T) {
	for _, ip := range []string{"", "0.0.0.0", "127.0.0.2", "::", "::1", "2001:db8::2"} {
		t.Run(ip, func(t *testing.T) {
			spec := &model.NodeSpec{Protocol: "hysteria", Version: 2, ListenIP: ip, ServerPort: 18443}
			inbound := buildInbound(spec, testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
			want := ip
			if want == "" {
				want = "::"
			}
			assertMapValue(t, inbound, "listen", want)
			assertMapValue(t, inbound, "listen_port", 18443)
		})
	}
}
