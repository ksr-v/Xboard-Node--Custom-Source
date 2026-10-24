package xray

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"golang.org/x/time/rate"
)

func TestHTTPRepliesAfterPolicyReplacementWithLiveUnlimitedBucket(t *testing.T) {
	serve := func() net.Listener {
		l := xrayPolicyListener(t)
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() {
					defer c.Close()
					b := make([]byte, 4096)
					c.Read(b)
					c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIRECT"))
				}()
			}
		}()
		return l
	}
	target, other := serve(), serve()
	nc, users := xrayPolicyNode(t)
	nc.ListenIP = ""
	nc.CustomRouteRules = nil
	x := New(config.KernelConfig{Type: "xray", LogLevel: "error", CustomRoute: []map[string]any{{"type": "field", "ip": []string{"127.0.0.0/8"}, "outboundTag": "direct"}}})
	liveBucket := rate.NewLimiter(rate.Inf, 65536)
	x.SetSpeedLimitFunc(func(string) *rate.Limiter { return liveBucket })
	if err := x.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer x.Stop()
	request := func(address string) string {
		c := xrayPolicyDial(t, nc.ServerPort, users[0].UUID, address)
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte("GET /controlled HTTP/1.1\r\nHost: controlled.fixture.test\r\nConnection: close\r\n\r\n"))
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return "ERROR:" + err.Error()
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return "ERROR:" + err.Error()
		}
		return string(body)
	}
	if body := request(other.Addr().String()); !strings.Contains(body, "DIRECT") {
		t.Fatalf("initial response: %s", body)
	}
	updated := *nc
	updated.CustomRoutes = []map[string]any{{"type": "field", "port": strconv.Itoa(target.Addr().(*net.TCPAddr).Port), "outboundTag": "block"}}
	if err := x.Reload(&updated, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	if body := request(other.Addr().String()); !strings.Contains(body, "DIRECT") {
		t.Fatalf("unmatched HTTP response after route replacement: %s", body)
	}
	if traffic, _, _, err := x.GetUserTraffic(context.Background()); err != nil || len(traffic) == 0 {
		t.Fatalf("missing counters after HTTP reply: %v %v", traffic, err)
	}
}
