package panel

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const addressPath = "/api/v2/flowscope/node-address"

// One host observation shared by all instances in this process. Panel credentials
// never enter this client. No proxy, kernel outbound, listener or persistent service.
var hostIPv4 = ipv4Cache{lookup: lookupIPv4}

type ipv4Cache struct {
	mu             sync.Mutex
	lookup         func() string
	ip             string
	observed, next time.Time
}

func (h *ipv4Cache) get(now time.Time) (string, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !now.Before(h.next) {
		h.next = now.Add(5 * time.Minute)
		if ip := h.lookup(); publicIPv4(ip) {
			h.ip, h.observed, h.next = ip, now, now.Add(12*time.Hour)
		}
	}
	age := int(now.Sub(h.observed).Seconds())
	if h.ip == "" || age < 0 || age >= 86400 {
		return "", 0
	}
	return h.ip, age
}

func ipv4HTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp4", address)
			},
			TLSHandshakeTimeout:   3 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
			IdleConnTimeout:       30 * time.Second,
		},
	}
}

var ipClient = ipv4HTTPClient()

func lookupIPv4() string {
	req, _ := http.NewRequest(http.MethodGet, "https://api-ipv4.ip.sb/ip", nil)
	req.Header.Set("User-Agent", "Xboard-Node-FlowScope-IP/1")
	req.Header.Set("Accept", "text/plain")
	resp, err := ipClient.Do(req)
	if err != nil {
		return ""
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65))
	if err != nil || len(body) > 64 {
		return ""
	}
	ip := strings.TrimSpace(string(body))
	if !publicIPv4(ip) {
		return ""
	}
	return ip
}

var nonPublicIPv4 = func() []netip.Prefix {
	var ranges []netip.Prefix
	for _, cidr := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		ranges = append(ranges, netip.MustParsePrefix(cidr))
	}
	return ranges
}()

func publicIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() {
		return false
	}
	for _, prefix := range nonPublicIPv4 {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type addressReporter struct {
	mu       sync.Mutex
	busy     bool
	next     time.Time
	failures int
}

// Successful existing authenticated requests drive this bounded background task,
// including first handshake, old-binding upgrade, REST/WS reports and reconnection.
func (c *Client) maybeReportAddress() {
	// Machine orchestrators own the report; per-node children share their identity.
	if c.machineID > 0 && c.nodeID > 0 {
		return
	}
	u, err := url.Parse(c.baseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return
	}
	c.address.mu.Lock()
	if c.address.busy || time.Now().Before(c.address.next) {
		c.address.mu.Unlock()
		return
	}
	c.address.busy = true
	c.address.mu.Unlock()
	go func() {
		delay, failed := c.reportAddress(&hostIPv4)
		c.address.mu.Lock()
		defer c.address.mu.Unlock()
		if failed {
			c.address.failures++
			// Exponential transient backoff, capped at 15 minutes.
			delay = time.Minute * time.Duration(1<<min(c.address.failures-1, 4))
			if delay > 15*time.Minute {
				delay = 15 * time.Minute
			}
		} else {
			c.address.failures = 0
		}
		c.address.next, c.address.busy = time.Now().Add(delay), false
	}()
}

func (c *Client) reportAddress(host *ipv4Cache) (time.Duration, bool) {
	ip, age := host.get(time.Now())
	if ip == "" {
		return 5 * time.Minute, false
	}
	payload := map[string]interface{}{"ipv4": ip, "age_seconds": age}
	c.injectAuth(payload)
	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.doRequestContext(ctx, http.MethodPost, addressPath, body, "")
	if err != nil {
		return 0, true
	} // Never log URLs, tokens or response bodies.
	defer drainAndClose(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		var ack struct {
			Data struct {
				Accepted bool `json:"accepted"`
				Protocol int  `json:"protocol"`
			} `json:"data"`
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2049))
		if err != nil || len(body) > 2048 || json.Unmarshal(body, &ack) != nil || !ack.Data.Accepted || ack.Data.Protocol != 1 {
			return 10 * time.Minute, false
		}
		return time.Hour, false // Capability recheck/refresh without repeating host detection.
	case 404, 405, 501:
		return 10 * time.Minute, false // Plugin absent/old/disabled: finite negative cache.
	case 401, 403:
		return 15 * time.Minute, false
	case 429:
		seconds, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return time.Duration(max(60, min(seconds, 900))) * time.Second, false
	default:
		if resp.StatusCode >= 500 {
			return 0, true
		}
		return 15 * time.Minute, false
	}
}
