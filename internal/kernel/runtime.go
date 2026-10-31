package kernel

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Inbound describes a listening socket in a successfully applied kernel config.
// Transport is the host socket protocol (tcp or udp), not the tunneled traffic.
type Inbound struct {
	Protocol      string `json:"protocol"`
	Transport     string `json:"transport"`
	ListenAddress string `json:"listen_address"`
	ListenPort    int    `json:"listen_port"`
}

// RuntimeProvider is deliberately separate from Kernel: implementations must
// expose an applied snapshot, never an unaccepted panel configuration.
type RuntimeProvider interface {
	RuntimeInbounds() ([]Inbound, error)
}

// ParseRuntimeInbounds reads the saved, successfully started configuration.
// Unknown protocols/transports are reported instead of guessing permissions.
func ParseRuntimeInbounds(backend string, data []byte) ([]Inbound, error) {
	var cfg struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid applied %s inbound snapshot", backend)
	}
	var result []Inbound
	var issues []string
	for index, raw := range cfg.Inbounds {
		var in struct {
			Type       string          `json:"type"`
			Protocol   string          `json:"protocol"`
			Listen     string          `json:"listen"`
			ListenPort int             `json:"listen_port"`
			Port       int             `json:"port"`
			Network    string          `json:"network"`
			Transport  json.RawMessage `json:"transport"`
			Settings   struct {
				Network string `json:"network"`
				UDP     bool   `json:"udp"`
			} `json:"settings"`
			Stream struct {
				Network string `json:"network"`
			} `json:"streamSettings"`
		}
		if json.Unmarshal(raw, &in) != nil {
			issues = append(issues, fmt.Sprintf("inbound %d has invalid listener metadata", index))
			continue
		}
		protocol, port := in.Type, in.ListenPort
		if backend == "xray" {
			protocol, port = in.Protocol, in.Port
		} else if backend != "sing-box" {
			return nil, fmt.Errorf("unknown runtime backend %q", backend)
		}
		address := in.Listen
		if address == "" {
			address = "::"
		}
		ip, err := netip.ParseAddr(address)
		if err != nil || ip.Zone() != "" || ip.IsMulticast() || port < 1 || port > 65535 {
			issues = append(issues, fmt.Sprintf("inbound %d has invalid address or port", index))
			continue
		}
		address = ip.Unmap().String()
		var transports []string
		switch protocol {
		case "hysteria", "hysteria2", "tuic":
			transports = []string{"udp"}
		case "shadowsocks":
			network := in.Network
			if backend == "xray" {
				network = in.Settings.Network
			}
			if network == "" {
				network = "tcp,udp"
			}
			transports, err = socketNetworks(network)
		case "socks":
			transports = []string{"tcp"}
			// sing-box UDP ASSOCIATE uses dynamic sockets, not this TCP port.
			if backend == "xray" && in.Settings.UDP {
				transports = append(transports, "udp")
			}
		case "vmess", "vless", "trojan":
			network := in.Stream.Network
			if backend == "sing-box" {
				var transport struct {
					Type string `json:"type"`
				}
				if len(in.Transport) > 0 && json.Unmarshal(in.Transport, &transport) != nil {
					err = fmt.Errorf("invalid transport")
				} else {
					network = transport.Type
				}
			}
			if err == nil {
				switch network {
				case "", "tcp", "raw", "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "splithttp":
					transports = []string{"tcp"}
				case "kcp", "mkcp", "quic", "hysteria":
					transports = []string{"udp"}
				default:
					err = fmt.Errorf("unknown transport")
				}
			}
		case "http", "anytls":
			transports = []string{"tcp"}
		case "naive":
			// HTTP/3 bind failures can be nonfatal in this dependency. Its
			// successful configuration alone cannot prove surviving sockets.
			err = fmt.Errorf("naive runtime sockets require direct observation")
		case "mieru":
			var network string
			if len(in.Transport) == 0 {
				network = "tcp"
			} else if json.Unmarshal(in.Transport, &network) != nil {
				err = fmt.Errorf("invalid mieru transport")
			}
			if err == nil {
				transports, err = socketNetworks(strings.ToLower(network))
			}
		default:
			err = fmt.Errorf("unknown protocol")
		}
		if err != nil {
			issues = append(issues, fmt.Sprintf("inbound %d has unsupported protocol or transport", index))
			continue
		}
		for _, transport := range transports {
			result = append(result, Inbound{protocol, transport, address, port})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ListenPort != result[j].ListenPort {
			return result[i].ListenPort < result[j].ListenPort
		}
		return result[i].Transport < result[j].Transport
	})
	if len(issues) > 0 {
		return result, fmt.Errorf("%s", strings.Join(issues, "; "))
	}
	return result, nil
}

func socketNetworks(network string) ([]string, error) {
	seen := map[string]bool{}
	var result []string
	for _, item := range strings.Split(network, ",") {
		item = strings.TrimSpace(item)
		if item != "tcp" && item != "udp" {
			return nil, fmt.Errorf("unknown socket transport")
		}
		if !seen[item] {
			result = append(result, item)
			seen[item] = true
		}
	}
	return result, nil
}
