package firewall

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/cedar2025/xboard-node/internal/inputfirewall"
)

const (
	DefaultSocket      = "/run/xboard-node-firewall/control.sock"
	controlTimeout     = 30 * time.Second
	maxControlResponse = 4 << 20
)

var ErrControlUnavailable = errors.New("firewall control unavailable: run as root and ensure the running Node exposes its private local control socket")

type reportProvider interface {
	Report() Report
	Repair() Report
}

// Persistence describes restoration policy; saved host files are inspected only
// for existence and are never read, rewritten, or used as runtime inventory.
type Persistence struct {
	Strategy                     string `json:"strategy"`
	NetfilterPersistentInstalled bool   `json:"netfilter_persistent_installed"`
	SavedIPv4Rules               bool   `json:"saved_ipv4_rules"`
	SavedIPv6Rules               bool   `json:"saved_ipv6_rules"`
}

type ControlResponse struct {
	Action      string                        `json:"action"`
	Report      Report                        `json:"report"`
	Persistence Persistence                   `json:"persistence"`
	Inventory   inputfirewall.InventoryStatus `json:"inventory"`
	Error       string                        `json:"error,omitempty"`
}

type controlRequest struct {
	Action string `json:"action"`
}

func validAction(action string) bool {
	switch action {
	case "status", "check", "ports", "diagnose", "repair":
		return true
	}
	return false
}

// handleControl handles one bounded request. Only an explicit repair request
// can invoke mutation, and registry permission checks remain authoritative.
func handleControl(conn net.Conn, provider reportProvider) {
	handleControlWithInventory(conn, provider, inputfirewall.Inventory)
}

func handleControlWithInventory(conn net.Conn, provider reportProvider, inventory func() inputfirewall.InventoryStatus) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlTimeout))
	var request controlRequest
	line, err := bufio.NewReaderSize(conn, 512).ReadSlice('\n')
	if err != nil || len(line) > 512 {
		_ = json.NewEncoder(conn).Encode(ControlResponse{Error: "invalid firewall control request"})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || !validAction(request.Action) {
		_ = json.NewEncoder(conn).Encode(ControlResponse{Error: "invalid firewall control request"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		_ = json.NewEncoder(conn).Encode(ControlResponse{Error: "invalid firewall control request"})
		return
	}
	response := ControlResponse{Action: request.Action, Persistence: persistenceInventory(), Inventory: inventory()}
	if request.Action == "repair" {
		response.Report = provider.Repair()
	} else {
		response.Report = provider.Report()
	}
	data, err := json.Marshal(response)
	if err != nil || len(data)+1 > maxControlResponse {
		_ = json.NewEncoder(conn).Encode(ControlResponse{Error: "firewall report exceeds the response limit"})
		return
	}
	_, _ = conn.Write(append(data, '\n'))
}

func requestControl(conn net.Conn, action string) (ControlResponse, error) {
	defer conn.Close()
	if !validAction(action) {
		return ControlResponse{}, errors.New("unknown firewall action")
	}
	_ = conn.SetDeadline(time.Now().Add(controlTimeout))
	if err := json.NewEncoder(conn).Encode(controlRequest{Action: action}); err != nil {
		return ControlResponse{}, ErrControlUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(conn, maxControlResponse+1))
	if err != nil {
		return ControlResponse{}, ErrControlUnavailable
	}
	if len(data) > maxControlResponse {
		return ControlResponse{}, errors.New("firewall response exceeds the response limit")
	}
	var response ControlResponse
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&response); err != nil {
		return ControlResponse{}, errors.New("invalid firewall control response")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ControlResponse{}, errors.New("invalid firewall control response")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	if response.Action != action {
		return ControlResponse{}, errors.New("mismatched firewall control response")
	}
	return response, nil
}
