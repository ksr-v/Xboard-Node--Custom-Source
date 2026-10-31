package firewall

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/inputfirewall"
)

type controlFixture struct{ reads, repairs int }

func (p *controlFixture) Report() Report {
	p.reads++
	return Report{Healthy: true, Ports: []Port{{Protocol: "vless", Transport: "tcp", ListenPort: 8443, RuntimeStatus: "running", RuleStatus: "allowed"}}}
}
func (p *controlFixture) Repair() Report { p.repairs++; return Report{Healthy: true} }
func fixtureInventory() inputfirewall.InventoryStatus {
	return inputfirewall.InventoryStatus{NativeNFT: "unknown"}
}

func TestControlOnlyExplicitRepairMutates(t *testing.T) {
	for _, action := range []string{"status", "check", "ports", "diagnose", "repair"} {
		t.Run(action, func(t *testing.T) {
			provider := new(controlFixture)
			server, client := net.Pipe()
			done := make(chan struct{})
			go func() { handleControlWithInventory(server, provider, fixtureInventory); close(done) }()
			response, err := requestControl(client, action)
			<-done
			if err != nil || response.Action != action || !response.Report.Healthy {
				t.Fatalf("response: %+v %v", response, err)
			}
			if action == "repair" {
				if provider.repairs != 1 || provider.reads != 0 {
					t.Fatal("repair dispatch")
				}
			} else if provider.reads != 1 || provider.repairs != 0 {
				t.Fatal("read-only action mutated registry")
			}
		})
	}
}

func TestControlRejectsInvalidAndOversizedRequestsBeforeRegistry(t *testing.T) {
	for _, request := range []string{"{}\n", "{\"action\":\"flush\"}\n", "{\"action\":\"repair\",\"grant\":true}\n", "{\"action\":\"repair\"} {}\n", strings.Repeat(" ", 513) + "\n"} {
		provider := new(controlFixture)
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() { handleControlWithInventory(server, provider, fixtureInventory); close(done) }()
		go func() { _, _ = io.WriteString(client, request) }()
		var response ControlResponse
		if err := json.NewDecoder(client).Decode(&response); err != nil {
			t.Fatal(err)
		}
		client.Close()
		<-done
		if response.Error == "" || provider.reads != 0 || provider.repairs != 0 {
			t.Fatal("invalid request reached registry")
		}
	}
}

func TestControlClientRejectsMalformedOrMismatchedResponses(t *testing.T) {
	for _, body := range []string{"{}\n", "{\"action\":\"repair\"}\n", "{\"action\":\"status\"} {}\n", "not-json", strings.Repeat("x", maxControlResponse+1)} {
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			var request controlRequest
			_ = json.NewDecoder(server).Decode(&request)
			_, _ = io.WriteString(server, body)
		}()
		if _, err := requestControl(client, "status"); err == nil {
			t.Fatal("untrusted control response accepted")
		}
	}
}

func TestUnavailableControlIsExplicit(t *testing.T) {
	if _, err := QueryControl("/definitely-missing-xboard-firewall/control.sock", "status"); !errors.Is(err, ErrControlUnavailable) {
		t.Fatal(err)
	}
}
