package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/inputfirewall"
)

func TestCLIQueriesLiveActionAndFormatsReport(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		for _, action := range []string{"status", "check", "ports", "diagnose", "repair"} {
			var output bytes.Buffer
			called := 0
			err := runCLI([]string{action, "--output", format}, &output, func(got string) (ControlResponse, error) {
				called++
				if got != action {
					t.Fatal("wrong action")
				}
				return ControlResponse{Action: got, Report: Report{Healthy: true, Ports: []Port{{Protocol: "vless", Transport: "tcp", ListenAddress: "::", ListenPort: 8443, InstanceID: "fixture", NodeID: 4, RuleStatus: "allowed", RuntimeStatus: "running", Managed: true}}}}, nil
			})
			if err != nil || called != 1 {
				t.Fatalf("CLI: %v", err)
			}
			if format == "json" {
				var response ControlResponse
				if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.Report.Ports[0].ListenPort != 8443 {
					t.Fatal("invalid JSON report")
				}
			} else if !strings.Contains(output.String(), "VLESS TCP [::]:8443: owned_permission=allowed effective_input=unknown") || !strings.Contains(output.String(), "running Node runtime registry") {
				t.Fatal(output.String())
			}
		}
	}
}

func TestCLICheckAndRepairFailForUnresolvedIssues(t *testing.T) {
	for _, action := range []string{"status", "diagnose", "check", "repair"} {
		var output bytes.Buffer
		err := runCLI([]string{action, "--json"}, &output, func(action string) (ControlResponse, error) {
			return ControlResponse{Action: action, Report: Report{Healthy: false, Issues: []string{"native firewall conflict"}}}, nil
		})
		if (action == "check" || action == "repair") != errors.Is(err, ErrUnhealthy) {
			t.Fatalf("%s exit status: %v", action, err)
		}
		if !strings.Contains(output.String(), "native firewall conflict") {
			t.Fatal("lost diagnostic evidence")
		}
	}
}

func TestCLIInvalidArgumentsAndHelpNeverContactService(t *testing.T) {
	for _, args := range [][]string{nil, {"flush"}, {"repair", "--grant"}, {"status", "--output"}, {"status", "--output", "xml"}, {"help"}} {
		var output bytes.Buffer
		err := runCLI(args, &output, func(string) (ControlResponse, error) {
			t.Fatal("invalid CLI contacted registry")
			return ControlResponse{}, nil
		})
		if len(args) > 0 && args[0] == "help" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatalf("accepted invalid arguments %v", args)
		}
	}
}

func TestCLIUnavailableDoesNotInventRuntimePorts(t *testing.T) {
	var output bytes.Buffer
	err := runCLI([]string{"ports"}, &output, func(string) (ControlResponse, error) { return ControlResponse{}, ErrControlUnavailable })
	if !errors.Is(err, ErrControlUnavailable) || output.Len() != 0 {
		t.Fatal("unavailable service produced runtime output")
	}
}

func TestCLITextExplainsBackendDriftAndRepairPermissions(t *testing.T) {
	response := ControlResponse{Action: "diagnose", Report: Report{Owners: []OwnerStatus{
		{InstanceID: "repairable", NodeID: 1, Managed: true, Status: inputfirewall.Status{Chain: "XB_IN_fixture", Repairable: true, Issues: []string{"jump appears after REJECT"}, Backends: []inputfirewall.BackendStatus{{Family: 4, Kind: "nft", Policy: "DROP", ChainPresent: true, Referenced: true}}}},
		{InstanceID: "disabled", NodeID: 2, Managed: false},
		{InstanceID: "conflict", NodeID: 3, Managed: true, Error: "UFW ownership conflict"},
	}}}
	var output bytes.Buffer
	if err := printControlReport(&output, response); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"chain=XB_IN_fixture", "IPv4 nft; INPUT policy=DROP", "jump_referenced=true jump_ordered=false", "jump appears after REJECT", "node=1): xboard-node firewall repair", "node=2): automatic management is disabled", "UFW ownership conflict", "node=3): resolve the reported host firewall"} {
		if !strings.Contains(output.String(), required) {
			t.Fatalf("missing %q in %s", required, output.String())
		}
	}
}

func TestCLIInventoryFailurePreventsHealthyEmptyRegistry(t *testing.T) {
	for _, action := range []string{"status", "check", "repair"} {
		var output bytes.Buffer
		err := runCLI([]string{action}, &output, func(action string) (ControlResponse, error) {
			return ControlResponse{Action: action, Report: Report{Healthy: true}, Inventory: inputfirewall.InventoryStatus{NativeNFT: "unknown", Issues: []string{"nft inspection unavailable"}}}, nil
		})
		if !strings.Contains(output.String(), "Firewall Status: WARNING") {
			t.Fatal(output.String())
		}
		if (action == "check" || action == "repair") != errors.Is(err, ErrUnhealthy) {
			t.Fatalf("%s inventory check status: %v", action, err)
		}
	}
}
