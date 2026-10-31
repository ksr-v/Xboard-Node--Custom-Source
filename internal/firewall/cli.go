package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

var ErrUnhealthy = errors.New("firewall check reported unresolved issues")

const CLIUsage = "firewall <status|check|repair|ports|diagnose> [--output text|json] [--json]"

// RunCLI queries the live process. It never starts a second rule writer or
// treats panel configuration or a persisted snapshot as a running listener.
func RunCLI(args []string, output io.Writer) error {
	return runCLI(args, output, func(action string) (ControlResponse, error) {
		return QueryControl(DefaultSocket, action)
	})
}

func runCLI(args []string, output io.Writer, query func(string) (ControlResponse, error)) error {
	if len(args) == 0 {
		return errors.New("usage: " + CLIUsage)
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprintln(output, CLIUsage)
		return err
	}
	action, format := args[0], "text"
	if !validAction(action) {
		return errors.New("usage: " + CLIUsage)
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
			format = "json"
		case "--output":
			i++
			if i == len(args) {
				return errors.New("--output requires text or json")
			}
			format = args[i]
		default:
			return errors.New("usage: " + CLIUsage)
		}
	}
	if format != "text" && format != "json" {
		return errors.New("--output requires text or json")
	}
	response, err := query(action)
	if err != nil {
		return err
	}
	if format == "json" {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(response); err != nil {
			return err
		}
	} else {
		if err := printControlReport(output, response); err != nil {
			return err
		}
	}
	if (action == "check" || action == "repair") && (!response.Report.Healthy || len(response.Inventory.Issues) > 0) {
		return ErrUnhealthy
	}
	return nil
}

func printControlReport(output io.Writer, response ControlResponse) error {
	status := "OK"
	if !response.Report.Healthy || len(response.Inventory.Issues) > 0 {
		status = "WARNING"
	}
	var text strings.Builder
	fmt.Fprintf(&text, "Firewall Status: %s\nSource: running Node runtime registry\n", status)
	if response.Action != "ports" {
		fmt.Fprintf(&text, "Tools installed: iptables-nft=%t iptables-legacy=%t nft=%t\nNative nft INPUT chains: %s\n",
			response.Inventory.IPTablesNFTPresent, response.Inventory.IPTablesLegacyPresent,
			response.Inventory.NFTToolPresent, response.Inventory.NativeNFT)
		for _, owner := range response.Report.Owners {
			fmt.Fprintf(&text, "Owner: instance=%s node=%d managed=%t chain=%s\n", owner.InstanceID, owner.NodeID, owner.Managed, owner.Status.Chain)
			for _, backend := range owner.Status.Backends {
				fmt.Fprintf(&text, "  Backend: IPv%d %s; INPUT policy=%s; chain_present=%t jump_referenced=%t jump_ordered=%t ports_allowed=%t\n",
					backend.Family, backend.Kind, backend.Policy, backend.ChainPresent, backend.Referenced, backend.Ordered, backend.Allowed)
			}
		}
	}
	text.WriteString("Node Inbounds:\n")
	if len(response.Report.Ports) == 0 {
		text.WriteString("  none registered\n")
	}
	for _, port := range response.Report.Ports {
		fmt.Fprintf(&text, "  %s %s %s: owned_permission=%s effective_input=%s (instance=%s node=%d runtime=%s managed=%t)\n",
			strings.ToUpper(port.Protocol), strings.ToUpper(port.Transport), net.JoinHostPort(port.ListenAddress, strconv.Itoa(port.ListenPort)),
			port.RuleStatus, effectiveStatus(port.EffectiveStatus), port.InstanceID, port.NodeID, port.RuntimeStatus, port.Managed)
	}
	for _, issue := range response.Report.Issues {
		fmt.Fprintf(&text, "Detected: %s\n", issue)
	}
	for _, owner := range response.Report.Owners {
		seen := make(map[string]bool)
		issue := func(message string) {
			if message != "" && !seen[message] {
				fmt.Fprintf(&text, "Detected (instance=%s node=%d): %s\n", owner.InstanceID, owner.NodeID, message)
				seen[message] = true
			}
		}
		issue(owner.Error)
		for _, message := range owner.Status.Issues {
			issue(message)
		}
		for _, backend := range owner.Status.Backends {
			for _, message := range backend.Issues {
				issue(message)
			}
		}
		for _, listener := range owner.Status.Listeners {
			for _, message := range listener.Issues {
				issue(message)
			}
		}
		if response.Action == "ports" {
			continue
		}
		switch {
		case !owner.Managed:
			fmt.Fprintf(&text, "Suggested Repair (instance=%s node=%d): automatic management is disabled; manage these ports through the host firewall configuration.\n", owner.InstanceID, owner.NodeID)
		case owner.Status.Repairable && owner.Error == "":
			fmt.Fprintf(&text, "Suggested Repair (instance=%s node=%d): xboard-node firewall repair\n", owner.InstanceID, owner.NodeID)
		case !owner.Status.Healthy || owner.Error != "":
			fmt.Fprintf(&text, "Suggested Repair (instance=%s node=%d): resolve the reported host firewall or inspection conflict before retrying; automatic repair is unavailable.\n", owner.InstanceID, owner.NodeID)
		}
	}
	for _, issue := range response.Inventory.Issues {
		fmt.Fprintf(&text, "Inventory: %s\n", issue)
	}
	if response.Action != "ports" {
		fmt.Fprintf(&text, "Persistence: %s; netfilter-persistent installed=%t; saved IPv4=%t IPv6=%t\n",
			response.Persistence.Strategy, response.Persistence.NetfilterPersistentInstalled,
			response.Persistence.SavedIPv4Rules, response.Persistence.SavedIPv6Rules)
	}
	_, err := io.WriteString(output, text.String())
	return err
}

func effectiveStatus(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
