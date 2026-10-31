// Package firewall connects live kernel listeners with owned INPUT management.
package firewall

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cedar2025/xboard-node/internal/inputfirewall"
)

type RuleManager interface {
	UpdateListeners([]inputfirewall.Listener) error
	CheckListeners([]inputfirewall.Listener) (inputfirewall.Status, error)
	Close() error
}

type ownerReservation interface {
	Reserve() error
	ReleaseReservation()
}

type Port struct {
	Owner           string `json:"owner"`
	InstanceID      string `json:"instance_id"`
	NodeID          int    `json:"node_id"`
	Protocol        string `json:"protocol"`
	Transport       string `json:"transport"`
	ListenAddress   string `json:"listen_address"`
	ListenPort      int    `json:"listen_port"`
	RuntimeStatus   string `json:"runtime_status"`
	RuleStatus      string `json:"rule_status"`
	EffectiveStatus string `json:"effective_status"`
	Managed         bool   `json:"managed"`
}

type OwnerStatus struct {
	Owner      string               `json:"owner"`
	InstanceID string               `json:"instance_id"`
	NodeID     int                  `json:"node_id"`
	Managed    bool                 `json:"managed"`
	Status     inputfirewall.Status `json:"status"`
	Error      string               `json:"error,omitempty"`
}

type Report struct {
	Healthy bool          `json:"healthy"`
	Ports   []Port        `json:"ports"`
	Owners  []OwnerStatus `json:"owners"`
	Issues  []string      `json:"issues"`
}

type Registry struct {
	mu         sync.Mutex
	owners     map[string]*Registration
	newManager func(string) RuleManager
}

var Default = NewRegistry()

func NewRegistry() *Registry {
	return &Registry{owners: make(map[string]*Registration), newManager: func(owner string) RuleManager { return inputfirewall.New(owner) }}
}

type Registration struct {
	mu                sync.Mutex
	registry          *Registry
	owner, instanceID string
	nodeID            int
	managed           bool
	provider          func() ([]inputfirewall.Listener, error)
	manager           RuleManager
	closed            bool
	conflict          bool
	reservation       ownerReservation
	conflictErr       error
}

func (r *Registry) Register(owner, instanceID string, nodeID int, managed bool, provider func() ([]inputfirewall.Listener, error)) *Registration {
	return r.RegisterWithManager(owner, instanceID, nodeID, managed, provider, nil)
}

// RegisterWithManager permits an existing instance-owned manager to be reused.
// A disabled registration remains observable and can never mutate rules.
func (r *Registry) RegisterWithManager(owner, instanceID string, nodeID int, managed bool, provider func() ([]inputfirewall.Listener, error), manager RuleManager) *Registration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if manager == nil {
		manager = r.newManager(owner)
	}
	registration := &Registration{registry: r, owner: owner, instanceID: instanceID, nodeID: nodeID, managed: managed, provider: provider, manager: manager}
	if owner == "" || provider == nil || r.owners[owner] != nil {
		registration.conflict = true
	} else {
		if reservation, ok := manager.(ownerReservation); ok {
			if err := reservation.Reserve(); err != nil {
				registration.conflict = true
				registration.conflictErr = err
				return registration
			}
			registration.reservation = reservation
		}
		r.owners[owner] = registration
	}
	return registration
}

func (r *Registration) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sync()
}

// ChangeRuntime serializes listener lifecycle changes with diagnostic repairs.
// The two errors keep kernel failures separate from nonfatal INPUT failures.
func (r *Registration) ChangeRuntime(change func() error) (error, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("firewall registration is closed"), nil
	}
	runtimeErr := change()
	return runtimeErr, r.sync()
}

func (r *Registration) sync() error {
	if r.closed {
		return errors.New("firewall registration is closed")
	}
	if r.conflict {
		if r.conflictErr != nil {
			return r.conflictErr
		}
		return errors.New("firewall owner registration conflicts")
	}
	if !r.managed {
		return nil
	}
	listeners, err := r.provider()
	if err != nil {
		return fmt.Errorf("runtime listener discovery: %w", err)
	}
	return r.manager.UpdateListeners(listeners)
}

func (r *Registration) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if !r.conflict && r.managed {
		err = r.manager.Close()
	}
	if r.reservation != nil {
		r.reservation.ReleaseReservation()
		r.reservation = nil
	}
	r.registry.mu.Lock()
	if r.registry.owners[r.owner] == r {
		delete(r.registry.owners, r.owner)
	}
	r.registry.mu.Unlock()
	return err
}

func (r *Registry) Report() Report { return r.report(false) }

// Repair uses only registrations that already have local authorization.
func (r *Registry) Repair() Report { return r.report(true) }

func (r *Registry) report(repair bool) Report {
	r.mu.Lock()
	registrations := make([]*Registration, 0, len(r.owners))
	for _, registration := range r.owners {
		registrations = append(registrations, registration)
	}
	r.mu.Unlock()
	sort.Slice(registrations, func(i, j int) bool { return registrations[i].owner < registrations[j].owner })
	report := Report{Healthy: true, Ports: []Port{}, Owners: []OwnerStatus{}, Issues: []string{}}
	for _, registration := range registrations {
		registration.mu.Lock()
		if registration.closed {
			registration.mu.Unlock()
			continue
		}
		owner := OwnerStatus{Owner: registration.owner, InstanceID: registration.instanceID, NodeID: registration.nodeID, Managed: registration.managed}
		listeners, discoveryErr := registration.provider()
		var repairErr error
		if repair && registration.managed && discoveryErr == nil {
			repairErr = registration.manager.UpdateListeners(listeners)
		}
		status, checkErr := registration.manager.CheckListeners(listeners)
		if discoveryErr != nil {
			status.Healthy, status.Repairable = false, false
		}
		if !registration.managed {
			status.Repairable = false
		}
		owner.Status = status
		combined := errors.Join(discoveryErr, repairErr, checkErr)
		if combined != nil {
			owner.Error = combined.Error()
			report.Issues = append(report.Issues, fmt.Sprintf("node %d: %s", registration.nodeID, owner.Error))
		}
		if combined != nil || !status.Healthy {
			report.Healthy = false
		}
		for _, issue := range status.Issues {
			report.Issues = append(report.Issues, fmt.Sprintf("node %d: %s", registration.nodeID, issue))
		}
		ruleStatus := "allowed"
		if !status.Healthy {
			ruleStatus = "warning"
			if status.Repairable {
				ruleStatus = "missing_or_displaced"
			}
		}
		if checkErr != nil || discoveryErr != nil {
			ruleStatus = "unknown"
		}
		for _, listener := range listeners {
			portStatus := ruleStatus
			effectiveStatus := "unknown"
			for _, checked := range status.Listeners {
				if checked.Listener == listener {
					portStatus = checked.RuleStatus
					if checked.EffectiveStatus != "" {
						effectiveStatus = checked.EffectiveStatus
					}
					break
				}
			}
			if checkErr != nil || discoveryErr != nil {
				portStatus = "unknown"
				effectiveStatus = "unknown"
			}
			report.Ports = append(report.Ports, Port{Owner: registration.owner, InstanceID: registration.instanceID, NodeID: registration.nodeID, Protocol: listener.Protocol, Transport: listener.Transport, ListenAddress: listener.ListenAddress, ListenPort: listener.ListenPort, RuntimeStatus: "running", RuleStatus: portStatus, EffectiveStatus: effectiveStatus, Managed: registration.managed})
		}
		report.Owners = append(report.Owners, owner)
		registration.mu.Unlock()
	}
	return report
}
