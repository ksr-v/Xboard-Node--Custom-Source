// Package portforward manages only the UDP redirects owned by one Node instance.
// It never opens a firewall, changes a default policy, or flushes foreign rules.
package portforward

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/cedar2025/xboard-node/internal/model"
)

const markerPrefix = "xboard-node-portforward:v1:"
const portableMarkerPrefix = "xboard-node-portforward:v2:"
const ownerChain = "__xbnode_owner"

type system interface {
	available() bool
	lease(string) (func(), error)
	lock() (func(), error)
	snapshot() ([]byte, error)
	apply(string) error
	verify(*redirect, []int) error
}

type Manager struct {
	mu             sync.Mutex
	table          string
	marker         string
	ownerOK        bool
	engaged        bool
	checked        bool
	leaseDenied    bool
	releaseLease   func()
	acceptedTarget int
	system         system
}

// New uses a stable, per-instance owner. Only its hash enters the host ruleset.
// Owners must remain stable across process restarts to reclaim their stale table.
func New(owner string) *Manager {
	digest := sha256.Sum256([]byte(owner))
	id := hex.EncodeToString(digest[:])
	return &Manager{table: "xbnode_hop_" + id[:24], marker: markerPrefix + id,
		ownerOK: strings.TrimSpace(owner) != "", system: newSystem()}
}

type redirect struct {
	start, end, target int
	family             int // 0 is dual stack; otherwise 4 or 6.
	address            netip.Addr
}

func validate(nc *model.NodeSpec) (*redirect, error) {
	if nc == nil || nc.PortHopping == nil {
		return nil, nil
	}
	if err := model.ValidatePortHopping(nc); err != nil {
		return nil, err
	}
	h := nc.PortHopping
	r := &redirect{start: h.Start, end: h.End, target: nc.ServerPort}
	if nc.ListenIP == "" || nc.ListenIP == "::" {
		return r, nil
	}
	addr, err := netip.ParseAddr(nc.ListenIP)
	if err != nil || addr.Zone() != "" {
		return nil, fmt.Errorf("UDP port hopping listen_ip must be an IP literal without an interface zone")
	}
	addr = addr.Unmap()
	if addr.Is4() {
		r.family = 4
	} else {
		r.family = 6
	}
	if !addr.IsUnspecified() {
		r.address = addr
	}
	return r, nil
}

// Update atomically replaces this owner's NAT table. A rejected or failed batch
// leaves the previous rules intact. The caller coordinates kernel rollback.
// No range needs neither nft nor root. When both are present, a one-time
// ownership check removes this owner's stale redirect after a process crash.
func (m *Manager) Update(nc *model.NodeSpec) error {
	want, err := validate(nc)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.update(want)
}

func (m *Manager) update(want *redirect) error {
	optional := want == nil && !m.engaged
	if want == nil && !m.engaged && (m.checked || m.leaseDenied || !m.system.available()) {
		return nil
	}
	if !m.ownerOK {
		return fmt.Errorf("UDP port hopping requires a non-empty stable instance owner")
	}
	if m.releaseLease == nil {
		var err error
		m.releaseLease, err = m.system.lease(m.table)
		if err != nil {
			m.leaseDenied = true
			if optional {
				return nil
			}
			return err
		}
		m.leaseDenied = false
	}
	unlock, err := m.system.lock()
	if err != nil {
		if optional {
			return nil
		}
		return err
	}
	defer unlock()
	data, err := m.system.snapshot()
	if err != nil {
		if optional {
			return nil
		}
		return err
	}
	view, err := inspect(data, m.table, m.marker)
	if err != nil {
		return err
	}
	m.checked = true
	if view.owned {
		m.engaged = true
	}
	if want != nil {
		if err := view.conflicts(want); err != nil {
			return err
		}
		// A stale table alone cannot prove that a same-process socket still
		// belongs to this instance. Exempt an old target only after this Manager
		// successfully installed it during its current lifetime.
		var previous []int
		for _, target := range view.oldTargets {
			if target == m.acceptedTarget && target > 0 {
				previous = []int{target}
				break
			}
		}
		if err := m.system.verify(want, previous); err != nil {
			return err
		}
	}
	if want == nil && !view.owned {
		m.engaged = false
		return nil
	}
	if err := m.system.apply(batch(m.table, m.marker, view.families, want)); err != nil {
		return err
	}
	m.engaged = want != nil
	m.acceptedTarget = 0
	if want != nil {
		m.acceptedTarget = want.target
	}
	return nil
}

// Close removes only this owner's previously managed table. It never deletes a
// table whose name collides but whose ownership comment differs.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if m.releaseLease != nil {
			m.releaseLease()
			m.releaseLease = nil
		}
	}()
	return m.update(nil)
}

func batch(table, marker string, replace map[string]bool, r *redirect) string {
	var b strings.Builder
	for _, family := range []string{"inet", "ip", "ip6"} {
		if replace[family] {
			fmt.Fprintf(&b, "delete table %s %s\n", family, table)
		}
	}
	if r == nil {
		return b.String()
	}
	portableMarker := portableMarkerPrefix + strings.TrimPrefix(marker, markerPrefix)
	for _, family := range []string{"ip", "ip6"} {
		if r.family == 4 && family != "ip" || r.family == 6 && family != "ip6" {
			continue
		}
		fmt.Fprintf(&b, "table %s %s {\n chain %s {\n return comment %q\n }\n chain prerouting {\n type nat hook prerouting priority -100; policy accept;\n ", family, table, ownerChain, portableMarker)
		if r.address.IsValid() {
			fmt.Fprintf(&b, "%s daddr %s ", family, r.address)
		}
		// Per-family NAT and a rule-comment sentinel work on Linux 4.19 and
		// nft 0.9.0; inet NAT and table comments need newer kernel/CLI features.
		fmt.Fprintf(&b, "fib daddr type local meta l4proto udp udp dport %d-%d counter redirect to :%d comment %q\n }\n}\n", r.start, r.end, r.target, portableMarker)
	}
	return b.String()
}
