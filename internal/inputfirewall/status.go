package inputfirewall

import "strconv"

// CheckListeners inspects host rules without acquiring the host management
// lease, registering an owner, or applying a restore transaction.
func (m *Manager) CheckListeners(values []Listener) (Status, error) {
	status := Status{Healthy: true, Repairable: true, Chain: m.name, Backends: []BackendStatus{}, Issues: []string{}, Listeners: []ListenerStatus{}}
	want, err := validateListeners(values)
	if err != nil || !m.ownerOK {
		status.Healthy = false
		status.Repairable = false
		status.Issues = append(status.Issues, errInvalid.Error())
		return status, errInvalid
	}
	c := m.controller
	c.mu.Lock()
	defer c.mu.Unlock()
	var first error
	var tracked []*listener
	for _, v := range values {
		parsed, _ := validateListeners([]Listener{v})
		tracked = append(tracked, parsed[0])
		status.Listeners = append(status.Listeners, ListenerStatus{Listener: v, Allowed: true, RuleStatus: "allowed", EffectiveStatus: "allowed", Issues: []string{}})
	}
	finish := func() (Status, error) {
		if first != nil {
			for i := range status.Listeners {
				status.Listeners[i].Allowed = false
				status.Listeners[i].RuleStatus = "unknown"
				status.Listeners[i].EffectiveStatus = "unknown"
				status.Listeners[i].Issues = append(status.Listeners[i].Issues, first.Error())
			}
		}
		return status, first
	}
	problem := func(err error) {
		err = safeError(err)
		status.Healthy, status.Repairable = false, false
		status.Issues = append(status.Issues, err.Error())
		if first == nil {
			first = err
		}
	}
	if err := c.system.checkNative(); err != nil {
		problem(phaseError("inspect native nft INPUT", err))
	}
	backends, err := c.system.discover()
	if err != nil {
		problem(phaseError("discover active filter backends", err))
		return finish()
	}
	if len(backends) == 0 {
		problem(errUnavailable)
		return finish()
	}
	seen, available := make(map[string]bool), make(map[int]bool)
	for _, b := range backends {
		if seen[b.key()] {
			continue
		}
		seen[b.key()] = true
		available[b.family] = true
		row := BackendStatus{Family: b.family, Kind: b.kind, Issues: []string{}}
		data, err := c.system.read(b)
		if err != nil {
			err = phaseError("read IPv"+b.key()+" filter", err)
			problem(err)
			row.Issues = append(row.Issues, err.Error())
			status.Backends = append(status.Backends, row)
			continue
		}
		s, err := inspectSave(data)
		if err != nil {
			problem(err)
			row.Issues = append(row.Issues, err.Error())
			status.Backends = append(status.Backends, row)
			continue
		}
		row.Policy = s.chains["INPUT"].policy
		if row.Policy == "" {
			row.Policy = "ACCEPT (no filter INPUT chain)"
		}
		if externallyManaged(s) {
			problem(errExternal)
			row.Issues = append(row.Issues, errExternal.Error())
		}
		all, err := owned(s)
		if err != nil {
			problem(err)
			row.Issues = append(row.Issues, err.Error())
			status.Backends = append(status.Backends, row)
			continue
		}
		current, exists := all[m.name]
		row.ChainPresent = exists
		row.Referenced = exists && len(current.jumps) > 0
		row.Ordered = exists && len(current.jumps) == 1 && current.positions[0] <= leadingOwned(s, all)
		for i, l := range tracked {
			if l.family != 0 && l.family != b.family {
				continue
			}
			effective := effectiveInput(s, all, l)
			if effective == "blocked" || effective == "unknown" && status.Listeners[i].EffectiveStatus != "blocked" {
				status.Listeners[i].EffectiveStatus = effective
			}
			if !exists || !row.Ordered || !allowsListener(current, l) {
				status.Listeners[i].Allowed = false
				status.Listeners[i].RuleStatus = "missing"
				status.Listeners[i].Issues = append(status.Listeners[i].Issues, "IPv"+b.key()+": "+l.transport+" port "+strconv.Itoa(l.port)+" has no effective Node permission before host filtering")
			}
		}
		selected := listenersForFamily(want, b.family)
		if len(selected) == 0 {
			row.Allowed = !exists
			if exists {
				row.Issues = append(row.Issues, "stale Node permissions exist for an inactive listener family")
			}
		} else {
			row.Allowed = exists && row.Ordered && sameBody(current, m.desiredMany(selected))
			if !exists {
				row.Issues = append(row.Issues, "Node-owned INPUT chain is missing")
			} else {
				if !row.Referenced {
					row.Issues = append(row.Issues, "Node chain is not referenced from INPUT")
				} else if !row.Ordered {
					row.Issues = append(row.Issues, "Node INPUT reference is displaced or duplicated; an earlier REJECT, DROP or host chain can block traffic")
				}
				if !sameBody(current, m.desiredMany(selected)) {
					row.Issues = append(row.Issues, "Node permissions differ from running TCP/UDP listeners or the terminal RETURN is missing")
				}
			}
		}
		if !row.Allowed {
			status.Healthy = false
		}
		status.Issues = append(status.Issues, row.Issues...)
		status.Backends = append(status.Backends, row)
	}
	for _, l := range want {
		if l.family != 0 && !available[l.family] || l.family == 0 && !available[4] && !available[6] {
			problem(errUnavailable)
			break
		}
	}
	return finish()
}

// The first RETURN ends evaluation, so permissions appended after it do not
// count even when the complete chain is otherwise strictly owner-marked.
func allowsListener(current ownedChain, l *listener) bool {
	address := ""
	if l.address.IsValid() {
		address = l.address.String() + "/" + strconv.Itoa(l.address.BitLen())
	}
	for _, rule := range current.rules {
		if jumpTarget(rule) == "RETURN" {
			return false
		}
		parsed, ok := parseOwned(rule, "ACCEPT")
		if ok && parsed.port == l.port && parsed.transport == l.transport && parsed.address == address {
			return true
		}
	}
	return false
}
