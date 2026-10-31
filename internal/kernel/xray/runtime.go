package xray

import "github.com/cedar2025/xboard-node/internal/kernel"

func (x *Xray) RuntimeInbounds() ([]kernel.Inbound, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if !x.running.Load() || x.instance == nil {
		return nil, nil
	}
	return kernel.ParseRuntimeInbounds("xray", x.activeConfig)
}
