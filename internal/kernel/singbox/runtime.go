package singbox

import "github.com/cedar2025/xboard-node/internal/kernel"

func (s *SingBox) RuntimeInbounds() ([]kernel.Inbound, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.box == nil {
		return nil, nil
	}
	return kernel.ParseRuntimeInbounds("sing-box", s.activeConfig)
}
