package controlplane

import "github.com/cedar2025/xboard-node/internal/deviceadmission"

// DeviceAdmissionProvider is optional so local mode and older panels keep their
// existing behavior without expanding the common Source or Kernel interfaces.
type DeviceAdmissionProvider interface {
	DeviceAdmission() deviceadmission.Client
}

func (p *PanelControlPlane) DeviceAdmission() deviceadmission.Client {
	if !p.deviceAdmission {
		return nil
	}
	return p.client
}

func (p *MachinePanelControlPlane) DeviceAdmission() deviceadmission.Client {
	if !p.deviceAdmission {
		return nil
	}
	return p.client
}
