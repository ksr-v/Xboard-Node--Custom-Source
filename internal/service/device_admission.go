package service

import (
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/deviceadmission"
)

type admissionKernel interface {
	SetDeviceAdmissionFunc(func(userUUID, sourceIP string) (release func(), err error))
}

type sourceIPKernel interface {
	HasUserSourceIP(userUUID, sourceIP string) bool
}

// installDeviceAdmission is called after initial panel discovery and interval
// selection, before starting the kernel. Unsupported panels install no hook.
func (s *Service) installDeviceAdmission() bool {
	provider, ok := s.source.(controlplane.DeviceAdmissionProvider)
	if !ok {
		return false
	}
	client := provider.DeviceAdmission()
	if client == nil {
		return false
	}
	k, ok := s.kernel.(admissionKernel)
	if !ok {
		return false
	}
	if s.pushInterval == 0 || s.pushInterval > 5 {
		s.pushInterval = 5
	}
	if s.cfg.Node.TrackInterval == 0 || s.cfg.Node.TrackInterval > 1 {
		s.cfg.Node.TrackInterval = 1
	}
	if s.cfg.Node.DeviceReportInterval == 0 || s.cfg.Node.DeviceReportInterval > 5 {
		s.cfg.Node.DeviceReportInterval = 5
	}
	var presence func(string, string) bool
	if tracked, ok := s.kernel.(sourceIPKernel); ok {
		presence = tracked.HasUserSourceIP
	}
	manager := deviceadmission.New(client, s.pushInterval, presence)
	k.SetDeviceAdmissionFunc(manager.Acquire)
	s.deviceLeaseGuard = newDeviceLeaseGuard(time.Now())
	return true
}
