package service

import (
	"context"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/deviceadmission"
)

type admissionTestSource struct {
	controlplane.Source
	client deviceadmission.Client
}

func (s *admissionTestSource) DeviceAdmission() deviceadmission.Client { return s.client }

type admissionTestClient struct{}

func (*admissionTestClient) AcquireDevice(context.Context, string, string, string, int) error {
	return nil
}
func (*admissionTestClient) ReleaseDevice(context.Context, string, string, string) error { return nil }

type admissionTestKernel struct {
	*fakeKernel
	hook func(string, string) (func(), error)
}

func (k *admissionTestKernel) SetDeviceAdmissionFunc(fn func(string, string) (func(), error)) {
	k.hook = fn
}

func TestInstallDeviceAdmissionKeepsOlderPanelBehavior(t *testing.T) {
	k := &admissionTestKernel{fakeKernel: &fakeKernel{}}
	s := &Service{
		cfg:          &config.Config{Node: config.NodeConfig{TrackInterval: 10, DeviceReportInterval: 30}},
		source:       &admissionTestSource{},
		kernel:       k,
		pushInterval: 60,
	}
	if s.installDeviceAdmission() || k.hook != nil {
		t.Fatal("older panel unexpectedly installed central gate")
	}
	if s.pushInterval != 60 || s.cfg.Node.TrackInterval != 10 || s.cfg.Node.DeviceReportInterval != 30 {
		t.Fatal("older panel intervals changed without capability")
	}
}

func TestInstallDeviceAdmissionConfiguresFastLeasedHeartbeats(t *testing.T) {
	for _, deviceInterval := range []int{0, 1, 30} {
		k := &admissionTestKernel{fakeKernel: &fakeKernel{}}
		s := &Service{
			cfg:          &config.Config{Node: config.NodeConfig{TrackInterval: 10, DeviceReportInterval: deviceInterval}},
			source:       &admissionTestSource{client: &admissionTestClient{}},
			kernel:       k,
			pushInterval: 60,
		}
		if !s.installDeviceAdmission() || k.hook == nil {
			t.Fatal("capable panel did not install central gate")
		}
		wantDeviceInterval := 5
		if deviceInterval == 1 {
			wantDeviceInterval = 1
		}
		if s.pushInterval != 5 || s.cfg.Node.TrackInterval != 1 || s.cfg.Node.DeviceReportInterval != wantDeviceInterval {
			t.Fatalf("unexpected capable panel intervals: push=%d node=%+v", s.pushInterval, s.cfg.Node)
		}
	}
}

func TestInstallDeviceAdmissionRequiresKernelSupport(t *testing.T) {
	s := &Service{
		cfg:          &config.Config{Node: config.NodeConfig{TrackInterval: 10, DeviceReportInterval: 30}},
		source:       &admissionTestSource{client: &admissionTestClient{}},
		kernel:       &fakeKernel{},
		pushInterval: 60,
	}
	if s.installDeviceAdmission() || s.pushInterval != 60 {
		t.Fatal("unsupported kernel changed behavior")
	}
}

type presenceAdmissionKernel struct{ *admissionTestKernel }

func (*presenceAdmissionKernel) HasUserSourceIP(string, string) bool { return true }

type retainingAdmissionTestClient struct{ retained chan struct{} }

func (*retainingAdmissionTestClient) AcquireDevice(context.Context, string, string, string, int) error {
	return nil
}
func (*retainingAdmissionTestClient) ReleaseDevice(context.Context, string, string, string) error {
	return nil
}
func (*retainingAdmissionTestClient) SupportsRetainedDeviceRelease() bool { return true }
func (c *retainingAdmissionTestClient) ReleaseDeviceRetainingIP(context.Context, string, string, string) error {
	c.retained <- struct{}{}
	return nil
}

func TestInstallDeviceAdmissionConnectsKernelPresenceProbe(t *testing.T) {
	k := &presenceAdmissionKernel{admissionTestKernel: &admissionTestKernel{fakeKernel: &fakeKernel{}}}
	client := &retainingAdmissionTestClient{retained: make(chan struct{}, 1)}
	s := &Service{
		cfg:    &config.Config{Node: config.NodeConfig{TrackInterval: 10, DeviceReportInterval: 30}},
		source: &admissionTestSource{client: client}, kernel: k, pushInterval: 60,
	}
	if !s.installDeviceAdmission() {
		t.Fatal("admission was not installed")
	}
	release, err := k.hook("user", "ip")
	if err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-client.retained:
	case <-time.After(time.Second):
		t.Fatal("kernel's remaining source IP was not retained")
	}
}
