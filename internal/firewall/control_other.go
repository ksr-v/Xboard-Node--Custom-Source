//go:build !linux

package firewall

import "io"

func StartControl() (io.Closer, error) { return nil, ErrControlUnavailable }
func QueryControl(string, string) (ControlResponse, error) {
	return ControlResponse{}, ErrControlUnavailable
}
func persistenceInventory() Persistence {
	return Persistence{Strategy: "rebuild from successful runtime inbounds on Node startup; reconcile periodically; never save host rules"}
}
