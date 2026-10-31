//go:build !linux

package portforward

import "fmt"

type unsupportedSystem struct{}

func newSystem() system                   { return unsupportedSystem{} }
func (unsupportedSystem) available() bool { return false }
func (unsupportedSystem) lease(string) (func(), error) {
	return nil, fmt.Errorf("automatic Hysteria2 UDP port forwarding requires Linux nftables; no host changes were made")
}
func (unsupportedSystem) lock() (func(), error) {
	return nil, fmt.Errorf("automatic Hysteria2 UDP port forwarding requires Linux nftables; no host changes were made")
}
func (unsupportedSystem) snapshot(string, string) ([]byte, error) {
	return nil, fmt.Errorf("Linux nftables is required")
}
func (unsupportedSystem) apply(string) error { return fmt.Errorf("Linux nftables is required") }
func (unsupportedSystem) verify(*redirect, []int) error {
	return fmt.Errorf("Linux nftables is required")
}
