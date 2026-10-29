//go:build !linux

package inputfirewall

type unsupportedSystem struct{}

func newSystem() system                                { return unsupportedSystem{} }
func (unsupportedSystem) acquire() error               { return errUnavailable }
func (unsupportedSystem) discover() ([]backend, error) { return nil, errUnavailable }
func (unsupportedSystem) checkNative() error           { return errUnavailable }
func (unsupportedSystem) read(backend) ([]byte, error) { return nil, errUnavailable }
func (unsupportedSystem) apply(backend, string) error  { return errUnavailable }
