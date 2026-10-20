//go:build !linux

package shaping

import "errors"

type Manager struct{}

func New(Config) (*Manager, error) {
	return nil, errors.New("wire shaping requires Linux with tc and CAP_NET_ADMIN")
}
func (*Manager) Status() Status          { return Status{} }
func (*Manager) Failed() <-chan struct{} { return nil }
func (*Manager) Close() error            { return nil }
