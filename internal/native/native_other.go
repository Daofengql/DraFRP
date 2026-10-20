//go:build !linux

package native

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

type Manager struct{}

func New(Config) (*Manager, error) {
	return nil, errors.New("native transparent sockets are verified only on Linux")
}
func (*Manager) Capabilities() []string { return nil }
func (*Manager) Dial(context.Context, string, netip.AddrPort, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("native transparent sockets are unsupported on this platform")
}
func (*Manager) Close() error { return nil }
