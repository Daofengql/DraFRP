//go:build !linux

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

type Manager struct{}

func New(Config) (*Manager, error) {
	return nil, errors.New("tun: source IP/port passthrough is supported only on Linux clients; Windows supports ordinary socket forwarding")
}
func (*Manager) Capabilities() []string  { return nil }
func (*Manager) Failed() <-chan struct{} { return nil }
func (*Manager) Close() error            { return nil }
func (*Manager) Dial(context.Context, string, netip.AddrPort, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("tun: Linux client required")
}
