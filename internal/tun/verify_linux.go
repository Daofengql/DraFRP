//go:build linux

package tun

import (
	"errors"
	"net"
	"time"
)

func (m *Manager) verifyLink() {
	defer m.wg.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-m.failed:
			return
		case <-ticker.C:
			link, err := net.InterfaceByName(m.owned.Interface)
			if err != nil || link.Flags&net.FlagUp == 0 || link.MTU != MTU {
				m.failWith(errors.New("tun: owned interface is missing, down or has an unexpected MTU"))
				return
			}
		}
	}
}
