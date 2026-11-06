//go:build linux

package tun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

func tcpPacket(source, dest netip.AddrPort, seq, ack uint32, flags byte) []byte {
	b := make([]byte, 40)
	b[0], b[8], b[9], b[32], b[33] = 0x45, 64, 6, 0x50, flags
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	s, d := source.Addr().As4(), dest.Addr().As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], source.Port())
	binary.BigEndian.PutUint16(b[22:24], dest.Port())
	binary.BigEndian.PutUint32(b[24:28], seq)
	binary.BigEndian.PutUint32(b[28:32], ack)
	binary.BigEndian.PutUint16(b[34:36], 65535)
	fixChecksums(b, 20)
	return b
}
func udpPacket(source, dest netip.AddrPort, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	s, d := source.Addr().As4(), dest.Addr().As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], source.Port())
	binary.BigEndian.PutUint16(b[22:24], dest.Port())
	binary.BigEndian.PutUint16(b[24:26], uint16(8+len(payload)))
	copy(b[28:], payload)
	fixChecksums(b, 20)
	return b
}
func (m *Manager) probe() error {
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	peer := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.254"), 32768+binary.BigEndian.Uint16(random[:])%32768)
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := m.Dial(ctx, "tcp", ln.Addr().(*net.TCPAddr).AddrPort(), peer)
	if err != nil {
		return fmt.Errorf("TCP TUN target handshake: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = ln.SetDeadline(time.Now().Add(2 * time.Second))
	origin, err := ln.AcceptTCP()
	if err != nil {
		return err
	}
	defer origin.Close()
	_ = origin.SetDeadline(time.Now().Add(2 * time.Second))
	if origin.RemoteAddr().String() != peer.String() {
		return errors.New("TCP visitor identity changed")
	}
	if _, err = conn.Write([]byte("t")); err != nil {
		return err
	}
	var payload [1]byte
	if _, err = io.ReadFull(origin, payload[:]); err != nil || payload[0] != 't' {
		return fmt.Errorf("TCP request failed: %v", err)
	}
	if _, err = origin.Write([]byte("r")); err != nil {
		return err
	}
	if _, err = io.ReadFull(conn, payload[:]); err != nil || payload[0] != 'r' {
		return fmt.Errorf("TCP return failed: %v", err)
	}
	if err = conn.Close(); err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer udp.Close()
	u, err := m.Dial(ctx, "udp", udp.LocalAddr().(*net.UDPAddr).AddrPort(), peer)
	if err != nil {
		return err
	}
	defer u.Close()
	_ = u.SetDeadline(time.Now().Add(2 * time.Second))
	_ = udp.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = u.Write([]byte("probe")); err != nil {
		return err
	}
	buf := make([]byte, 32)
	n, source, err := udp.ReadFromUDPAddrPort(buf)
	if err != nil || source != peer || string(buf[:n]) != "probe" {
		return fmt.Errorf("UDP visitor identity/payload changed: %v", err)
	}
	if _, err = udp.WriteToUDPAddrPort(buf[:n], source); err != nil {
		return err
	}
	n, err = u.Read(buf)
	if err != nil || string(buf[:n]) != "probe" {
		return fmt.Errorf("UDP return failed: %v", err)
	}
	return nil
}
