// Package tun implements the Linux client's opt-in IPv4 source-preserving
// target connection. The edge and carrier exchange application data only.
package tun

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// A normal link MTU makes the target kernel perform PMTU/fragmentation before
// capture. Reassembly is local to the client and bounded to the IPv4 size.
const MTU = 1500
const MaxPacketSize = 65535

type Config struct {
	StateDir    string   `json:"state_dir"`
	ReturnCIDRs []string `json:"return_cidrs,omitempty"`
	MaxFlows    int      `json:"max_flows,omitempty"`
}

type Packet struct {
	Bytes        []byte
	Source, Dest netip.AddrPort
	Protocol     string
	Header       int
	Transport    int
	Flags        byte
}

func Parse(b []byte) (Packet, error) {
	p := Packet{Bytes: b}
	if len(b) < 20 || len(b) > MaxPacketSize || b[0]>>4 != 4 {
		return p, errors.New("tun: bounded IPv4 packet required")
	}
	h := int(b[0]&15) * 4
	// IPv4 options (including source routing) are deliberately unsupported:
	// the validated destination must be the address the kernel actually uses.
	if h != 20 || int(binary.BigEndian.Uint16(b[2:4])) != len(b) || checksum(b[:h]) != 0 || b[8] == 0 {
		return p, errors.New("tun: invalid IPv4 header")
	}
	if binary.BigEndian.Uint16(b[6:8])&^uint16(0x4000) != 0 {
		return p, errors.New("tun: fragmented packet requires reassembly")
	}
	p.Header = h
	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	if !unicast(src) || !unicast(dst) || len(b)-h < 8 {
		return p, errors.New("tun: invalid IPv4 endpoints")
	}
	p.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(b[h:h+2]))
	p.Dest = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(b[h+2:h+4]))
	if p.Source.Port() == 0 || p.Dest.Port() == 0 {
		return p, errors.New("tun: zero transport port")
	}
	switch b[9] {
	case 6:
		p.Protocol = "tcp"
		if len(b)-h < 20 {
			return p, errors.New("tun: short TCP header")
		}
		p.Transport = int(b[h+12]>>4) * 4
		p.Flags = b[h+13]
		if p.Transport < 20 || p.Transport > len(b)-h || transportChecksum(b, h) != 0 {
			return p, errors.New("tun: invalid TCP header or checksum")
		}
	case 17:
		p.Protocol = "udp"
		p.Transport = 8
		if int(binary.BigEndian.Uint16(b[h+4:h+6])) != len(b)-h || binary.BigEndian.Uint16(b[h+6:h+8]) != 0 && transportChecksum(b, h) != 0 {
			return p, errors.New("tun: invalid UDP length or checksum")
		}
	default:
		return p, errors.New("tun: only IPv4 TCP/UDP is supported")
	}
	return p, nil
}

func unicast(a netip.Addr) bool {
	return a.Is4() && !a.IsUnspecified() && !a.IsMulticast() && a != netip.MustParseAddr("255.255.255.255")
}

// Rewrite retains TCP sequence numbers, flags, options and payload. It never
// creates a second TCP connection or changes the visitor's source port.
func (p Packet) Rewrite(source, dest netip.AddrPort) []byte {
	b := append([]byte(nil), p.Bytes...)
	s, d := source.Addr().As4(), dest.Addr().As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[p.Header:p.Header+2], source.Port())
	binary.BigEndian.PutUint16(b[p.Header+2:p.Header+4], dest.Port())
	fixChecksums(b, p.Header)
	return b
}

// Reset follows RFC 9293's response to a closed connection. Only an observed
// authenticated TCP tuple supplies its sequence/acknowledgement numbers.
func (p Packet) Reset() []byte {
	return p.ResetInto(make([]byte, 40))
}

// ResetInto records only the cancellation header; hot paths need not retain
// or copy the most recent packet payload just to reset its TCP connection.
func (p Packet) ResetInto(b []byte) []byte {
	if p.Protocol != "tcp" || p.Flags&4 != 0 {
		return nil
	}
	b = b[:40]
	clear(b)
	b[0], b[8], b[9], b[32] = 0x45, 64, 6, 0x50
	binary.BigEndian.PutUint16(b[2:4], 40)
	s, d := p.Dest.Addr().As4(), p.Source.Addr().As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], p.Dest.Port())
	binary.BigEndian.PutUint16(b[22:24], p.Source.Port())
	if p.Flags&16 != 0 {
		copy(b[24:28], p.Bytes[p.Header+8:p.Header+12])
		b[33] = 4
	} else {
		ack := binary.BigEndian.Uint32(p.Bytes[p.Header+4:p.Header+8]) + uint32(len(p.Bytes)-p.Header-p.Transport)
		if p.Flags&2 != 0 {
			ack++
		}
		if p.Flags&1 != 0 {
			ack++
		}
		binary.BigEndian.PutUint32(b[28:32], ack)
		b[33] = 20
	}
	fixChecksums(b, 20)
	return b
}

func checksum(b []byte) uint16 { return finishSum(sumBytes(0, b)) }
func sumBytes(s uint32, b []byte) uint32 {
	for len(b) >= 8 {
		word := binary.BigEndian.Uint64(b)
		s += uint32(word>>48) + uint32(word>>32&0xffff) + uint32(word>>16&0xffff) + uint32(word&0xffff)
		b = b[8:]
	}
	for len(b) >= 4 {
		word := binary.BigEndian.Uint32(b)
		s += (word >> 16) + (word & 0xffff)
		b = b[4:]
	}
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		s += uint32(b[0]) << 8
	}
	return s
}
func finishSum(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&65535 + s>>16
	}
	return ^uint16(s)
}
func transportChecksum(b []byte, h int) uint16 {
	s := sumBytes(0, b[12:20]) + uint32(b[9]) + uint32(len(b)-h)
	return finishSum(sumBytes(s, b[h:]))
}
func fixChecksums(b []byte, h int) {
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:h]))
	offset := h + 6
	if b[9] == 6 {
		offset = h + 16
	}
	b[offset], b[offset+1] = 0, 0
	s := transportChecksum(b, h)
	if s == 0 && b[9] == 17 {
		s = 65535
	}
	binary.BigEndian.PutUint16(b[offset:offset+2], s)
}
