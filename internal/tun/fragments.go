package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

const maxAssemblies = 64
const fragmentLifetime = 2 * time.Second

type fragmentKey struct {
	addresses [8]byte
	id        uint16
	protocol  byte
}
type span struct{ start, end int }
type fragmentAssembly struct {
	data               []byte
	header             []byte
	ranges             []span
	expected, received int
	expires            time.Time
}
type assembler struct {
	pending map[fragmentKey]*fragmentAssembly
}

// Linux can refragment a DNAT'ed datagram to its original fragment size even
// when the TUN MTU is larger. Reassembly precedes tuple admission. The entire
// namespace has at most 64 x (MaxPacketSize-20) bytes, 64 parts per packet and two seconds.
// Overlaps, inconsistent lengths/options and invalid fragment headers fail
// closed; partial IP packets never reach an Agent or an ACL decision.
func (a *assembler) push(b []byte, now time.Time) ([]byte, error) {
	if len(b) < 20 || len(b) > MaxPacketSize || b[0] != 0x45 || int(binary.BigEndian.Uint16(b[2:4])) != len(b) || checksum(b[:20]) != 0 {
		return nil, errors.New("tun: invalid fragment header")
	}
	flags := binary.BigEndian.Uint16(b[6:8])
	if flags&0x8000 != 0 {
		return nil, errors.New("tun: reserved IPv4 flag")
	}
	if flags&0x3fff == 0 {
		return b, nil
	}
	if b[9] != 6 && b[9] != 17 || flags&0x4000 != 0 {
		return nil, errors.New("tun: unsupported fragmented protocol")
	}
	start := int(flags&0x1fff) * 8
	end := start + len(b) - 20
	more := flags&0x2000 != 0
	if end > MaxPacketSize-20 || end <= start || more && (len(b)-20)%8 != 0 {
		return nil, errors.New("tun: invalid fragment extent")
	}
	if a.pending == nil {
		a.pending = make(map[fragmentKey]*fragmentAssembly)
	}
	for k, v := range a.pending {
		if !now.Before(v.expires) {
			delete(a.pending, k)
		}
	}
	k := fragmentKey{[8]byte(b[12:20]), binary.BigEndian.Uint16(b[4:6]), b[9]}
	v := a.pending[k]
	if v == nil {
		if len(a.pending) >= maxAssemblies {
			return nil, errors.New("tun: fragment assembly capacity")
		}
		v = &fragmentAssembly{data: make([]byte, MaxPacketSize-20), expected: -1, expires: now.Add(fragmentLifetime)}
		a.pending[k] = v
	}
	invalid := func() ([]byte, error) {
		delete(a.pending, k)
		return nil, errors.New("tun: overlapping or inconsistent fragments")
	}
	if len(v.ranges) >= 64 || v.expected >= 0 && end > v.expected {
		return invalid()
	}
	for _, r := range v.ranges {
		if start == r.start && end == r.end && bytes.Equal(v.data[start:end], b[20:]) {
			return nil, nil
		}
		if start < r.end && end > r.start {
			return invalid()
		}
	}
	if !more {
		if v.expected >= 0 && v.expected != end {
			return invalid()
		}
		for _, r := range v.ranges {
			if r.end > end {
				return invalid()
			}
		}
		v.expected = end
	}
	copy(v.data[start:end], b[20:])
	v.ranges = append(v.ranges, span{start, end})
	v.received += end - start
	if start == 0 {
		v.header = append([]byte(nil), b[:20]...)
	}
	if v.header == nil || v.expected < 0 || v.received != v.expected {
		return nil, nil
	}
	out := make([]byte, 20+v.expected)
	copy(out, v.header)
	copy(out[20:], v.data[:v.expected])
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[6], out[7], out[10], out[11] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	delete(a.pending, k)
	return out, nil
}
