package tun

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func sumBytes16Reference(s uint32, b []byte) uint32 {
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) != 0 {
		s += uint32(b[0]) << 8
	}
	return s
}

func TestSumBytesMatches16BitReference(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1500, 4095, MaxPacketSize}
	seeds := []uint32{0, 0x12345678, 0xffffffff}
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*37 + 13)
		}
		for _, seed := range seeds {
			want := sumBytes16Reference(seed, data)
			if got := sumBytes(seed, data); got != want {
				t.Fatalf("sumBytes(size=%d, seed=%#x) = %#x, want %#x", size, seed, got, want)
			}
		}
	}
}

func samplePacket(tcp bool, payload []byte) []byte {
	h := 8
	if tcp {
		h = 24
	}
	b := make([]byte, 20+h+len(payload))
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:20], []byte{203, 0, 113, 10, 198, 18, 0, 1})
	binary.BigEndian.PutUint16(b[20:22], 32123)
	binary.BigEndian.PutUint16(b[22:24], 8080)
	if tcp {
		b[9], b[32], b[33] = 6, 0x60, 0x18
		binary.BigEndian.PutUint32(b[24:28], 12345)
		binary.BigEndian.PutUint32(b[28:32], 67890)
		copy(b[40:44], []byte{1, 1, 1, 1})
	} else {
		binary.BigEndian.PutUint16(b[24:26], uint16(h+len(payload)))
	}
	copy(b[20+h:], payload)
	fixChecksums(b, 20)
	return b
}
func TestPacketRewritePreservesTransportAndPayload(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		payload := bytes.Repeat([]byte("odd"), 19999)
		original := samplePacket(tcp, payload)
		p, err := Parse(original)
		if err != nil {
			t.Fatal(err)
		}
		source, dest := netip.MustParseAddrPort("203.0.113.10:32123"), netip.MustParseAddrPort("127.0.0.1:38081")
		rewritten := p.Rewrite(source, dest)
		q, err := Parse(rewritten)
		if err != nil || q.Source != source || q.Dest != dest {
			t.Fatalf("invalid rewrite: %+v %v", q, err)
		}
		if !bytes.Equal(q.Bytes[q.Header+q.Transport:], payload) {
			t.Fatal("payload changed")
		}
		if tcp && !bytes.Equal(original[24:36], rewritten[24:36]) {
			t.Fatal("TCP sequence, acknowledgement, flags or window changed")
		}
		if bytes.Equal(original, rewritten) {
			t.Fatal("rewrite did not replace destination")
		}
		if _, err := Parse(original); err != nil {
			t.Fatal("rewrite mutated caller buffer")
		}
	}
}
func TestPacketRejectsUntrustedNetworkHeaders(t *testing.T) {
	valid := samplePacket(true, []byte("payload"))
	for name, mutate := range map[string]func([]byte){
		"ipv6":                 func(b []byte) { b[0] = 0x65 },
		"source_route_options": func(b []byte) { b[0] = 0x46 },
		"reserved_flag":        func(b []byte) { b[6] = 0x80; fixChecksums(b, 20) },
		"fragment":             func(b []byte) { b[6] = 0x20; fixChecksums(b, 20) },
		"length":               func(b []byte) { b[3]--; fixChecksums(b, 20) },
		"ttl":                  func(b []byte) { b[8] = 0; fixChecksums(b, 20) },
		"ip_checksum":          func(b []byte) { b[10] ^= 1 },
		"tcp_checksum":         func(b []byte) { b[len(b)-1] ^= 1 },
		"tcp_header":           func(b []byte) { b[32] = 0x40; fixChecksums(b, 20) },
		"zero_port":            func(b []byte) { b[20], b[21] = 0, 0; fixChecksums(b, 20) },
		"multicast":            func(b []byte) { b[12] = 224; fixChecksums(b, 20) },
		"icmp":                 func(b []byte) { b[9] = 1; fixChecksums(b, 20) },
	} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte(nil), valid...)
			mutate(b)
			if _, err := Parse(b); err == nil {
				t.Fatal("unsafe packet accepted")
			}
		})
	}
	for n := 0; n < 44; n++ {
		if _, err := Parse(valid[:n]); err == nil {
			t.Fatalf("truncated %d-byte packet accepted", n)
		}
	}
	if _, err := Parse(make([]byte, MaxPacketSize+1)); err == nil {
		t.Fatal("oversize packet accepted")
	}
}
func TestTCPResetUsesObservedAcknowledgement(t *testing.T) {
	p, err := Parse(samplePacket(true, []byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse(p.Reset())
	if err != nil || r.Source != p.Dest || r.Dest != p.Source || r.Flags != 4 || binary.BigEndian.Uint32(r.Bytes[24:28]) != 67890 {
		t.Fatalf("invalid acknowledged reset: %+v %v", r, err)
	}
	b := samplePacket(true, nil)
	b[33] = 2
	fixChecksums(b, 20)
	p, _ = Parse(b)
	r, err = Parse(p.Reset())
	if err != nil || r.Flags != 20 || binary.BigEndian.Uint32(r.Bytes[28:32]) != 12346 {
		t.Fatal("SYN reset did not acknowledge sequence")
	}
	if r.Reset() != nil {
		t.Fatal("RST must not cause a reset loop")
	}
}
