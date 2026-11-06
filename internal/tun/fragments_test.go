package tun

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func fragment(b []byte, start, end int, more bool) []byte {
	out := append([]byte(nil), b[:20]...)
	out = append(out, b[20+start:20+end]...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	flags := uint16(start / 8)
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(out[6:8], flags)
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	return out
}
func TestFragmentsReassembleOutOfOrderAndDuplicate(t *testing.T) {
	packet := samplePacket(false, bytes.Repeat([]byte("x"), 60000))
	var a assembler
	now := time.Now()
	for i := len(packet) - 20; i > 0; {
		start := max(0, ((i-1)/1480)*1480)
		b := fragment(packet, start, i, i != len(packet)-20)
		out, e := a.push(b, now)
		if e != nil {
			t.Fatal(e)
		}
		if start != 0 {
			if out != nil {
				t.Fatal("incomplete packet delivered")
			}
			if _, e = a.push(b, now); e != nil {
				t.Fatal(e)
			}
		} else if !bytes.Equal(out, packet) {
			t.Fatal("reassembled bytes differ")
		}
		i = start
	}
	if len(a.pending) != 0 {
		t.Fatal("completed assembly retained")
	}
}
func TestFragmentsOverlapExpiryAndCapacity(t *testing.T) {
	b := samplePacket(false, bytes.Repeat([]byte("x"), 3000))
	now := time.Now()
	var a assembler
	if _, e := a.push(fragment(b, 0, 1480, true), now); e != nil {
		t.Fatal(e)
	}
	if _, e := a.push(fragment(b, 8, 1488, true), now); e == nil {
		t.Fatal("overlap accepted")
	}
	for i := 0; i < maxAssemblies; i++ {
		binary.BigEndian.PutUint16(b[4:6], uint16(i))
		fixChecksums(b, 20)
		if _, e := a.push(fragment(b, 0, 1480, true), now); e != nil {
			t.Fatal(e)
		}
	}
	binary.BigEndian.PutUint16(b[4:6], 1000)
	fixChecksums(b, 20)
	if _, e := a.push(fragment(b, 0, 1480, true), now); e == nil {
		t.Fatal("unbounded assembly allocation")
	}
	if _, e := a.push(fragment(b, 0, 1480, true), now.Add(fragmentLifetime)); e != nil || len(a.pending) != 1 {
		t.Fatalf("expired assemblies not released: %v", e)
	}
}
