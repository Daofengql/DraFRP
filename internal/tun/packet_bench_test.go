package tun

import "testing"

var checksumBenchSink uint32

func BenchmarkTUNChecksum(b *testing.B) {
	for _, tc := range []struct {
		name string
		size int
	}{{"mtu", 1480}, {"max", MaxPacketSize - 20}} {
		data := make([]byte, tc.size)
		for i := range data {
			data[i] = byte(i*37 + 13)
		}
		seed := uint32(6 + len(data))
		b.Run(tc.name, func(b *testing.B) {
			b.Run("16bit-reference", func(b *testing.B) {
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					checksumBenchSink = sumBytes16Reference(seed, data)
				}
			})
			b.Run("optimized", func(b *testing.B) {
				b.SetBytes(int64(len(data)))
				b.ReportAllocs()
				for b.Loop() {
					checksumBenchSink = sumBytes(seed, data)
				}
			})
		})
	}
}

func BenchmarkTUNPacketParse(b *testing.B) {
	cases := []struct {
		name    string
		tcp     bool
		payload int
	}{
		{name: "tcp-small", tcp: true, payload: 128},
		{name: "tcp-mtu", tcp: true, payload: 1460},
		{name: "udp-max", payload: 65507},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			payload := make([]byte, tc.payload)
			for i := range payload {
				payload[i] = byte(i*37 + 13)
			}
			packet := samplePacket(tc.tcp, payload)
			b.SetBytes(int64(len(packet)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Parse(packet); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
