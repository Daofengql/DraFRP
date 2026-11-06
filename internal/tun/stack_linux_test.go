//go:build linux

package tun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestClientStackTCPIdentityPayloadAndHalfClose(t *testing.T) {
	privileged(t)
	m := newTestManager(t)
	origin, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	peer := netip.MustParseAddrPort("203.0.113.51:41001")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := m.Dial(ctx, "tcp", origin.Addr().(*net.TCPAddr).AddrPort(), peer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	target, err := origin.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	_ = target.SetDeadline(time.Now().Add(4 * time.Second))
	if target.RemoteAddr().String() != peer.String() {
		t.Fatal("visitor tuple changed", target.RemoteAddr())
	}
	payload := bytes.Repeat([]byte("source-preserving-tun"), 7000)
	done := make(chan error, 1)
	go func() {
		got, e := io.ReadAll(target)
		if e == nil && !bytes.Equal(got, payload) {
			e = errors.New("request changed")
		}
		if e == nil {
			_, e = target.Write(got)
		}
		if e == nil {
			e = target.CloseWrite()
		}
		done <- e
	}()
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("half-closed response changed: bytes=%d err=%v", len(got), err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClientStackUDPLargeAndEmptyDatagrams(t *testing.T) {
	privileged(t)
	m := newTestManager(t)
	origin, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	_ = origin.SetDeadline(time.Now().Add(5 * time.Second))
	peer := netip.MustParseAddrPort("203.0.113.52:41002")
	c, err := m.Dial(context.Background(), "udp", origin.LocalAddr().(*net.UDPAddr).AddrPort(), peer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	for _, payload := range [][]byte{nil, []byte("small"), bytes.Repeat([]byte{0x93}, 60000)} {
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		n, from, e := origin.ReadFromUDPAddrPort(buf)
		if e != nil || from != peer || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("UDP target tuple/payload: %s %v", from, e)
		}
		if _, err = origin.WriteToUDPAddrPort(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		n, err = c.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("UDP return bytes=%d err=%v", n, err)
		}
	}
}

func TestClientStackCanceledHandshakeReleasesTuple(t *testing.T) {
	privileged(t)
	m := newTestManager(t)
	origin, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	target := origin.Addr().(*net.TCPAddr).AddrPort()
	args := []string{"INPUT", "-i", m.owned.Interface, "-p", "tcp", "--dport", strconv.Itoa(int(target.Port())), "-j", "DROP"}
	if err = fw("filter", append([]string{"-I"}, args...)...); err != nil {
		t.Fatal(err)
	}
	defer fw("filter", append([]string{"-D"}, args...)...)
	peer := netip.MustParseAddrPort("203.0.113.53:41003")
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if c, e := m.Dial(ctx, "tcp", target, peer); e == nil {
		c.Close()
		t.Fatal("blocked handshake succeeded")
	}
	if err = fw("filter", append([]string{"-D"}, args...)...); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	c, err := m.Dial(ctx2, "tcp", target, peer)
	if err != nil {
		t.Fatal("canceled handshake leaked its tuple", err)
	}
	_ = c.Close()
}

func TestClientStackFailureClosesActiveReaders(t *testing.T) {
	privileged(t)
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			m := newTestManager(t)
			var target netip.AddrPort
			if network == "tcp" {
				l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				target = l.Addr().(*net.TCPAddr).AddrPort()
			} else {
				l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				target = l.LocalAddr().(*net.UDPAddr).AddrPort()
			}
			c, err := m.Dial(context.Background(), network, target, netip.MustParseAddrPort("203.0.113.54:41004"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			done := make(chan error, 1)
			go func() { var b [1]byte; _, e := c.Read(b[:]); done <- e }()
			if _, err = run("ip", "link", "delete", "dev", m.owned.Interface); err != nil {
				t.Fatal(err)
			}
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("failed link returned success")
				}
			case <-time.After(time.Second):
				t.Fatal("failed link left active read blocked")
			}
			if err = m.Close(); err != nil {
				t.Fatal(err)
			}
			_ = c.Close() // Must not recreate the recovery file after Manager.Close.
			if _, err = os.Stat(statePath(m.cfg.StateDir)); !os.IsNotExist(err) {
				t.Fatal("connection close recreated ownership state", err)
			}
		})
	}
}

func viewPacket() *stack.PacketBuffer {
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: 40, Payload: buffer.MakeWithData(bytes.Repeat([]byte{0x75}, 1460))})
	copy(p.TransportHeader().Push(20), bytes.Repeat([]byte{0x34}, 20))
	copy(p.NetworkHeader().Push(20), bytes.Repeat([]byte{0x45}, 20))
	return p
}

func TestPacketViewsMatchOwnedFlattening(t *testing.T) {
	p := viewPacket()
	defer p.DecRef()
	flat := p.ToView()
	defer flat.Release()
	var storage [8][]byte
	if !bytes.Equal(bytes.Join(packetViews(p, storage[:0]), nil), flat.AsSlice()) {
		t.Fatal("scatter/gather changed packet headers or payload")
	}
}

func BenchmarkTUNPacketPreparation(b *testing.B) {
	p := viewPacket()
	defer p.DecRef()
	b.Run("flatten-copy", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(p.Size()))
		for b.Loop() {
			v := p.ToView()
			if v.Size() != p.Size() {
				b.Fatal("size")
			}
			v.Release()
		}
	})
	b.Run("borrowed-writev-views", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(p.Size()))
		for b.Loop() {
			var storage [8][]byte
			views := packetViews(p, storage[:0])
			if len(views) == 0 {
				b.Fatal("empty")
			}
		}
	})
}
