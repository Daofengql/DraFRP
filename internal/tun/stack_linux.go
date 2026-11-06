//go:build linux

package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// tunLink sends stack-owned packet views directly to one TUN writev. There is
// no outbound channel, flattening copy, address rewrite or second checksum pass.
type tunLink struct {
	*channel.Endpoint
	m *Manager
}

func packetViews(pkt *stack.PacketBuffer, dst [][]byte) [][]byte {
	views, offset := pkt.AsViewList()
	for v := views.Front(); v != nil; v = v.Next() {
		b := v.AsSlice()
		if offset >= len(b) {
			offset -= len(b)
			continue
		}
		dst = append(dst, b[offset:])
		offset = 0
	}
	return dst
}

func (l *tunLink) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	for i, pkt := range packets.AsSlice() {
		var storage [8][]byte
		if err := l.m.writeViews(packetViews(pkt, storage[:0])); err != nil {
			return i, &tcpip.ErrAborted{}
		}
	}
	return packets.Len(), nil
}

func (m *Manager) writeViews(views [][]byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	select {
	case <-m.failed:
		return m.failure()
	default:
	}
	raw, err := m.file.SyscallConn()
	if err != nil {
		return err
	}
	var writeErr error
	var n int
	err = raw.Write(func(fd uintptr) bool {
		for {
			n, writeErr = unix.Writev(int(fd), views)
			if errors.Is(writeErr, unix.EINTR) {
				continue
			}
			return !errors.Is(writeErr, unix.EAGAIN)
		}
	})
	if err == nil {
		err = writeErr
	}
	size := 0
	for _, b := range views {
		size += len(b)
	}
	if err == nil && n != size {
		err = io.ErrShortWrite
	}
	if err != nil {
		m.failWith(fmt.Errorf("tun: packet write: %w", err))
	}
	return err
}

func (m *Manager) initStack() error {
	m.netstack = stack.New(stack.Options{
		// Loopback targets return through our private TUN as well. The manager
		// validates the complete return tuple before giving packets to this NIC.
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true})},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	m.link = &tunLink{Endpoint: channel.New(0, MTU, ""), m: m}
	if e := m.netstack.CreateNIC(1, m.link); e != nil {
		return errors.New(e.String())
	}
	if e := m.netstack.SetSpoofing(1, true); e != nil {
		return errors.New(e.String())
	}
	if e := m.netstack.SetPromiscuousMode(1, true); e != nil {
		return errors.New(e.String())
	}
	m.netstack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	sack := tcpip.TCPSACKEnabled(true)
	if e := m.netstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); e != nil {
		return errors.New(e.String())
	}
	return nil
}

func (m *Manager) deliverStack(b []byte) {
	// The TUN read buffer is reused. Give the asynchronous TCP stack exactly
	// one owned copy, after validating the complete authorized return tuple.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	pkt.RXChecksumValidated = true // Parse already verified the full transport checksum.
	m.link.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

func (m *Manager) Dial(ctx context.Context, network string, target, peer netip.AddrPort) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := m.open(network, target, peer, true)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if !m.available() {
		m.mu.Unlock()
		_ = f.Close()
		return nil, errors.New("tun: closed during target dial")
	}
	m.dialWG.Add(1)
	m.mu.Unlock()
	defer m.dialWG.Done()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	defer cancel()
	local := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(peer.Addr().As4()), Port: peer.Port()}
	remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(target.Addr().As4()), Port: target.Port()}
	var conn net.Conn
	if network == "tcp" {
		conn, err = m.dialTCP(ctx, local, remote)
	} else {
		conn, err = gonet.DialUDP(m.netstack, &local, &remote, ipv4.ProtocolNumber)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	m.mu.Lock()
	if !m.available() || ctx.Err() != nil {
		m.mu.Unlock()
		_ = conn.Close()
		_ = f.Close()
		return nil, errors.New("tun: closed during target dial")
	}
	f.conn = conn
	m.mu.Unlock()
	return &tunConn{Conn: conn, flow: f}, nil
}

// Own every endpoint from creation, including bind and cancellation failures.
// A zero linger releases target TCP state on full Close; CloseWrite still
// performs an ordinary FIN so requests and responses can finish independently.
func (m *Manager) dialTCP(ctx context.Context, local, remote tcpip.FullAddress) (_ net.Conn, result error) {
	var q waiter.Queue
	ep, e := m.netstack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &q)
	if e != nil {
		return nil, errors.New(e.String())
	}
	defer func() {
		if result != nil {
			ep.Close()
		}
	}()
	ep.SocketOptions().SetLinger(tcpip.LingerOption{Enabled: true})
	entry, notify := waiter.NewChannelEntry(waiter.WritableEvents)
	q.EventRegister(&entry)
	defer q.EventUnregister(&entry)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e = ep.Bind(local); e != nil {
		return nil, fmt.Errorf("tun: bind: %s", e)
	}
	e = ep.Connect(remote)
	if _, started := e.(*tcpip.ErrConnectStarted); started {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-notify:
			e = ep.LastError()
		}
	}
	if e != nil {
		return nil, fmt.Errorf("tun: connect: %s", e)
	}
	return gonet.NewTCPConn(&q, ep), nil
}

type tunConn struct {
	net.Conn
	flow *Flow
	once sync.Once
	err  error
}

func (c *tunConn) Close() error {
	c.once.Do(func() { c.err = c.flow.Close() })
	return c.err
}

func (c *tunConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return c.Close()
}
