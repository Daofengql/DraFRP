//go:build linux

package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type ownedNetwork struct {
	Owner    string `json:"owner"`
	Chain    string `json:"chain"`
	Mark     uint32 `json:"mark"`
	Table    int    `json:"table"`
	Priority int    `json:"priority"`
}
type tuple struct {
	protocol     string
	target, peer netip.AddrPort
}
type lease struct {
	tuple     tuple
	conn      net.Conn
	installed bool
	once      sync.Once
	m         *Manager
}
type Manager struct {
	mu           sync.Mutex
	cfg          Config
	owned        ownedNetwork
	returnCIDRs  []netip.Prefix
	flows        map[tuple]*lease
	capabilities []string
	closed       bool
	ctx          context.Context
	cancel       context.CancelFunc
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(b), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}
func ip(args ...string) error { _, err := run("ip", append([]string{"-4"}, args...)...); return err }
func fw(args ...string) error {
	_, err := run("iptables", append([]string{"-w", "2", "-t", "mangle"}, args...)...)
	return err
}
func ownershipPath(dir string) string { return filepath.Join(dir, "native-network.json") }
func validOwned(o ownedNetwork) bool {
	b, err := hex.DecodeString(o.Owner)
	return err == nil && len(b) == 16 && o.Chain == "DFRP_"+o.Owner[:16] && o.Mark&0xff000000 == 0xda000000 && o.Table >= 10000 && o.Table < 30000 && o.Priority >= 10000 && o.Priority < 30000
}

func New(c Config) (*Manager, error) {
	if c.StateDir == "" {
		return nil, errors.New("native state directory is required")
	}
	if c.MaxFlows <= 0 {
		c.MaxFlows = 128
	}
	if c.MaxFlows > 1024 {
		return nil, errors.New("native flow limit exceeds 1024")
	}
	for _, name := range []string{"ip", "iptables"} {
		if _, err := exec.LookPath(name); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{cfg: c, flows: map[tuple]*lease{}, ctx: ctx, cancel: cancel}
	for _, cidr := range c.ReturnCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil || !p.Addr().Is4() {
			cancel()
			return nil, fmt.Errorf("invalid IPv4 native return CIDR %q", cidr)
		}
		m.returnCIDRs = append(m.returnCIDRs, p.Masked())
	}
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		cancel()
		return nil, err
	}
	if b, err := os.ReadFile(ownershipPath(c.StateDir)); err == nil {
		var old ownedNetwork
		if json.Unmarshal(b, &old) != nil || !validOwned(old) {
			cancel()
			return nil, errors.New("invalid native ownership state; refusing to change network objects")
		}
		if err = removeNetwork(old); err != nil {
			cancel()
			return nil, fmt.Errorf("native crash recovery: %w", err)
		}
	} else if !os.IsNotExist(err) {
		cancel()
		return nil, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		cancel()
		return nil, err
	}
	owner := hex.EncodeToString(random[:])
	seed := binary.BigEndian.Uint32(random[:4])
	m.owned = ownedNetwork{Owner: owner, Chain: "DFRP_" + owner[:16], Mark: 0xda000000 | (seed & 0x00ffffff), Table: 10000 + int(seed%20000), Priority: 10000 + int(binary.BigEndian.Uint32(random[4:8])%20000)}
	// Refuse resource collisions rather than flushing or replacing any table.
	routes, err := run("ip", "-4", "route", "show", "table", strconv.Itoa(m.owned.Table))
	if err != nil && !strings.Contains(routes, "FIB table does not exist") {
		cancel()
		return nil, err
	}
	if strings.TrimSpace(routes) != "" && err == nil {
		cancel()
		return nil, errors.New("native routing table collision")
	}
	rules, err := run("ip", "-4", "rule", "show")
	if err != nil {
		cancel()
		return nil, err
	}
	for _, line := range strings.Split(rules, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), strconv.Itoa(m.owned.Priority)+":") {
			cancel()
			return nil, errors.New("native routing priority collision")
		}
	}
	b, _ := json.Marshal(m.owned)
	if err = os.WriteFile(ownershipPath(c.StateDir), b, 0600); err != nil {
		cancel()
		return nil, err
	}
	if err = m.install(); err != nil {
		cancel()
		_ = removeNetwork(m.owned)
		return nil, err
	}
	// Each protocol is actually bound, delivered, and read back independently.
	var probeErrors []error
	for _, network := range []string{"tcp", "udp"} {
		if err = m.probe(network); err == nil {
			m.capabilities = append(m.capabilities, "native_"+network+"_ipv4_ip_port")
		} else {
			probeErrors = append(probeErrors, fmt.Errorf("%s probe: %w", network, err))
		}
	}
	if len(m.capabilities) == 0 {
		_ = m.Close()
		return nil, fmt.Errorf("native_source_unavailable: transparent TCP/UDP loopback return-path verification failed: %w", errors.Join(probeErrors...))
	}
	return m, nil
}
func (m *Manager) install() error {
	o := m.owned
	if err := fw("-N", o.Chain); err != nil {
		return err
	}
	if err := fw("-A", o.Chain, "-m", "comment", "--comment", "drafrp-owned:"+o.Owner, "-j", "RETURN"); err != nil {
		return err
	}
	if err := ip("route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(o.Table)); err != nil {
		return err
	}
	if err := ip("rule", "add", "priority", strconv.Itoa(o.Priority), "fwmark", fmt.Sprintf("0x%x/0xffffffff", o.Mark), "lookup", strconv.Itoa(o.Table)); err != nil {
		return err
	}
	for _, hook := range []string{"OUTPUT", "PREROUTING"} {
		if err := fw("-A", hook, "-m", "comment", "--comment", "drafrp-owned:"+o.Owner, "-j", o.Chain); err != nil {
			return err
		}
	}
	return nil
}
func removeNetwork(o ownedNetwork) error {
	if !validOwned(o) {
		return errors.New("invalid native ownership")
	}
	allRules, err := run("iptables", "-w", "2", "-t", "mangle", "-S")
	if err != nil {
		return err
	}
	var chainRules []string
	for _, line := range strings.Split(allRules, "\n") {
		if line == "-N "+o.Chain || strings.HasPrefix(line, "-A "+o.Chain+" ") {
			chainRules = append(chainRules, line)
		}
	}
	listing := strings.Join(chainRules, "\n")
	if listing == "" {
		// A crash before chain creation has no other network objects. A
		// missing chain with live routing state was changed externally; keep
		// the state file and refuse to guess ownership from table numbers.
		return requireVacantRouting(o)
	}
	if !strings.Contains(listing, "drafrp-owned:"+o.Owner) {
		// Chain creation and the first marker rule are separate commands.
		// Recover that narrow crash window only if the chain is empty and
		// no routing object has been installed yet.
		if strings.TrimSpace(listing) == "-N "+o.Chain {
			if err := requireVacantRouting(o); err != nil {
				return err
			}
			return fw("-X", o.Chain)
		}
		return errors.New("native chain ownership marker mismatch")
	}
	var failures []error
	for _, hook := range []string{"OUTPUT", "PREROUTING"} {
		args := []string{hook, "-m", "comment", "--comment", "drafrp-owned:" + o.Owner, "-j", o.Chain}
		if fw(append([]string{"-C"}, args...)...) == nil {
			if e := fw(append([]string{"-D"}, args...)...); e != nil {
				failures = append(failures, e)
			}
		}
	}
	// Exact deletes preserve unrelated routes, rules and firewall chains.
	// Per-flow port rules share only this private priority/table pair. They
	// must be recovered after process death as well as the fwmark rule.
	for count := 0; count <= 1025; count++ {
		raw, e := run("ip", "-j", "-4", "rule", "show")
		if e != nil {
			failures = append(failures, e)
			break
		}
		var rules []struct {
			Priority int             `json:"priority"`
			Table    json.RawMessage `json:"table"`
		}
		if e = json.Unmarshal([]byte(raw), &rules); e != nil {
			failures = append(failures, e)
			break
		}
		found := false
		for _, r := range rules {
			if r.Priority == o.Priority && strings.Trim(string(r.Table), "\"") == strconv.Itoa(o.Table) {
				found = true
				break
			}
		}
		if !found {
			break
		}
		if count == 1025 {
			failures = append(failures, errors.New("native route rule recovery limit exceeded"))
			break
		}
		if e = ip("rule", "del", "priority", strconv.Itoa(o.Priority), "lookup", strconv.Itoa(o.Table)); e != nil {
			failures = append(failures, e)
			break
		}
	}
	routes, e := run("ip", "-4", "route", "show", "table", strconv.Itoa(o.Table))
	if e == nil && strings.Contains(routes, "local default dev lo") {
		if e = ip("route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(o.Table)); e != nil {
			failures = append(failures, e)
		}
	} else if e != nil && !strings.Contains(routes, "FIB table does not exist") {
		failures = append(failures, e)
	}
	// Keep the ownership marker when cleanup fails, so a later retry still
	// has authoritative proof that these objects belong to this instance.
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if e := fw("-F", o.Chain); e != nil {
		failures = append(failures, e)
	}
	if e := fw("-X", o.Chain); e != nil {
		failures = append(failures, e)
	}
	return errors.Join(failures...)
}

func requireVacantRouting(o ownedNetwork) error {
	routes, err := run("ip", "-4", "route", "show", "table", strconv.Itoa(o.Table))
	if err != nil && !strings.Contains(routes, "FIB table does not exist") {
		return err
	}
	if err == nil && strings.TrimSpace(routes) != "" {
		return errors.New("native ownership chain missing but routing table remains; refusing unproven cleanup")
	}
	raw, err := run("ip", "-j", "-4", "rule", "show")
	if err != nil {
		return err
	}
	var rules []struct {
		Priority int             `json:"priority"`
		Table    json.RawMessage `json:"table"`
	}
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return err
	}
	for _, rule := range rules {
		if rule.Priority == o.Priority && strings.Trim(string(rule.Table), "\"") == strconv.Itoa(o.Table) {
			return errors.New("native ownership chain missing but policy rule remains; refusing unproven cleanup")
		}
	}
	return nil
}
func (m *Manager) Capabilities() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.capabilities...)
}
func (m *Manager) localOrRouted(target netip.Addr) bool {
	if target.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err == nil && p.Addr().Unmap() == target {
				return true
			}
		}
	}
	for _, p := range m.returnCIDRs {
		if p.Contains(target) {
			return true
		}
	}
	return false
}
func (m *Manager) flowArgs(t tuple) []string {
	// Loading conntrack also installs IPv4 defragmentation before mangle, so
	// later UDP return fragments are subject to the same exact tuple rule.
	return []string{"-p", t.protocol, "-s", t.target.Addr().String() + "/32", "--sport", strconv.Itoa(int(t.target.Port())), "-d", t.peer.Addr().String() + "/32", "--dport", strconv.Itoa(int(t.peer.Port())), "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "drafrp-flow:" + m.owned.Owner, "-j", "MARK", "--set-xmark", fmt.Sprintf("0x%x/0xffffffff", m.owned.Mark)}
}
func (m *Manager) guardArgs(t tuple) []string {
	// A wildcard UDP origin may select a different local address for its
	// reply. Capturing that packet as a valid reply would cross target
	// authority; allowing the host route would bypass the edge entirely.
	// Load conntrack for defragmentation, then drop the mismatching source.
	return []string{"-p", "udp", "!", "-s", t.target.Addr().String() + "/32", "--sport", strconv.Itoa(int(t.target.Port())), "-d", t.peer.Addr().String() + "/32", "--dport", strconv.Itoa(int(t.peer.Port())), "-m", "conntrack", "--ctstate", "INVALID,NEW,ESTABLISHED,RELATED,UNTRACKED", "-m", "comment", "--comment", "drafrp-guard:" + m.owned.Owner, "-j", "DROP"}
}
func (m *Manager) routeArgs(t tuple) []string {
	// The kernel selects a route for locally generated replies before the
	// OUTPUT hook. A port-specific rule is therefore required for a 127/8
	// origin; merely marking OUTPUT cannot make that initial route valid.
	args := []string{"priority", strconv.Itoa(m.owned.Priority)}
	if t.protocol != "udp" {
		args = append(args, "from", t.target.Addr().String()+"/32")
	}
	// UDP must also catch wildcard-origin replies whose source address was
	// selected by the host routing table. guardArgs drops any such mismatch;
	// the connected transparent socket accepts only the configured target.
	return append(args, "to", t.peer.Addr().String()+"/32", "ipproto", t.protocol, "sport", strconv.Itoa(int(t.target.Port())), "dport", strconv.Itoa(int(t.peer.Port())), "lookup", strconv.Itoa(m.owned.Table))
}
func (m *Manager) Dial(ctx context.Context, network string, target, peer netip.AddrPort) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("unsupported native protocol")
	}
	if !target.IsValid() || !peer.IsValid() || !target.Addr().Is4() || !peer.Addr().Is4() || target.Port() == 0 || peer.Port() == 0 || target.Addr().IsUnspecified() || peer.Addr().IsUnspecified() || target.Addr().IsMulticast() || peer.Addr().IsMulticast() {
		return nil, errors.New("native IPv4 unicast endpoints required")
	}
	if !m.localOrRouted(target.Addr()) {
		return nil, errors.New("native_return_route_required: remote target is outside native_return_cidrs")
	}
	t := tuple{network, target, peer}
	l := &lease{tuple: t, m: m}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errors.New("native manager closed")
	}
	if len(m.flows) >= m.cfg.MaxFlows {
		m.mu.Unlock()
		return nil, errors.New("native flow capacity")
	}
	if _, exists := m.flows[t]; exists {
		m.mu.Unlock()
		return nil, ErrTupleInUse
	}
	if network == "udp" {
		for existing := range m.flows {
			if existing.protocol == "udp" && existing.peer == peer && existing.target.Port() == target.Port() {
				m.mu.Unlock()
				return nil, ErrTupleInUse
			}
		}
	}
	m.flows[t] = l
	m.mu.Unlock()
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		var e error
		err := c.Control(func(fd uintptr) {
			e = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			if e == nil {
				// Reserve the exact kernel source socket before installing return
				// rules. A competing manager must fail its exclusive bind before
				// it can add a broader UDP guard over another manager's flow.
				e = unix.Bind(int(fd), &unix.SockaddrInet4{Port: int(peer.Port()), Addr: peer.Addr().As4()})
			}
		})
		if err != nil {
			return err
		}
		if e != nil {
			return e
		}
		return m.installFlow(l)
	}}
	conn, err := d.DialContext(dialCtx, network+"4", target.String())
	if err != nil {
		_ = l.Close()
		if errors.Is(err, unix.EADDRINUSE) {
			return nil, fmt.Errorf("%w: %v", ErrTupleInUse, err)
		}
		return nil, err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = conn.Close()
		_ = l.Close()
		return nil, errors.New("native manager closed")
	}
	l.conn = conn
	m.mu.Unlock()
	return &nativeConn{Conn: conn, lease: l}, nil
}

func (m *Manager) installFlow(l *lease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.flows[l.tuple] != l {
		return errors.New("native manager closed")
	}
	t := l.tuple
	if err := ip(append([]string{"rule", "add"}, m.routeArgs(t)...)...); err != nil {
		return err
	}
	if err := fw(append([]string{"-I", m.owned.Chain, "1"}, m.flowArgs(t)...)...); err != nil {
		_ = ip(append([]string{"rule", "del"}, m.routeArgs(t)...)...)
		return err
	}
	if t.protocol == "udp" {
		if err := fw(append([]string{"-I", m.owned.Chain, "1"}, m.guardArgs(t)...)...); err != nil {
			_ = fw(append([]string{"-D", m.owned.Chain}, m.flowArgs(t)...)...)
			_ = ip(append([]string{"rule", "del"}, m.routeArgs(t)...)...)
			return err
		}
	}
	l.installed = true
	return nil
}

type nativeConn struct {
	net.Conn
	lease *lease
}

func (c *nativeConn) Close() error { return c.lease.Close() }
func (c *nativeConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return c.Close()
}
func (l *lease) Close() error {
	var out error
	l.once.Do(func() {
		m := l.m
		m.mu.Lock()
		defer m.mu.Unlock()
		if l.conn != nil {
			out = l.conn.Close()
		}
		if m.flows[l.tuple] == l && l.installed {
			if l.tuple.protocol == "udp" {
				if err := fw(append([]string{"-D", m.owned.Chain}, m.guardArgs(l.tuple)...)...); err != nil {
					out = errors.Join(out, err)
				}
			}
			if err := fw(append([]string{"-D", m.owned.Chain}, m.flowArgs(l.tuple)...)...); err != nil {
				out = errors.Join(out, err)
			}
			if err := ip(append([]string{"rule", "del"}, m.routeArgs(l.tuple)...)...); err != nil {
				out = errors.Join(out, err)
			}
		}
		if m.flows[l.tuple] == l {
			delete(m.flows, l.tuple)
		}
	})
	return out
}
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.cancel()
	var leases []*lease
	for _, l := range m.flows {
		leases = append(leases, l)
	}
	m.mu.Unlock()
	var failures []error
	for _, l := range leases {
		if err := l.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if err := removeNetwork(m.owned); err != nil {
		failures = append(failures, err)
	} else {
		_ = os.Remove(ownershipPath(m.cfg.StateDir))
	}
	return errors.Join(failures...)
}

func (m *Manager) probe(network string) error {
	ctx, cancel := context.WithTimeout(m.ctx, 2*time.Second)
	defer cancel()
	var b [2]byte
	_, _ = rand.Read(b[:])
	peer := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.254"), 30000+binary.BigEndian.Uint16(b[:])%20000)
	const payload = "drafrp-native-source-probe"
	verified := make(chan error, 1)
	var target netip.AddrPort
	if network == "tcp" {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer ln.Close()
		target = ln.Addr().(*net.TCPAddr).AddrPort()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				verified <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if conn.RemoteAddr().String() != peer.String() {
				verified <- errors.New("TCP source tuple differs")
				return
			}
			data := make([]byte, len(payload))
			_, err = io.ReadFull(conn, data)
			if err == nil {
				_, err = conn.Write(data)
			}
			verified <- err
		}()
	} else {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return err
		}
		defer conn.Close()
		target = conn.LocalAddr().(*net.UDPAddr).AddrPort()
		go func() {
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			data := make([]byte, 128)
			n, source, err := conn.ReadFromUDPAddrPort(data)
			if err == nil && source != peer {
				err = errors.New("UDP source tuple differs")
			}
			if err == nil {
				_, err = conn.WriteToUDPAddrPort(data[:n], source)
			}
			verified <- err
		}()
	}
	conn, err := m.Dial(ctx, network, target, peer)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte(payload)); err != nil {
		return err
	}
	data := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, data); err != nil {
		return err
	}
	if string(data) != payload {
		return errors.New("native return-path payload mismatch")
	}
	select {
	case err = <-verified:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
