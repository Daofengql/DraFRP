//go:build linux

package tun

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
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type tuple struct {
	Protocol string         `json:"protocol"`
	Target   netip.AddrPort `json:"target"`
	Peer     netip.AddrPort `json:"peer"`
}
type ownership struct {
	Owner, Interface, Chain, Namespace string
	Table, Priority                    int
	Flows                              []tuple
}
type Manager struct {
	cfg            Config
	mu             sync.Mutex
	writeMu        sync.Mutex
	file, lock     *os.File
	owned          ownership
	flows          map[tuple]*Flow
	failed         chan struct{}
	failOnce, once sync.Once
	wg             sync.WaitGroup
	dialWG         sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	closed         bool
	closeErr       error
	errMu          sync.Mutex
	dataErr        error
	received       atomic.Uint64
	rejected       atomic.Uint64
	lastReject     string
	netstack       *stack.Stack
	link           *tunLink
}
type Flow struct {
	Packets      <-chan []byte
	queue        chan []byte
	m            *Manager
	t            tuple
	reset        [40]byte
	hasReset     bool
	reservation  *os.File
	stackManaged bool
	conn         net.Conn
	once         sync.Once
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(b), fmt.Errorf("tun: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}
func ip(args ...string) error { _, e := run("ip", append([]string{"-4"}, args...)...); return e }
func fw(table string, args ...string) error {
	_, e := run("iptables", append([]string{"-w", "3", "-t", table}, args...)...)
	return e
}
func absent(err error) bool {
	if err == nil {
		return true
	}
	s := err.Error()
	for _, text := range []string{"No such", "Cannot find device", "does a matching rule exist", "Bad rule", "does not exist", "No chain/target/match"} {
		if strings.Contains(s, text) {
			return true
		}
	}
	return false
}
func namespace() (string, error)  { return os.Readlink("/proc/self/ns/net") }
func statePath(dir string) string { return filepath.Join(dir, "tun-network.json") }

func New(c Config) (_ *Manager, err error) {
	var caps [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err = unix.Capget(&header, &caps[0]); err != nil || caps[unix.CAP_NET_ADMIN/32].Effective&(1<<uint(unix.CAP_NET_ADMIN%32)) == 0 {
		return nil, errors.New("tun: CAP_NET_ADMIN is required")
	}
	if !filepath.IsAbs(c.StateDir) {
		return nil, errors.New("tun: an absolute private state_dir is required")
	}
	if c.MaxFlows == 0 {
		c.MaxFlows = 128
	}
	if c.MaxFlows < 1 || c.MaxFlows > 1024 {
		return nil, errors.New("tun: max_flows must be 1..1024")
	}
	for _, text := range c.ReturnCIDRs {
		p, e := netip.ParsePrefix(text)
		if e != nil || !p.Addr().Is4() {
			return nil, errors.New("tun: IPv4 return_cidrs required")
		}
	}
	if b, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); e != nil || strings.TrimSpace(string(b)) != "1" {
		return nil, errors.New("tun: enable IPv4 forwarding in the dedicated network namespace before startup")
	}
	if b, e := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter"); e != nil || strings.TrimSpace(string(b)) == "1" {
		return nil, errors.New("tun: strict global rp_filter is incompatible; configure the dedicated namespace first")
	}
	if err = os.MkdirAll(c.StateDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(c.StateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("tun: state_dir must be a private directory (0700)")
	}
	lock, err := os.OpenFile(filepath.Join(c.StateDir, "tun.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("tun: state directory is already in use")
	}
	m := &Manager{cfg: c, lock: lock, flows: map[tuple]*Flow{}, failed: make(chan struct{})}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			_ = m.Close()
		}
	}()
	ns, err := namespace()
	if err != nil {
		return nil, err
	}
	if b, e := os.ReadFile(statePath(c.StateDir)); e == nil {
		if err = json.Unmarshal(b, &m.owned); err != nil {
			return nil, err
		}
		if err = m.cleanup(ns); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	owner := hex.EncodeToString(random[:])
	m.owned = ownership{Owner: owner, Interface: "drt" + owner[:10], Chain: "DRT" + owner[:12], Namespace: ns, Table: 20000 + int(binary.BigEndian.Uint16(random[:2]))%30000}
	// The return rule must run before Linux's main table (priority 32766).
	// A table identifier is not a safe routing priority.
	m.owned.Priority = 10000 + int(binary.BigEndian.Uint16(random[2:4]))%10000
	if err = m.requireVacant(); err != nil {
		return nil, err
	}
	if err = m.save(); err != nil {
		return nil, err
	}
	for _, table := range []string{"filter"} {
		if err = fw(table, "-N", m.owned.Chain); err != nil {
			return nil, err
		}
		if err = fw(table, "-A", m.owned.Chain, "-m", "comment", "--comment", m.marker()); err != nil {
			return nil, err
		}
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(m.owned.Interface)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	// TUNSETIFF must precede Go's epoll registration: an unattached TUN fd
	// cannot be polled, and NewFile would permanently mark it unpollable.
	m.file = os.NewFile(uintptr(fd), "/dev/net/tun")
	if _, err = run("ip", "link", "set", "dev", m.owned.Interface, "alias", m.marker(), "mtu", strconv.Itoa(MTU), "up"); err != nil {
		return nil, err
	}
	for key, value := range map[string]string{"rp_filter": "0", "route_localnet": "1", "accept_local": "1"} {
		path := "/proc/sys/net/ipv4/conf/" + m.owned.Interface + "/" + key
		current, readErr := os.ReadFile(path)
		if readErr == nil && strings.TrimSpace(string(current)) == value {
			continue
		}
		if err = os.WriteFile(path, []byte(value), 0600); err != nil {
			return nil, err
		}
	}
	if err = ip("route", "add", "table", strconv.Itoa(m.owned.Table), "default", "dev", m.owned.Interface); err != nil {
		return nil, err
	}
	// Referencing conntrack enables IPv4 defragmentation before routing. Invalid
	// fragments never become authorized tuples; the private link fails closed.
	if err = fw("filter", "-A", m.owned.Chain, "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"); err != nil {
		return nil, err
	}
	if err = fw("filter", "-A", m.owned.Chain, "-j", "DROP"); err != nil {
		return nil, err
	}
	for _, hook := range []string{"INPUT", "FORWARD"} {
		if err = fw("filter", "-I", hook, "1", "-i", m.owned.Interface, "-m", "comment", "--comment", m.marker(), "-j", m.owned.Chain); err != nil {
			return nil, err
		}
	}
	if err = m.initStack(); err != nil {
		return nil, err
	}
	m.wg.Add(3)
	go m.read()
	go m.verifyLink()
	go m.stopOnFailure()
	if err = m.probe(); err != nil {
		return nil, fmt.Errorf("tun: kernel return-path verification failed: %w", err)
	}
	return m, nil
}

func (m *Manager) marker() string          { return "drafrp-tun:" + m.owned.Owner }
func (m *Manager) Failed() <-chan struct{} { return m.failed }
func (m *Manager) fail() {
	m.failOnce.Do(func() {
		m.cancel()
		close(m.failed)
	})
}

func (m *Manager) stopOnFailure() {
	defer m.wg.Done()
	<-m.failed
	_ = m.file.Close() // Wake a blocked TUN read/write immediately.
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.flows {
		if f.conn != nil {
			_ = f.conn.Close()
		}
	}
}
func (m *Manager) failWith(err error) {
	m.errMu.Lock()
	if m.dataErr == nil {
		m.dataErr = err
	}
	m.errMu.Unlock()
	m.fail()
}
func (m *Manager) failure() error {
	m.errMu.Lock()
	defer m.errMu.Unlock()
	return fmt.Errorf("tun: data path failed: %v", m.dataErr)
}
func (m *Manager) available() bool {
	if m.closed {
		return false
	}
	select {
	case <-m.failed:
		return false
	default:
		return true
	}
}
func (m *Manager) Capabilities() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available() {
		return nil
	}
	return []string{"native_tcp_ipv4_ip_port", "native_udp_ipv4_ip_port", "tun_client_tcp_ipv4_ip_port", "tun_client_udp_ipv4_ip_port"}
}
func localAddress(a netip.Addr) bool {
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		p, e := netip.ParsePrefix(addr.String())
		if e == nil && p.Addr().Unmap() == a {
			return true
		}
	}
	return false
}
func (m *Manager) save() error {
	b, err := json.Marshal(m.owned)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.cfg.StateDir, "tun-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), statePath(m.cfg.StateDir))
}
func (m *Manager) requireVacant() error {
	raw, err := run("ip", "-j", "-4", "rule", "show")
	if err != nil {
		return err
	}
	var rules []struct {
		Priority int             `json:"priority"`
		Table    json.RawMessage `json:"table"`
	}
	if err = json.Unmarshal([]byte(raw), &rules); err != nil {
		return err
	}
	for _, r := range rules {
		if r.Priority == m.owned.Priority || strings.Trim(string(r.Table), "\"") == strconv.Itoa(m.owned.Table) {
			return errors.New("tun: routing identity already in use; retry startup")
		}
	}
	routes, err := run("ip", "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	var entries []struct {
		Dst   string          `json:"dst"`
		Table json.RawMessage `json:"table"`
	}
	if err = json.Unmarshal([]byte(routes), &entries); err != nil {
		return err
	}
	for _, r := range entries {
		if strings.Trim(string(r.Table), "\"") == strconv.Itoa(m.owned.Table) {
			return errors.New("tun: routing table already in use")
		}
	}
	return nil
}

func (m *Manager) routeArgs(t tuple) []string {
	a := []string{"priority", strconv.Itoa(m.owned.Priority)}
	if t.Protocol == "tcp" {
		a = append(a, "from", t.Target.Addr().String()+"/32")
	}
	return append(a, "to", t.Peer.Addr().String()+"/32", "ipproto", t.Protocol, "sport", strconv.Itoa(int(t.Target.Port())), "dport", strconv.Itoa(int(t.Peer.Port())), "lookup", strconv.Itoa(m.owned.Table))
}
func (m *Manager) flowArgs(t tuple) []string {
	return []string{"-s", t.Peer.Addr().String(), "-d", t.Target.Addr().String(), "-p", t.Protocol, "--sport", strconv.Itoa(int(t.Peer.Port())), "--dport", strconv.Itoa(int(t.Target.Port())), "-j", "ACCEPT"}
}
func (m *Manager) returnGuard(t tuple, hook, action string) []string {
	a := []string{action, hook}
	if action == "-I" {
		a = append(a, "1")
	}
	if t.Protocol == "tcp" {
		a = append(a, "-s", t.Target.Addr().String())
	}
	return append(a, "-d", t.Peer.Addr().String(), "-p", t.Protocol, "--sport", strconv.Itoa(int(t.Target.Port())), "--dport", strconv.Itoa(int(t.Peer.Port())), "!", "-o", m.owned.Interface, "-m", "comment", "--comment", m.marker(), "-j", "DROP")
}
func (m *Manager) Open(network string, target, peer netip.AddrPort) (*Flow, error) {
	return m.open(network, target, peer, false)
}
func (m *Manager) open(network string, target, peer netip.AddrPort, managed bool) (*Flow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available() || network != "tcp" && network != "udp" || !unicast(target.Addr()) || !unicast(peer.Addr()) || target.Port() == 0 || peer.Port() == 0 || localAddress(peer.Addr()) {
		return nil, errors.New("tun: valid nonlocal visitor and IPv4 target required")
	}
	allowed := localAddress(target.Addr())
	for _, text := range m.cfg.ReturnCIDRs {
		p, _ := netip.ParsePrefix(text)
		allowed = allowed || p.Contains(target.Addr())
	}
	if !allowed {
		return nil, errors.New("tun_return_route_required: remote target is outside return_cidrs")
	}
	t := tuple{network, target, peer}
	if len(m.flows) >= m.cfg.MaxFlows {
		return nil, errors.New("tun: flow capacity")
	}
	for existing := range m.flows {
		if existing == t || network == "udp" && existing.Protocol == "udp" && existing.Peer == peer && existing.Target.Port() == target.Port() {
			return nil, errors.New("native_source_tuple_conflict")
		}
	}
	// The kernel reservation also excludes another TUN/transparent process in
	// this namespace. A second owner must never steal an existing return tuple.
	kind := unix.SOCK_STREAM
	if network == "udp" {
		kind = unix.SOCK_DGRAM
	}
	fd, e := unix.Socket(unix.AF_INET, kind|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	reservation := os.NewFile(uintptr(fd), "tun-source-reservation")
	keep := false
	defer func() {
		if !keep {
			reservation.Close()
		}
	}()
	if e = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); e != nil {
		return nil, e
	}
	if e = unix.Bind(fd, &unix.SockaddrInet4{Addr: peer.Addr().As4(), Port: int(peer.Port())}); e != nil {
		return nil, fmt.Errorf("native_source_tuple_conflict: %w", e)
	}
	m.owned.Flows = append(m.owned.Flows, t)
	if err := m.save(); err != nil {
		m.fail()
		return nil, err
	}
	if err := ip(append([]string{"rule", "add"}, m.routeArgs(t)...)...); err != nil {
		m.fail()
		return nil, err
	}
	for _, hook := range []string{"OUTPUT", "FORWARD"} {
		if err := fw("filter", m.returnGuard(t, hook, "-I")...); err != nil {
			m.failWith(err)
			return nil, err
		}
	}
	if err := fw("filter", append([]string{"-I", m.owned.Chain, "1"}, m.flowArgs(t)...)...); err != nil {
		m.fail()
		return nil, err
	}
	var ch chan []byte
	if !managed {
		ch = make(chan []byte, 8)
	}
	f := &Flow{Packets: ch, queue: ch, m: m, t: t, reservation: reservation, stackManaged: managed}
	m.flows[t] = f
	keep = true
	return f, nil
}

func (m *Manager) read() {
	defer m.wg.Done()
	defer m.fail()
	b := make([]byte, 65536)
	var fragments assembler
	for {
		n, err := m.file.Read(b)
		if err != nil {
			m.failWith(fmt.Errorf("device read: %w", err))
			return
		}
		raw := b[:n]
		if n >= 20 && binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			raw, err = fragments.push(raw, time.Now())
		}
		m.received.Add(1)
		if raw == nil && err == nil {
			continue
		}
		var p Packet
		if err == nil {
			p, err = Parse(raw)
		}
		if err != nil {
			m.rejected.Add(1)
			m.errMu.Lock()
			m.lastReject = err.Error()
			m.errMu.Unlock()
			continue
		}
		m.mu.Lock()
		if !m.available() {
			m.mu.Unlock()
			return
		}
		f := m.flows[tuple{p.Protocol, p.Source, p.Dest}]
		managed := f != nil && f.stackManaged
		if f != nil && p.Protocol == "tcp" {
			f.hasReset = p.ResetInto(f.reset[:]) != nil
		}
		if f != nil && !managed {
			select {
			case f.queue <- append([]byte(nil), p.Bytes...):
			default:
			}
		}
		if managed {
			m.deliverStack(p.Bytes)
		}
		m.mu.Unlock()
	}
}

func (m *Manager) Inject(b []byte) error {
	if _, err := Parse(b); err != nil {
		return err
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	select {
	case <-m.failed:
		return m.failure()
	default:
	}
	n, err := m.file.Write(b)
	if err != nil {
		m.fail()
		return err
	}
	if n != len(b) {
		m.fail()
		return io.ErrShortWrite
	}
	return nil
}
func (f *Flow) Close() error {
	var result error
	f.once.Do(func() {
		m := f.m
		m.mu.Lock()
		defer m.mu.Unlock()
		if f.conn != nil {
			_ = f.conn.Close()
		}
		if m.closed {
			// Manager.Close owns final network cleanup and keeps the source
			// reservation until those routes and guards have been removed.
			return
		}
		if f.hasReset {
			_ = m.Inject(f.reset[:])
		}
		delete(m.flows, f.t)
		if e := fw("filter", append([]string{"-D", m.owned.Chain}, m.flowArgs(f.t)...)...); !absent(e) {
			result = errors.Join(result, e)
		}
		if e := ip(append([]string{"rule", "del"}, m.routeArgs(f.t)...)...); !absent(e) {
			result = errors.Join(result, e)
		}
		for _, hook := range []string{"OUTPUT", "FORWARD"} {
			if e := fw("filter", m.returnGuard(f.t, hook, "-D")...); !absent(e) {
				result = errors.Join(result, e)
			}
		}
		if result == nil {
			for i, t := range m.owned.Flows {
				if t == f.t {
					m.owned.Flows = append(m.owned.Flows[:i], m.owned.Flows[i+1:]...)
					break
				}
			}
			result = m.save()
		}
		if result != nil {
			m.fail()
		}
		_ = f.reservation.Close()
	})
	return result
}

// Recovery uses a private ownership marker and the same network namespace.
// Neither a routing table nor a system firewall chain is ever flushed.
func (m *Manager) cleanup(ns string) error {
	o := m.owned
	if o.Owner == "" {
		return nil
	}
	if len(o.Owner) != 32 || o.Interface != "drt"+o.Owner[:10] || o.Chain != "DRT"+o.Owner[:12] || o.Namespace != ns || o.Table < 20000 || o.Table >= 50000 || o.Priority < 10000 || o.Priority >= 20000 || len(o.Flows) > 1024 {
		return errors.New("tun: invalid ownership or different network namespace; preserving recovery state")
	}
	var result error
	for _, table := range []string{"filter"} {
		raw, e := run("iptables", "-w", "3", "-t", table, "-S", o.Chain)
		if !absent(e) {
			return e
		}
		if e == nil && !strings.Contains(raw, m.marker()) && strings.TrimSpace(raw) != "-N "+o.Chain {
			return errors.New("tun: firewall ownership marker mismatch")
		}
	}
	if alias, e := os.ReadFile("/sys/class/net/" + o.Interface + "/ifalias"); e == nil {
		if strings.TrimSpace(string(alias)) != m.marker() {
			return errors.New("tun: interface ownership marker mismatch")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	for _, t := range o.Flows {
		if e := ip(append([]string{"rule", "del"}, m.routeArgs(t)...)...); !absent(e) {
			result = errors.Join(result, e)
		}
		for _, hook := range []string{"OUTPUT", "FORWARD"} {
			if e := fw("filter", m.returnGuard(t, hook, "-D")...); !absent(e) {
				result = errors.Join(result, e)
			}
		}
	}
	for _, table := range []string{"filter"} {
		if table == "filter" {
			for _, hook := range []string{"INPUT", "FORWARD"} {
				for _, direction := range []string{"-i", "-o"} {
					a := []string{hook, direction, o.Interface, "-m", "comment", "--comment", m.marker(), "-j", o.Chain}
					if fw(table, append([]string{"-C"}, a...)...) == nil {
						if e := fw(table, append([]string{"-D"}, a...)...); e != nil {
							result = errors.Join(result, e)
						}
					}
				}
			}
		}
		if e := fw(table, "-F", o.Chain); !absent(e) {
			result = errors.Join(result, e)
		}
		if e := fw(table, "-X", o.Chain); !absent(e) {
			result = errors.Join(result, e)
		}
	}
	if alias, e := os.ReadFile("/sys/class/net/" + o.Interface + "/ifalias"); e == nil {
		if strings.TrimSpace(string(alias)) != m.marker() {
			return errors.New("tun: interface ownership marker mismatch")
		}
		if _, e = run("ip", "link", "delete", "dev", o.Interface); e != nil {
			result = errors.Join(result, e)
		}
	} else if !os.IsNotExist(e) {
		result = errors.Join(result, e)
	}
	if result == nil {
		if e := os.Remove(statePath(m.cfg.StateDir)); !os.IsNotExist(e) {
			result = e
		}
	}
	return result
}
func (m *Manager) Close() error {
	m.once.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.mu.Unlock()
		m.fail()
		if m.file != nil {
			_ = m.file.Close()
		}
		m.wg.Wait()
		m.dialWG.Wait()
		if m.netstack != nil {
			m.netstack.Close()
			m.netstack.Wait()
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		ns, e := namespace()
		if e == nil {
			e = m.cleanup(ns)
		}
		m.closeErr = e
		for t, f := range m.flows {
			_ = f.reservation.Close()
			delete(m.flows, t)
		}
		if m.lock != nil {
			_ = m.lock.Close()
		}
	})
	return m.closeErr
}
