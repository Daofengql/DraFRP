//go:build linux

package shaping

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type ownership struct {
	Owner      string          `json:"owner"`
	Boot       string          `json:"boot"`
	Namespace  string          `json:"namespace"`
	Interface  string          `json:"interface"`
	Index      int             `json:"index"`
	MAC        string          `json:"mac"`
	Handle     string          `json:"handle"`
	RateBPS    int64           `json:"rate_bps"`
	BurstBytes int64           `json:"burst_bytes"`
	LatencyUS  int64           `json:"latency_us"`
	Options    json.RawMessage `json:"options,omitempty"`
}
type qdisc struct {
	Kind    string          `json:"kind"`
	Handle  string          `json:"handle"`
	Root    bool            `json:"root"`
	Options json.RawMessage `json:"options"`
}
type Manager struct {
	mu       sync.Mutex
	cfg      Config
	owned    ownership
	status   Status
	lock     *os.File
	failed   chan struct{}
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	closeErr error
}

func tc(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "tc", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return b, nil
}
func root(interfaceName string) (qdisc, error) {
	b, err := tc("-j", "-d", "qdisc", "show", "dev", interfaceName)
	if err != nil {
		return qdisc{}, err
	}
	var all []qdisc
	if err = json.Unmarshal(b, &all); err != nil {
		return qdisc{}, err
	}
	var roots []qdisc
	for _, q := range all {
		if q.Root {
			roots = append(roots, q)
		}
	}
	if len(roots) != 1 {
		return qdisc{}, errors.New("expected exactly one root qdisc")
	}
	return roots[0], nil
}
func kernelDefault(q qdisc) bool {
	if q.Handle != "0:" {
		return false
	}
	switch q.Kind {
	case "noqueue", "fq_codel", "pfifo_fast", "mq":
		return true
	}
	return false
}

var burstPattern = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([KMGT]?)b/[0-9]+$`)

func burstSize(s string) (int64, error) {
	m := burstPattern.FindStringSubmatch(s)
	if m == nil {
		return 0, errors.New("unrecognized tc burst")
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, err
	}
	for i := 0; i < strings.Index(" KMGT", m[2]); i++ {
		v *= 1024
	}
	return int64(v), nil
}
func matches(q qdisc, o ownership) bool {
	if q.Kind != "tbf" || q.Handle != o.Handle || !q.Root {
		return false
	}
	if len(o.Options) > 0 {
		return string(q.Options) == string(o.Options)
	}
	var options struct {
		Rate    int64  `json:"rate"`
		Burst   string `json:"burst"`
		Latency int64  `json:"lat"`
	}
	if json.Unmarshal(q.Options, &options) != nil {
		return false
	}
	b, err := burstSize(options.Burst)
	return err == nil && options.Rate == o.RateBPS/8 && b == o.BurstBytes && abs(options.Latency-o.LatencyUS) <= 1000
}
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
func sameInterface(a, b ownership) bool {
	return a.Boot == b.Boot && a.Namespace == b.Namespace && a.Interface == b.Interface && a.Index == b.Index && a.MAC == b.MAC
}
func validOwnership(o ownership) bool {
	b, err := hex.DecodeString(o.Owner)
	if err != nil || len(b) != 16 {
		return false
	}
	handle := strconv.FormatUint(uint64(b[0])<<8|uint64(b[1]), 16) + ":"
	return o.Handle == handle && o.Handle != "0:" && o.Interface != "" && o.Index > 0 && o.Boot != "" && o.Namespace != "" && o.RateBPS > 0 && o.BurstBytes > 0 && o.LatencyUS > 0
}
func (m *Manager) statePath() string { return filepath.Join(m.cfg.StateDir, "wire-shaping.json") }
func (m *Manager) persist() error {
	b, err := json.Marshal(m.owned)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.cfg.StateDir, ".wire-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, m.statePath())
}
func New(c Config) (m *Manager, err error) {
	if err = c.defaults(); err != nil {
		return nil, err
	}
	if _, err = exec.LookPath("tc"); err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return nil, err
	}
	if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 || int64(iface.MTU) > c.BurstBytes {
		return nil, errors.New("wire interface must be up, non-loopback and burst must cover its MTU")
	}
	if err = os.MkdirAll(c.StateDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(c.StateDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("wire state_dir must be a private directory, without group/world write")
	}
	lock, err := os.OpenFile(filepath.Join(c.StateDir, "wire-shaping.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("wire shaping state is already in use")
	}
	m = &Manager{cfg: c, lock: lock, failed: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	defer func() {
		if err != nil {
			_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
			_ = lock.Close()
		}
	}()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	// Reserve a nonzero handle. The state file and exact qdisc signature supply
	// ownership proof; the handle alone is never sufficient for recovery.
	if random[0] == 0 && random[1] == 0 {
		random[0] = 0xda
	}
	owner := hex.EncodeToString(random[:])
	handle := strconv.FormatUint(uint64(random[0])<<8|uint64(random[1]), 16) + ":"
	m.owned = ownership{Owner: owner, Boot: strings.TrimSpace(string(boot)), Namespace: ns, Interface: c.Interface, Index: iface.Index, MAC: iface.HardwareAddr.String(), Handle: handle, RateBPS: c.RateBPS, BurstBytes: c.BurstBytes, LatencyUS: c.Latency.Microseconds()}
	q, err := root(c.Interface)
	if err != nil {
		return nil, err
	}
	if b, e := os.ReadFile(m.statePath()); e == nil {
		var old ownership
		if json.Unmarshal(b, &old) != nil || !validOwnership(old) {
			return nil, errors.New("invalid wire ownership state; refusing qdisc mutation")
		}
		if !kernelDefault(q) {
			if !sameInterface(old, m.owned) || !matches(q, old) {
				return nil, errors.New("wire recovery ownership mismatch; preserving existing qdisc")
			}
			if _, err = tc("qdisc", "del", "dev", c.Interface, "root", "handle", old.Handle); err != nil {
				return nil, err
			}
			q, err = root(c.Interface)
			if err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if !kernelDefault(q) {
		return nil, errors.New("wire interface has an existing non-default qdisc; refusing to replace it")
	}
	if err = m.persist(); err != nil {
		return nil, err
	}
	if _, err = tc("qdisc", "add", "dev", c.Interface, "root", "handle", m.owned.Handle, "tbf", "rate", strconv.FormatInt(c.RateBPS, 10)+"bit", "burst", strconv.FormatInt(c.BurstBytes, 10), "latency", strconv.FormatInt(c.Latency.Microseconds(), 10)+"us"); err != nil {
		return nil, err
	}
	q, err = root(c.Interface)
	if err != nil {
		return nil, err
	}
	if !matches(q, m.owned) {
		return nil, errors.New("installed wire qdisc could not be verified; ownership state preserved")
	}
	m.owned.Options = append(json.RawMessage{}, q.Options...)
	if err = m.persist(); err != nil {
		return nil, err
	}
	m.refresh()
	if !m.status.Enforced {
		return nil, errors.New(m.status.Error)
	}
	go m.watch()
	return m, nil
}
func counter(name, field string) (uint64, error) {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "statistics", field))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}
func (m *Manager) refresh() {
	s := Status{Interface: m.cfg.Interface, RateBPS: m.cfg.RateBPS, BurstBytes: m.cfg.BurstBytes, ObservedAt: time.Now().UTC()}
	iface, err := net.InterfaceByName(m.cfg.Interface)
	if err == nil && (iface.Index != m.owned.Index || iface.HardwareAddr.String() != m.owned.MAC) {
		err = errors.New("wire interface identity changed")
	}
	var q qdisc
	if err == nil {
		q, err = root(m.cfg.Interface)
	}
	if err == nil && !matches(q, m.owned) {
		err = errors.New("wire qdisc ownership/signature changed")
	}
	if err == nil {
		s.TXBytes, err = counter(m.cfg.Interface, "tx_bytes")
	}
	if err == nil {
		s.RXBytes, err = counter(m.cfg.Interface, "rx_bytes")
	}
	if err == nil {
		s.Enforced = true
	} else {
		s.Error = err.Error()
	}
	m.mu.Lock()
	m.status = s
	m.mu.Unlock()
}
func (m *Manager) watch() {
	defer close(m.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.refresh()
			if !m.Status().Enforced {
				close(m.failed)
				return
			}
		}
	}
}
func (m *Manager) Status() Status          { m.mu.Lock(); defer m.mu.Unlock(); return m.status }
func (m *Manager) Failed() <-chan struct{} { return m.failed }
func (m *Manager) Close() error {
	m.once.Do(func() {
		close(m.stop)
		<-m.done
		q, err := root(m.cfg.Interface)
		if err == nil && !kernelDefault(q) {
			iface, e := net.InterfaceByName(m.cfg.Interface)
			if e != nil || iface.Index != m.owned.Index || iface.HardwareAddr.String() != m.owned.MAC || !matches(q, m.owned) {
				err = errors.New("wire cleanup ownership mismatch; preserving existing qdisc")
			} else {
				_, err = tc("qdisc", "del", "dev", m.cfg.Interface, "root", "handle", m.owned.Handle)
			}
		}
		if err == nil {
			err = os.Remove(m.statePath())
			if os.IsNotExist(err) {
				err = nil
			}
		}
		m.closeErr = err
		_ = unix.Flock(int(m.lock.Fd()), unix.LOCK_UN)
		_ = m.lock.Close()
	})
	return m.closeErr
}
