// Package edge is the deliberately small, stateless-at-rest forwarding node.
// It owns sockets and short-lived authorization snapshots only; cloud storage
// and account policy remain in the cloud binary.
package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"drafrp/internal/acl"
	"drafrp/internal/limiter"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"github.com/quic-go/quic-go"
)

type Config struct {
	CloudURL       string        `json:"cloud_url"`
	EdgeID         string        `json:"edge_id"`
	Token          string        `json:"token"`
	CAFile         string        `json:"ca_file"`
	CertFile       string        `json:"cert_file"`
	KeyFile        string        `json:"key_file"`
	ListenHost     string        `json:"listen_host"`
	CertServerName string        `json:"cert_server_name"`
	SyncInterval   time.Duration `json:"sync_interval"`
	BootID         string        `json:"boot_id"`
	LogLevel       string        `json:"log_level"`
}

func (c *Config) defaults() {
	if c.SyncInterval <= 0 {
		c.SyncInterval = 20 * time.Second
	}
	if c.ListenHost == "" {
		c.ListenHost = "0.0.0.0"
	}
	if c.BootID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		c.BootID = hex.EncodeToString(b)
	}
}

type Runtime struct {
	cfg      Config
	mu       sync.RWMutex
	snap     model.EdgeSnapshot
	rules    map[string]*ruleRuntime
	carriers map[string]*protocol.Carrier
	usage    map[string]*usageCounter
	closed   chan struct{}
	wg       sync.WaitGroup
	ready    atomic.Bool
}
type ruleRuntime struct {
	rule   model.Rule
	acl    *acl.Policy
	grant  model.Grant
	bucket *limiter.Bucket
	conns  *limiter.Connections
}
type usageCounter struct {
	mu       sync.Mutex
	seq      uint64
	up, down int64
	closed   bool
	last     time.Time
}

func New(c Config) *Runtime {
	c.defaults()
	return &Runtime{cfg: c, rules: map[string]*ruleRuntime{}, carriers: map[string]*protocol.Carrier{}, usage: map[string]*usageCounter{}, closed: make(chan struct{})}
}
func (r *Runtime) Close() {
	select {
	case <-r.closed:
		return
	default:
		close(r.closed)
	}
	r.mu.Lock()
	for _, c := range r.carriers {
		_ = c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}
func (r *Runtime) Snapshot() model.EdgeSnapshot { r.mu.RLock(); defer r.mu.RUnlock(); return r.snap }
func (r *Runtime) Ready() bool                  { return r.ready.Load() }
func (r *Runtime) Sync(ctx context.Context) error {
	if r.cfg.CloudURL == "" || r.cfg.EdgeID == "" || r.cfg.Token == "" {
		return errors.New("cloud_url, edge_id and token are required")
	}
	client, e := protocol.HTTPClient(r.cfg.CAFile)
	if e != nil {
		return e
	}
	r.mu.RLock()
	req := model.EdgeSyncRequest{EdgeID: r.cfg.EdgeID, BootID: r.cfg.BootID, AppliedRevision: r.snap.Revision}
	for _, c := range r.usage {
		c.mu.Lock()
		req.Usage = append(req.Usage, model.Usage{GrantID: "", Sequence: c.seq, UploadBytes: c.up, DownloadBytes: c.down, Closed: c.closed, ObservedAt: c.last})
		c.mu.Unlock()
	}
	r.mu.RUnlock()
	b, _ := json.Marshal(req)
	url := strings.TrimRight(r.cfg.CloudURL, "/") + "/api/v1/runtime/edge/sync"
	hr, e := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(b)))
	if e != nil {
		return e
	}
	hr.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	hr.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(hr)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("cloud sync: HTTP %s", resp.Status)
	}
	var s model.EdgeSnapshot
	if e = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&s); e != nil {
		return e
	}
	if s.Edge.ID != "" && s.Edge.ID != r.cfg.EdgeID {
		return errors.New("cloud returned wrong edge")
	}
	r.apply(s)
	return nil
}
func (r *Runtime) apply(s model.EdgeSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt) {
		r.ready.Store(false)
		return
	}
	r.snap = s
	valid := map[string]model.Grant{}
	for _, g := range s.Grants {
		valid[g.ID] = g
	}
	next := map[string]*ruleRuntime{}
	for _, v := range s.Rules {
		if !v.Enabled || v.Protocol != "tcp" && v.Protocol != "udp" {
			continue
		}
		var pol *acl.Policy
		if v.ACL != nil {
			pol, _ = acl.Compile(*v.ACL)
		}
		g := valid[v.TenantID+":"+s.Edge.ID]
		if g.ID == "" {
			for _, x := range s.Grants {
				if x.TenantID == v.TenantID {
					g = x
					break
				}
			}
		}
		rr := &ruleRuntime{rule: v, acl: pol, grant: g, bucket: limiter.New(g), conns: limiter.NewConnections(g.MaxConnections)}
		next[v.ID] = rr
	}
	for id, old := range r.rules {
		if n := next[id]; n == nil || n.rule.Version != old.rule.Version || n.rule.Enabled == false {
			r.closeRuleLocked(id)
		}
	}
	r.rules = next
	r.ready.Store(true)
	r.ensureListenersLocked()
}
func (r *Runtime) closeRuleLocked(id string) {
	for k, c := range r.carriers {
		if strings.HasPrefix(k, id+"/") {
			_ = c.Close()
			delete(r.carriers, k)
		}
	}
}
func (r *Runtime) ensureListenersLocked() {
	for _, rr := range r.rules {
		key := rr.rule.ID
		switch rr.rule.Protocol {
		case "tcp":
			if _, ok := r.carriers["listen/"+key]; !ok {
				ln, e := net.Listen("tcp", net.JoinHostPort(r.cfg.ListenHost, strconv.Itoa(rr.rule.PublicPort)))
				if e != nil {
					log.Printf("edge rule %s listen: %v", key, e)
					continue
				}
				r.carriers["listen/"+key] = nil
				r.wg.Add(1)
				go r.acceptTCP(rr, ln)
			}
		case "udp":
			if _, ok := r.carriers["listen/"+key]; !ok {
				pc, e := net.ListenPacket("udp", net.JoinHostPort(r.cfg.ListenHost, strconv.Itoa(rr.rule.PublicPort)))
				if e != nil {
					log.Printf("edge rule %s UDP listen: %v", key, e)
					continue
				}
				r.carriers["listen/"+key] = nil
				r.wg.Add(1)
				go r.acceptUDP(rr, pc)
			}
		}
	}
}
func (r *Runtime) pickCarrier(rule model.Rule) (*protocol.Carrier, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.carriers {
		if c != nil && c.Device.DeviceID == rule.DeviceID && c.Done() != nil {
			return c, nil
		}
	}
	return nil, errors.New("client offline")
}
func (r *Runtime) allow(rr *ruleRuntime, peer net.Addr) bool {
	if rr.acl == nil {
		return true
	}
	host, port, _ := net.SplitHostPort(peer.String())
	ip, e := netipParse(host)
	if e != nil {
		return false
	}
	p, _ := strconv.Atoi(port)
	ok, _ := rr.acl.Allow(ip, rr.rule.Protocol, p)
	return ok
}
func netipParse(s string) (netip.Addr, error) { return netip.ParseAddr(s) }
func (r *Runtime) acceptTCP(rr *ruleRuntime, ln net.Listener) {
	defer r.wg.Done()
	for {
		conn, e := ln.Accept()
		if e != nil {
			return
		}
		if !r.allow(rr, conn.RemoteAddr()) || !rr.conns.Acquire() {
			_ = conn.Close()
			continue
		}
		r.wg.Add(1)
		go func() { defer r.wg.Done(); defer rr.conns.Release(); r.forwardTCP(rr, conn) }()
	}
}
func (r *Runtime) forwardTCP(rr *ruleRuntime, conn net.Conn) {
	defer conn.Close()
	c, e := r.pickCarrier(rr.rule)
	if e != nil {
		return
	}
	s, e := c.Open(context.Background())
	if e != nil {
		return
	}
	defer protocol.Abort(s)
	c.AddActive(1)
	defer c.AddActive(-1)
	flow := protocol.Flow{RuleID: rr.rule.ID, Version: rr.rule.Version, ID: protocol.FlowID(), Protocol: "tcp", Peer: conn.RemoteAddr().String()}
	if e = protocol.WriteJSON(s, flow); e != nil {
		return
	}
	if e = pipeConn(conn, s, rr.bucket, nil); e != nil {
		return
	}
}

// ConnOrStream is kept internal to make forwarding code explicit for both TCP and QUIC.
type ConnOrStream interface {
	io.ReadWriter
	SetDeadline(time.Time) error
}

func copyBound(dst io.Writer, src io.Reader, b *limiter.Bucket, usage *usageCounter) error {
	buf := make([]byte, 32<<10)
	for {
		n, e := src.Read(buf)
		if n > 0 {
			if b != nil && !b.Wait(n, time.Now().Add(5*time.Second)) {
				return errors.New("rate limit")
			}
			if _, w := dst.Write(buf[:n]); w != nil {
				return w
			}
			if usage != nil {
				usage.mu.Lock()
				usage.up += int64(n)
				usage.mu.Unlock()
			}
		}
		if e != nil {
			if e == io.EOF {
				return nil
			}
			return e
		}
	}
}
func pipeConn(a, b ConnOrStream, bucket *limiter.Bucket, usage *usageCounter) error {
	err := make(chan error, 2)
	go func() { err <- copyBound(b, a, bucket, usage) }()
	go func() { err <- copyBound(a, b, bucket, usage) }()
	return <-err
}
func (r *Runtime) acceptUDP(rr *ruleRuntime, pc net.PacketConn) {
	defer r.wg.Done()
	buf := make([]byte, 64<<10)
	type flow struct {
		conn net.Conn
		last time.Time
	}
	flows := map[string]flow{}
	for {
		n, peer, e := pc.ReadFrom(buf)
		if e != nil {
			return
		}
		if !r.allow(rr, peer) || !rr.conns.Acquire() {
			continue
		}
		c, e := r.pickCarrier(rr.rule)
		if e != nil {
			rr.conns.Release()
			continue
		}
		id := protocol.FlowID()
		s, e := c.Open(context.Background())
		if e != nil {
			rr.conns.Release()
			continue
		}
		_ = protocol.WriteJSON(s, protocol.Flow{RuleID: rr.rule.ID, Version: rr.rule.Version, ID: id, Protocol: "udp", Peer: peer.String()})
		_ = protocol.WritePacket(s, buf[:n])
		flows[peer.String()+"/"+strconv.FormatUint(id, 10)] = flow{conn: nil, last: time.Now()}
		go func() {
			defer rr.conns.Release()
			defer protocol.Abort(s)
			for {
				b, e := protocol.ReadPacket(s)
				if e != nil {
					return
				}
				_, _ = pc.WriteTo(b, peer)
			}
		}()
	}
}

// ServeCarrier authenticates an incoming QUIC/TLS carrier and serves agent streams.
func (r *Runtime) ServeCarrier(ctx context.Context, c *protocol.Carrier) {
	lookup := func(id string) (model.DeviceGrant, bool) {
		r.mu.RLock()
		defer r.mu.RUnlock()
		for _, d := range r.snap.Devices {
			if d.DeviceID == id {
				return d, true
			}
		}
		return model.DeviceGrant{}, false
	}
	if err := protocol.AuthenticateEdge(ctx, c, lookup); err != nil {
		_ = c.Close()
		return
	}
	r.mu.Lock()
	key := protocol.ID()
	r.carriers[key] = c
	r.mu.Unlock()
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer c.Close()
		for {
			st, e := c.Accept(ctx)
			if e != nil {
				return
			}
			r.wg.Add(1)
			go func() { defer r.wg.Done(); r.serveAgentStream(st) }()
		}
	}()
}
func (r *Runtime) serveAgentStream(st protocol.Stream) {
	defer protocol.Abort(st)
	var f protocol.Flow
	if e := protocol.ReadJSON(st, &f); e != nil {
		return
	}
	r.mu.RLock()
	rr := r.rules[f.RuleID]
	r.mu.RUnlock()
	if rr == nil || rr.rule.Version != f.Version || rr.rule.Protocol != "tcp" {
		return
	}
	target, e := net.DialTimeout("tcp", rr.rule.Target, 8*time.Second)
	if e != nil {
		return
	}
	defer target.Close()
	_ = protocol.WriteJSON(st, protocol.Result{})
	_ = pipeConn(target, st, rr.bucket, nil)
}

func ListenQUIC(cfg Config, addr string) (*quic.Listener, error) {
	cert, e := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if e != nil {
		return nil, e
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}
	return quic.ListenAddr(addr, tc, protocol.QUICConfig())
}
func (r *Runtime) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path != "/healthz" {
			http.NotFound(w, q)
			return
		}
		if !r.Ready() {
			http.Error(w, "edge snapshot unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

var _ = os.ErrClosed
