// Package edge owns only listeners, authenticated carriers and expiring local
// forwarding state. Durable identity, policy and accounting belong to cloud.
package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"drafrp/internal/acl"
	"drafrp/internal/geoip"
	"drafrp/internal/limiter"
	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"drafrp/internal/shaping"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	CloudURL             string          `json:"cloud_url"`
	EdgeID               string          `json:"edge_id"`
	Token                string          `json:"token"`
	CAFile               string          `json:"ca_file"`
	CertFile             string          `json:"cert_file"`
	KeyFile              string          `json:"key_file"`
	ListenHost           string          `json:"listen_host"`
	CarrierListenHosts   []string        `json:"carrier_listen_hosts,omitempty"`
	HTTPListenHosts      []string        `json:"http_listen_hosts,omitempty"`
	SyncInterval         time.Duration   `json:"sync_interval"`
	BootID               string          `json:"-"`
	MaxConnections       int             `json:"max_connections"`
	MaxUDPSessions       int             `json:"max_udp_sessions"`
	MaxPacketsPerSecond  int             `json:"max_packets_per_second"`
	MaxPendingHandshakes int             `json:"max_pending_handshakes"`
	MaxCarriersPerDevice int             `json:"max_carriers_per_device"`
	UDPIdleTimeout       time.Duration   `json:"udp_idle_timeout"`
	GeoIPFile            string          `json:"geoip_file"`
	WireShaping          *shaping.Config `json:"wire_shaping,omitempty"`
}

func (c *Config) defaults() {
	if c.SyncInterval <= 0 {
		c.SyncInterval = 20 * time.Second
	}
	if c.ListenHost == "" {
		c.ListenHost = "0.0.0.0"
	}
	if c.CarrierListenHosts == nil {
		c.CarrierListenHosts = []string{c.ListenHost}
		if c.ListenHost == "0.0.0.0" {
			c.CarrierListenHosts = append(c.CarrierListenHosts, "::")
		}
	}
	if c.HTTPListenHosts == nil {
		c.HTTPListenHosts = append([]string(nil), c.CarrierListenHosts...)
	}
	if c.BootID == "" {
		c.BootID = protocol.ID()
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 1024
	}
	if c.MaxUDPSessions <= 0 {
		c.MaxUDPSessions = 128
	}
	if c.MaxPacketsPerSecond <= 0 {
		c.MaxPacketsPerSecond = 20000
	}
	if c.MaxPendingHandshakes <= 0 {
		c.MaxPendingHandshakes = 32
	}
	if c.MaxCarriersPerDevice <= 0 {
		c.MaxCarriersPerDevice = 8
	}
	if c.UDPIdleTimeout <= 0 {
		c.UDPIdleTimeout = 30 * time.Second
	}
}

type ruleRuntime struct {
	rule        model.Rule
	policies    []*acl.Policy
	aclRefs     []model.ACLPolicyRef
	aclDigest   string
	policyError string
}
type listenerState struct {
	closer                io.Closer
	kind, ruleID, address string
}
type carrierState struct {
	c        *protocol.Carrier
	endpoint string
}
type flowState struct {
	id         string
	rule       model.Rule
	peer       netip.AddrPort
	generation uint64
	grantID    string
	cancel     context.CancelFunc
	ctx        context.Context
	budget     *accountBudget
	carrier    *protocol.Carrier
	finished   bool
}
type Runtime struct {
	aclMetrics     *aclMetrics
	cfg            Config
	mu             sync.RWMutex
	syncMu         sync.Mutex
	snap           model.EdgeSnapshot
	rules          map[string]*ruleRuntime
	devices        map[string]model.DeviceGrant
	carriers       map[string]carrierState
	listeners      map[string]listenerState
	flows          map[string]*flowState
	budgets        map[string]*accountBudget
	history        map[string]*accountBudget
	statuses       map[string]model.RuleStatus
	listenerErrors map[string]string
	certificates   map[string]*tls.Certificate
	root           *limiter.Bucket
	rootConns      *limiter.Connections
	packetRate     *limiter.Flows
	handshakeSlots chan struct{}
	httpSlots      chan struct{}
	udpSlots       chan struct{}
	http           *http.Client
	initErr        error
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	once           sync.Once
	closing        bool
	scheduler      *capacityScheduler
	geoDB          *geoip.Database
	geoError       string
	shaper         *shaping.Manager
}

func New(c Config) *Runtime {
	c.defaults()
	ctx, cancel := context.WithCancel(context.Background())
	h, e := protocol.HTTPClient(c.CAFile)
	if e == nil {
		e = c.validateListeners()
	}
	r := &Runtime{cfg: c, ctx: ctx, cancel: cancel, http: h, initErr: e, rules: map[string]*ruleRuntime{}, devices: map[string]model.DeviceGrant{}, carriers: map[string]carrierState{}, listeners: map[string]listenerState{}, flows: map[string]*flowState{}, budgets: map[string]*accountBudget{}, history: map[string]*accountBudget{}, statuses: map[string]model.RuleStatus{}, listenerErrors: map[string]string{}, certificates: map[string]*tls.Certificate{}, rootConns: limiter.NewConnections(c.MaxConnections), packetRate: limiter.NewFlows(c.MaxPacketsPerSecond), handshakeSlots: make(chan struct{}, c.MaxPendingHandshakes)}
	if c.WireShaping != nil && r.initErr == nil {
		r.shaper, r.initErr = shaping.New(*c.WireShaping)
	}
	r.scheduler = newCapacityScheduler()
	r.httpSlots = make(chan struct{}, c.MaxConnections)
	r.udpSlots = make(chan struct{}, c.MaxUDPSessions)
	r.wg.Add(2)
	go r.watch()
	go r.schedule()
	return r
}
func (r *Runtime) Config() Config { return r.cfg }
func (r *Runtime) launchLocked(fn func()) bool {
	if r.closing {
		return false
	}
	r.wg.Add(1)
	go func() { defer r.wg.Done(); fn() }()
	return true
}
func (r *Runtime) Close() {
	r.once.Do(func() {
		r.mu.Lock()
		r.closing = true
		r.cancel()
		for _, l := range r.listeners {
			_ = l.closer.Close()
		}
		for _, cs := range r.carriers {
			_ = cs.c.Close()
		}
		for _, f := range r.flows {
			f.cancel()
		}
		for _, b := range r.budgets {
			b.retire()
		}
		r.mu.Unlock()
		r.wg.Wait()
		if r.http != nil {
			r.http.CloseIdleConnections()
		}
		if r.shaper != nil {
			if err := r.shaper.Close(); err != nil {
				log.Printf("wire shaping cleanup: %v", err)
			}
		}
	})
}
func (r *Runtime) Snapshot() model.EdgeSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, _ := json.Marshal(r.snap)
	var s model.EdgeSnapshot
	_ = json.Unmarshal(b, &s)
	return s
}
func (r *Runtime) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closing || !time.Now().Before(r.snap.ExpiresAt) || !r.capacityAvailable() {
		return false
	}
	if len(r.snap.Edge.Endpoints) == 0 {
		return true
	}
	for _, l := range r.listeners {
		if l.kind == "carrier" {
			return true
		}
	}
	return false
}
func (r *Runtime) Sync(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	if r.initErr != nil {
		return r.initErr
	}
	if r.cfg.CloudURL == "" || r.cfg.EdgeID == "" || r.cfg.Token == "" {
		return errors.New("cloud_url, edge_id and token are required")
	}
	r.mu.Lock()
	req := model.EdgeSyncRequest{EdgeID: r.cfg.EdgeID, BootID: r.cfg.BootID, AppliedRevision: r.snap.Revision, Runtime: r.runtimeLocked()}
	req.ACL = r.aclReportLocked()
	r.refreshStatusesLocked()
	for _, st := range r.statuses {
		req.Statuses = append(req.Statuses, st)
	}
	for _, b := range r.history {
		req.Usage = append(req.Usage, b.report())
	}
	r.mu.Unlock()
	body, _ := json.Marshal(req)
	hr, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(r.cfg.CloudURL, "/")+"/api/v1/runtime/edge/sync", strings.NewReader(string(body)))
	if e != nil {
		return e
	}
	hr.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	hr.Header.Set("Content-Type", "application/json")
	res, e := r.http.Do(hr)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		var out struct {
			Error struct{ Code, Message string }
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out)
		return fmt.Errorf("edge sync HTTP %d %s: %s", res.StatusCode, out.Error.Code, out.Error.Message)
	}
	var s model.EdgeSnapshot
	if e = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&s); e != nil {
		return e
	}
	if e = r.apply(s); e != nil {
		r.failedACLApply(s, e)
		return e
	}
	// A successful response acknowledges the exact cumulative reports sent.
	r.mu.Lock()
	r.acknowledgeACLLocked(req.ACL)
	for _, u := range req.Usage {
		if b := r.history[u.GrantID]; b != nil {
			b.acknowledgeMinutes(u)
		}
		if u.Closed {
			if b := r.history[u.GrantID]; b != nil && b.isSettled(u) {
				delete(r.history, u.GrantID)
			}
		}
	}
	r.mu.Unlock()
	return nil
}
func (r *Runtime) apply(s model.EdgeSnapshot) error {
	if r.initErr != nil {
		return r.initErr
	}
	if err := validateCarrierPorts(s.Edge.Endpoints); err != nil {
		return err
	}
	if !r.capacityAvailable() {
		return errors.New("wire shaping verification failed")
	}
	if s.Edge.ID != r.cfg.EdgeID || s.Edge.BootID != r.cfg.BootID || !time.Now().Before(s.ExpiresAt) {
		return errors.New("invalid, expired or wrong-boot edge snapshot")
	}
	if len(s.Rules) > 4096 || len(s.Devices) > 4096 || len(s.Grants) > 4096 || len(s.MandatoryACLs) > 64 {
		return errors.New("snapshot exceeds edge capacity")
	}
	var geo *geoip.Database
	var geoError string
	if r.cfg.GeoIPFile != "" {
		var e error
		geo, e = geoip.Load(r.cfg.GeoIPFile)
		if e != nil {
			geoError = e.Error()
		}
	}
	var lookup func(netip.Addr) (string, string, bool)
	if geo != nil {
		lookup = geo.Lookup
	}
	mandatory := []*acl.Policy{}
	mandatoryRefs := []model.ACLPolicyRef{}
	mandatoryGeoMissing := false
	for _, p := range s.MandatoryACLs {
		compiled, e := acl.CompileWithGeo(p, lookup)
		if e != nil {
			return fmt.Errorf("mandatory ACL: %w", e)
		}
		mandatory = append(mandatory, compiled)
		mandatoryRefs = append(mandatoryRefs, acl.Reference(p, "mandatory_template"))
		mandatoryGeoMissing = mandatoryGeoMissing || compiled.RequiresGeo() && geo == nil
	}
	next := map[string]*ruleRuntime{}
	statuses := map[string]model.RuleStatus{}
	for _, v := range s.Rules {
		if v.ID == "" || v.EdgeID != r.cfg.EdgeID || v.DeviceID == "" || v.TenantID == "" || v.Version == 0 {
			return errors.New("rule identity mismatch in edge snapshot")
		}
		if _, ok := next[v.ID]; ok {
			return errors.New("duplicate rule")
		}
		st := model.RuleStatus{ID: v.ID, Version: v.Version, Status: "waiting_for_agent"}
		rr := &ruleRuntime{rule: v}
		if v.Deleting {
			st.Status = "deleted"
			statuses[v.ID] = st
			continue
		}
		if !v.Enabled {
			st.Status = "disabled"
			statuses[v.ID] = st
			continue
		}
		if v.Protocol == "tcp" || v.Protocol == "udp" {
			if host, _, err := net.SplitHostPort(v.Target); err == nil && strings.ContainsAny(host, ":%[]") {
				rr.policyError = "address_family_unsupported: TCP/UDP target must be an IPv4 address or hostname"
			}
			if v.SourceMode != "socket" && v.SourceMode != "native" {
				rr.policyError = "unsupported source identity mode"
			}
			if v.SourceMode == "native" {
				available := false
				for _, d := range s.Devices {
					if d.DeviceID == v.DeviceID && d.TenantID == v.TenantID && time.Now().Before(d.ExpiresAt) {
						for _, c := range d.Capabilities {
							available = available || c == "native_"+v.Protocol+"_ipv4_ip_port"
						}
					}
				}
				if !available {
					rr.policyError = "capability_missing: verified native IPv4 IP and port capability is unavailable"
				}
			}
			rr.policies = append(rr.policies, mandatory...)
			rr.aclRefs = append(rr.aclRefs, mandatoryRefs...)
			if mandatoryGeoMissing {
				rr.policyError = "capability_missing: mandatory regional ACL requires a valid GeoIP database"
			}
			if v.ACLTemplateID != "" && v.ACL == nil {
				rr.policyError = "required ACL template is unavailable"
			}
			if v.ACL != nil {
				p, e := acl.CompileWithGeo(*v.ACL, lookup)
				if e != nil {
					rr.policyError = "invalid ACL: " + e.Error()
				} else {
					rr.policies = append(rr.policies, p)
					kind := "rule_inline"
					if v.ACLTemplateID != "" {
						kind = "rule_template"
					}
					rr.aclRefs = append(rr.aclRefs, acl.Reference(*v.ACL, kind))
					if p.RequiresGeo() && geo == nil {
						rr.policyError = "capability_missing: regional ACL requires a valid GeoIP database"
					}
				}
			}
		} else if v.Protocol == "http" || v.Protocol == "https" {
			if v.SourceMode != "forwarded_headers" || v.Domain == "" {
				rr.policyError = "invalid HTTP source mode or domain"
			}
		} else {
			rr.policyError = "unsupported protocol"
		}
		rr.aclDigest = acl.EffectiveDigest(v.ID, v.Version, rr.aclRefs)
		if rr.policyError != "" {
			st.Status = "error"
			st.Error = rr.policyError
		}
		next[v.ID] = rr
		statuses[v.ID] = st
	}
	devices := map[string]model.DeviceGrant{}
	for _, d := range s.Devices {
		if d.DeviceID == "" || d.TenantID == "" || d.SessionID == "" || d.Generation == 0 {
			return errors.New("invalid device grant")
		}
		if _, ok := devices[d.DeviceID]; ok {
			return errors.New("duplicate device grant")
		}
		devices[d.DeviceID] = d
	}
	certs := map[string]*tls.Certificate{}
	for _, c := range s.Certificates {
		pair, e := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
		if e != nil {
			return fmt.Errorf("certificate %s: %w", c.ID, e)
		}
		pair.Leaf, e = x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			return e
		}
		if _, duplicate := certs[c.ID]; duplicate || c.ID == "" {
			return errors.New("duplicate or empty certificate ID")
		}
		certs[c.ID] = &pair
	}
	valid := map[string]bool{}
	for _, g := range s.Grants {
		if g.ID == "" || g.TenantID == "" || g.EdgeID != r.cfg.EdgeID || g.BootID != r.cfg.BootID || g.Bytes < 0 || g.Bytes > 1<<60 || g.BaseBPS < -1 || g.PeakBPS < -1 || g.BurstBytes < 0 || g.MaxConnections < -1 || g.NewFlowsPerSecond < -1 {
			return errors.New("invalid grant identity, credit or limit")
		}
		if valid[g.TenantID] {
			return errors.New("duplicate tenant budget")
		}
		valid[g.TenantID] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return errors.New("edge closed")
	}
	if s.Revision < r.snap.Revision {
		return errors.New("snapshot revision moved backwards")
	}
	// Validate all renewable balances before changing any current authority.
	for _, g := range s.Grants {
		if b := r.budgets[g.TenantID]; b != nil && b.id() == g.ID {
			if e := b.canUpdate(g); e != nil {
				return e
			}
		} else if _, replayed := r.history[g.ID]; replayed {
			return errors.New("retired grant cannot be reloaded")
		}
	}
	// A ready observation is preserved only for this exact rule version and while
	// the authoritative device, carrier and resource grant are still available.
	for id, st := range statuses {
		old, ok := r.statuses[id]
		if ok && old.Version == st.Version && old.Status == "ready" && st.Error == "" && st.Status == "waiting_for_agent" {
			st.Status = "ready"
			statuses[id] = st
		}
	}
	r.snap = s
	r.geoDB, r.geoError = geo, geoError
	r.rules = next
	r.devices = devices
	r.certificates = certs
	r.statuses = statuses
	for _, g := range s.Grants {
		if b := r.budgets[g.TenantID]; b != nil && b.id() == g.ID {
			if e := b.update(g); e != nil {
				return e
			}
		} else {
			if b != nil {
				b.retire()
			}
			b := newAccountBudget(g)
			r.budgets[g.TenantID] = b
			r.history[g.ID] = b
		}
	}
	for tid, b := range r.budgets {
		if !valid[tid] {
			b.retire()
			delete(r.budgets, tid)
		}
	}
	rootGrant := model.Grant{BaseBPS: s.Edge.CapacityBPS, PeakBPS: s.Edge.CapacityBPS, BurstBytes: 64 << 10, ExpiresAt: s.ExpiresAt}
	if r.root == nil {
		r.root = limiter.New(rootGrant)
	} else {
		r.root.Update(rootGrant)
	}
	r.reconcileLocked()
	r.ensureListenersLocked()
	r.refreshStatusesLocked()
	r.appliedACLLocked(s)
	return nil
}
func (r *Runtime) watch() {
	defer r.wg.Done()
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			r.mu.Lock()
			r.reconcileLocked()
			r.refreshStatusesLocked()
			r.mu.Unlock()
		}
	}
}
func (r *Runtime) deviceValidLocked(c *protocol.Carrier) bool {
	d, ok := r.devices[c.Device.DeviceID]
	return ok && time.Now().Before(d.ExpiresAt) && d.SessionID == c.Device.SessionID && d.Generation == c.Device.Generation && d.TenantID == c.Device.TenantID
}
func (r *Runtime) reconcileLocked() {
	valid := time.Now().Before(r.snap.ExpiresAt) && !r.closing && r.capacityAvailable()
	for key, cs := range r.carriers {
		closed := false
		select {
		case <-cs.c.Done():
			closed = true
		default:
		}
		if !valid || closed || !r.deviceValidLocked(cs.c) {
			_ = cs.c.Close()
			delete(r.carriers, key)
		}
	}
	for _, f := range r.flows {
		rr := r.rules[f.rule.ID]
		if !valid || rr == nil || rr.rule.Version != f.rule.Version || rr.rule.DeviceID != f.rule.DeviceID || rr.policyError != "" || !r.deviceValidLocked(f.carrier) || !f.budget.valid() || r.budgets[f.rule.TenantID] != f.budget || !rr.allow(f.peer) {
			f.cancel()
		}
	}
	if !valid {
		for key, l := range r.listeners {
			_ = l.closer.Close()
			delete(r.listeners, key)
		}
		return
	}
	for key, l := range r.listeners {
		if l.ruleID != "" {
			rr := r.rules[l.ruleID]
			if rr == nil || rr.policyError != "" || l.address != r.ruleAddress(rr.rule) || l.kind != rr.rule.Protocol {
				_ = l.closer.Close()
				delete(r.listeners, key)
			}
		}
	}
}
func (rr *ruleRuntime) allow(peer netip.AddrPort) bool {
	if rr.policyError != "" {
		return false
	}
	if rr.rule.Protocol != "tcp" && rr.rule.Protocol != "udp" {
		return true
	}
	for _, p := range rr.policies {
		if ok, _ := p.Allow(peer.Addr(), rr.rule.Protocol, int(peer.Port())); !ok {
			return false
		}
	}
	return true
}
func (r *Runtime) ruleAddress(rule model.Rule) string {
	return net.JoinHostPort(r.cfg.ListenHost, strconv.Itoa(rule.PublicPort))
}
func (r *Runtime) pickCarrierLocked(rule model.Rule) *protocol.Carrier {
	var chosen *protocol.Carrier
	for _, cs := range r.carriers {
		c := cs.c
		if c.Device.DeviceID != rule.DeviceID || c.Device.TenantID != rule.TenantID || !r.deviceValidLocked(c) {
			continue
		}
		if rule.Transport == "quic_only" && c.Transport != "quic" || rule.Transport == "tls_only" && c.Transport != "tls" {
			continue
		}
		select {
		case <-c.Done():
			continue
		default:
		}
		if chosen == nil || preferCarrier(c, chosen) {
			chosen = c
		}
	}
	return chosen
}
func (r *Runtime) refreshStatusesLocked() {
	for id, rr := range r.rules {
		st := r.statuses[id]
		if !r.capacityAvailable() {
			st.Status = "error"
			st.Error = "wire_shaping_unavailable"
		} else if rr.policyError != "" {
			st.Status = "error"
			st.Error = rr.policyError
		} else if !time.Now().Before(r.snap.ExpiresAt) {
			st.Status = "error"
			st.Error = "authorization_expired"
		} else if _, ok := r.listeners["rule/"+id]; (rr.rule.Protocol == "tcp" || rr.rule.Protocol == "udp") && !ok {
			st.Status = "error"
			st.Error = r.listenerErrors["rule/"+id]
		} else if rr.rule.Protocol == "http" || rr.rule.Protocol == "https" {
			port := r.snap.Edge.HTTPPort
			if rr.rule.Protocol == "https" {
				port = r.snap.Edge.HTTPSPort
			}
			if listening, err := r.siteListening(rr.rule.Protocol, port); !listening {
				st.Status = "error"
				st.Error = "site_listener_unavailable: " + err
				r.statuses[id] = st
				continue
			}
			// Continue through the shared carrier and budget checks below.
			r.statuses[id] = r.availableStatusLocked(rr.rule, st)
			continue
		} else if r.pickCarrierLocked(rr.rule) == nil {
			st.Status = "waiting_for_agent"
			st.Error = ""
		} else if b := r.budgets[rr.rule.TenantID]; b == nil || !b.valid() {
			st.Status = "quota_exhausted"
			st.Error = "account budget unavailable or exhausted"
		} else if st.Status != "ready" && st.Status != "error" {
			st.Status = "listening"
			st.Error = ""
		}
		r.statuses[id] = st
	}
}
func (r *Runtime) availableStatusLocked(rule model.Rule, st model.RuleStatus) model.RuleStatus {
	if r.pickCarrierLocked(rule) == nil {
		st.Status, st.Error = "waiting_for_agent", ""
	} else if b := r.budgets[rule.TenantID]; b == nil || !b.valid() {
		st.Status, st.Error = "quota_exhausted", "account budget unavailable or exhausted"
	} else if st.Status != "ready" && st.Status != "error" {
		st.Status, st.Error = "listening", ""
	}
	return st
}
func (r *Runtime) markStatus(rule model.Rule, state string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rr := r.rules[rule.ID]; rr == nil || rr.rule.Version != rule.Version {
		return
	}
	st := model.RuleStatus{ID: rule.ID, Version: rule.Version, Status: state}
	if err != nil {
		st.Error = err.Error()
	}
	r.statuses[rule.ID] = st
}
func (r *Runtime) ServeCarrier(ctx context.Context, c *protocol.Carrier) {
	r.mu.Lock()
	if !r.launchLocked(func() { r.serveCarrier(ctx, c, "") }) {
		_ = c.Close()
	}
	r.mu.Unlock()
}
func (r *Runtime) serveCarrier(ctx context.Context, c *protocol.Carrier, endpoint string) {
	defer c.Close()
	select {
	case r.handshakeSlots <- struct{}{}:
	default:
		return
	}
	lookup := func(id string) (model.DeviceGrant, bool) {
		r.mu.RLock()
		defer r.mu.RUnlock()
		d, ok := r.devices[id]
		return d, ok && time.Now().Before(r.snap.ExpiresAt)
	}
	err := protocol.AuthenticateEdge(ctx, c, lookup)
	<-r.handshakeSlots
	if err != nil {
		return
	}
	r.mu.Lock()
	if r.closing || !r.deviceValidLocked(c) {
		r.mu.Unlock()
		return
	}
	count := 0
	for _, cs := range r.carriers {
		if cs.c.Device.DeviceID == c.Device.DeviceID {
			count++
		}
	}
	if count >= r.cfg.MaxCarriersPerDevice || len(r.carriers) >= r.snap.Edge.MaxCarriers {
		r.mu.Unlock()
		return
	}
	key := protocol.ID()
	c.EstablishedAt = time.Now()
	r.carriers[key] = carrierState{c, endpoint}
	r.refreshStatusesLocked()
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.carriers, key); r.mu.Unlock() }()
	authorized := func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return !r.closing && time.Now().Before(r.snap.ExpiresAt) && r.deviceValidLocked(c)
	}
	if c.ReverseProbeSupported() {
		probeCtx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); c.ObserveQuality(probeCtx, authorized) }()
		defer func() { stop(); <-done }()
	}
	// Business streams remain edge-initiated. Agent streams can only echo the
	// negotiated fixed control probe, under renewable device authorization.
	// A synchronous handler bounds incoming control concurrency to one per
	// carrier and leaves business opening/flow permits available.
	for {
		st, e := c.Accept(ctx)
		if e != nil {
			return
		}
		c.HandleProbe(ctx, st, authorized)
	}
}
func ListenQUIC(cfg Config, addr string) (*quic.Listener, error) {
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return quic.ListenAddr(addr, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}, protocol.QUICConfig())
}

type boundQUICListener struct {
	*quic.Listener
	transport *quic.Transport
	packet    net.PacketConn
}

func (l *boundQUICListener) Close() error {
	err := l.Listener.Close()
	_ = l.transport.Close()
	_ = l.packet.Close()
	return err
}
func listenQUICNetwork(cfg Config, network, addr string) (*boundQUICListener, error) {
	pair, e := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if e != nil {
		return nil, e
	}
	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}
	t := &quic.Transport{Conn: pc}
	l, err := t.Listen(&tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}, protocol.QUICConfig())
	if err != nil {
		_ = t.Close()
		_ = pc.Close()
		return nil, err
	}
	return &boundQUICListener{Listener: l, transport: t, packet: pc}, nil
}
func (r *Runtime) Run(ctx context.Context) error {
	defer r.Close()
	if r.initErr != nil {
		return r.initErr
	}
	if _, e := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile); e != nil {
		return e
	}
	var shapingFailed <-chan struct{}
	if r.shaper != nil {
		shapingFailed = r.shaper.Failed()
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-shapingFailed:
			// Report the verified failure while the process still owns its identity
			// and accounting. apply rejects every response while shaping is down.
			r.mu.Lock()
			r.reconcileLocked()
			r.refreshStatusesLocked()
			r.mu.Unlock()
			reportCtx, reportCancel := context.WithTimeout(context.Background(), 4*time.Second)
			_ = r.Sync(reportCtx)
			reportCancel()
			return errors.New("wire shaping verification failed: " + r.shaper.Status().Error)
		case <-timer.C:
			syncCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			e := r.Sync(syncCtx)
			cancel()
			delay := r.cfg.SyncInterval
			if e != nil {
				log.Printf("cloud sync: %v", e)
				delay = min(delay, 3*time.Second)
			}
			timer.Reset(delay)
		}
	}
}
