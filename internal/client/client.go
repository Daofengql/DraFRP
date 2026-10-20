// Package client implements the outbound, independently authorized agent.
package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"drafrp/internal/model"
	"drafrp/internal/native"
	"drafrp/internal/protocol"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	CloudURL           string        `json:"cloud_url"`
	CAFile             string        `json:"ca_file"`
	OriginCAFile       string        `json:"origin_ca_file"`
	StateDir           string        `json:"state_dir"`
	Name               string        `json:"name"`
	SyncInterval       time.Duration `json:"sync_interval"`
	Transport          string        `json:"transport"`
	NetworkMode        string        `json:"network_mode"`
	AllowedTargetCIDRs []string      `json:"allowed_target_cidrs"`
	AllowedTargetPorts []int         `json:"allowed_target_ports"`
	MaxCarriersPerEdge int           `json:"max_carriers_per_edge"`
	Bind               bool          `json:"bind"`
	NativeReturnCIDRs  []string      `json:"native_return_cidrs"`
	NativeFlowLimit    int           `json:"native_flow_limit"`
}

// PublicKeyFingerprint matches the console binding inspection contract:
// SHA-256 of the standard Base64 public key, encoded as lowercase hex.
func (a *Agent) PublicKeyFingerprint() string {
	public := base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey))
	sum := sha256.Sum256([]byte(public))
	return hex.EncodeToString(sum[:])
}

func (c *Config) defaults() {
	if c.SyncInterval <= 0 {
		c.SyncInterval = 20 * time.Second
	}
	if c.StateDir == "" {
		c.StateDir = os.Getenv("DRAFRP_STATE_DIR")
		if c.StateDir == "" {
			c.StateDir = ".drafrp"
		}
	}
	if c.Transport == "" {
		c.Transport = "auto"
	}
	if c.NetworkMode == "" {
		c.NetworkMode = "socket"
	}
	if c.MaxCarriersPerEdge <= 0 {
		c.MaxCarriersPerEdge = 2
	}
}

type state struct {
	DeviceID   string              `json:"device_id"`
	PrivateKey string              `json:"private_key"`
	SessionID  string              `json:"session_id"`
	Name       string              `json:"name"`
	Pending    *model.BindResponse `json:"pending,omitempty"`
}
type activeFlow struct {
	rule       model.Rule
	edgeID     string
	generation uint64
	cancel     context.CancelFunc
	carrier    *protocol.Carrier
}
type Agent struct {
	cfg            Config
	mu             sync.RWMutex
	syncMu         sync.Mutex
	connectMu      sync.Mutex
	st             state
	key            ed25519.PrivateKey
	snap           model.ClientSnapshot
	carriers       map[string]*protocol.Carrier
	carrierEdges   map[string]model.Edge
	flows          map[protocol.Stream]activeFlow
	transports     map[string]*http.Transport
	http           *http.Client
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	once           sync.Once
	closing        bool
	stateLock      *os.File
	native         *native.Manager
	pendingStreams int
	pathHealth     map[endpointKey]*endpointHealth
}

func New(c Config) (*Agent, error) {
	c.defaults()
	if c.CloudURL == "" {
		return nil, errors.New("cloud_url is required")
	}
	u, err := url.Parse(c.CloudURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid cloud_url")
	}
	if c.Transport != "auto" && c.Transport != "quic_only" && c.Transport != "tls_only" {
		return nil, errors.New("invalid transport")
	}
	if c.NetworkMode != "socket" && c.NetworkMode != "tun" && c.NetworkMode != "transparent" {
		return nil, errors.New("invalid network_mode")
	}
	if c.MaxCarriersPerEdge > 8 {
		return nil, errors.New("max_carriers_per_edge must be <=8")
	}
	for _, s := range c.AllowedTargetCIDRs {
		if _, e := parsePrefix(s); e != nil {
			return nil, e
		}
	}
	for _, p := range c.AllowedTargetPorts {
		if p < 1 || p > 65535 {
			return nil, errors.New("invalid allowed target port")
		}
	}
	h, e := protocol.HTTPClient(c.CAFile)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &Agent{cfg: c, http: h, ctx: ctx, cancel: cancel, carriers: map[string]*protocol.Carrier{}, carrierEdges: map[string]model.Edge{}, flows: map[protocol.Stream]activeFlow{}, transports: map[string]*http.Transport{}, pathHealth: map[endpointKey]*endpointHealth{}}
	if e = os.MkdirAll(c.StateDir, 0700); e != nil {
		cancel()
		return nil, e
	}
	a.stateLock, e = lockState(filepath.Join(c.StateDir, "device.lock"))
	if e != nil {
		cancel()
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			_ = a.stateLock.Close()
			h.CloseIdleConnections()
		}
	}()
	if e = a.load(); e != nil {
		cancel()
		return nil, e
	}
	if a.st.PrivateKey == "" {
		_, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			cancel()
			return nil, e
		}
		a.st.PrivateKey = base64.StdEncoding.EncodeToString(k)
	}
	b, e := base64.StdEncoding.DecodeString(a.st.PrivateKey)
	if e != nil || len(b) != ed25519.PrivateKeySize {
		cancel()
		return nil, errors.New("invalid persisted private key")
	}
	a.key = ed25519.PrivateKey(b)
	a.st.SessionID = protocol.ID()
	if c.Name != "" {
		a.st.Name = c.Name
	}
	if a.st.Name == "" {
		a.st.Name, _ = os.Hostname()
	}
	if e = a.save(); e != nil {
		cancel()
		return nil, e
	}
	if c.NetworkMode == "transparent" {
		a.native, e = native.New(native.Config{StateDir: c.StateDir, ReturnCIDRs: c.NativeReturnCIDRs, MaxFlows: c.NativeFlowLimit})
		if e != nil {
			cancel()
			return nil, e
		}
	}
	a.wg.Add(1)
	go a.watch()
	ok = true
	return a, nil
}
func (a *Agent) load() error {
	b, e := os.ReadFile(filepath.Join(a.cfg.StateDir, "device.json"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(b, &a.st)
}
func (a *Agent) save() error {
	if e := os.MkdirAll(a.cfg.StateDir, 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(a.st, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(a.cfg.StateDir, "device-*.tmp")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(tmp, filepath.Join(a.cfg.StateDir, "device.json"))
}
func (a *Agent) Bound() bool { a.mu.RLock(); defer a.mu.RUnlock(); return a.st.DeviceID != "" }
func (a *Agent) Close() {
	a.once.Do(func() {
		a.mu.Lock()
		a.closing = true
		a.cancel()
		for _, c := range a.carriers {
			_ = c.Close()
		}
		for _, f := range a.flows {
			f.cancel()
		}
		for _, t := range a.transports {
			t.CloseIdleConnections()
		}
		a.mu.Unlock()
		a.wg.Wait()
		a.syncMu.Lock()
		a.syncMu.Unlock()
		a.connectMu.Lock()
		a.connectMu.Unlock()
		a.http.CloseIdleConnections()
		if a.native != nil {
			if err := a.native.Close(); err != nil {
				log.Printf("native network cleanup: %v", err)
			}
		}
		_ = a.stateLock.Close()
	})
}
func (a *Agent) post(ctx context.Context, path string, in, out any) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(a.cfg.CloudURL, "/")+"/api/v1/runtime/client/"+path, strings.NewReader(string(b)))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := a.http.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		var body struct {
			Error struct{ Code, Message string }
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&body)
		return fmt.Errorf("%s HTTP %d %s: %s", path, res.StatusCode, body.Error.Code, body.Error.Message)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
}
func (a *Agent) Bind(ctx context.Context) (model.BindResponse, error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return model.BindResponse{}, errors.New("agent closed")
	}
	if a.st.DeviceID != "" {
		a.mu.Unlock()
		return model.BindResponse{}, errors.New("device is already bound; use a new state directory for a separate device")
	}
	if p := a.st.Pending; p != nil && time.Now().Before(p.ExpiresAt) {
		a.mu.Unlock()
		return *p, nil
	}
	in := model.BindRequest{Name: a.st.Name, PublicKey: base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey))}
	a.mu.Unlock()
	var out model.BindResponse
	if e := a.post(ctx, "bind", in, &out); e != nil {
		return out, e
	}
	if out.ID == "" || out.PollToken == "" || !time.Now().Before(out.ExpiresAt) {
		return out, errors.New("invalid binding challenge")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.Pending = &out
	return out, a.save()
}
func (a *Agent) PollBind(ctx context.Context, id, token string) (model.BindResponse, error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	a.mu.RLock()
	pending := a.st.Pending
	valid := !a.closing && pending != nil && pending.ID == id && pending.PollToken == token && a.st.DeviceID == ""
	a.mu.RUnlock()
	if !valid {
		return model.BindResponse{}, errors.New("binding challenge does not belong to this device")
	}
	var out model.BindResponse
	if e := a.post(ctx, "bind/poll", map[string]string{"id": id, "poll_token": token}, &out); e != nil {
		return out, e
	}
	if out.ID != id {
		return out, errors.New("unexpected binding response")
	}
	if out.Status == "approved" && out.DeviceID != "" {
		a.mu.Lock()
		a.st.DeviceID = out.DeviceID
		a.st.Pending = nil
		e := a.save()
		a.mu.Unlock()
		if e != nil {
			return out, e
		}
	}
	return out, nil
}
func (a *Agent) Sync(ctx context.Context) (model.ClientSnapshot, error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	a.mu.RLock()
	capabilities := []string{"tcp_socket", "udp_socket", "http_forwarded_headers", "quic_datagram", "tls_mux"}
	if a.native != nil {
		capabilities = append(capabilities, a.native.Capabilities()...)
	}
	in := model.ClientSyncRequest{DeviceID: a.st.DeviceID, SessionID: a.st.SessionID, Timestamp: time.Now().Unix(), Nonce: protocol.ID(), AppliedRevision: a.snap.Revision, Capabilities: capabilities, Runtime: a.runtimeStatusLocked()}
	a.mu.RUnlock()
	if in.DeviceID == "" {
		return model.ClientSnapshot{}, errors.New("device is not bound")
	}
	in.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(a.key, model.ClientSyncPayload(in)))
	var s model.ClientSnapshot
	if e := a.post(ctx, "sync", in, &s); e != nil {
		return s, e
	}
	if s.Device.DeviceID != in.DeviceID || s.Device.SessionID != in.SessionID || s.Device.TenantID == "" || s.Device.Generation == 0 || !time.Now().Before(s.ExpiresAt) || !time.Now().Before(s.Device.ExpiresAt) || s.Device.PublicKey != base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey)) {
		return s, errors.New("invalid cloud device snapshot")
	}
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return s, errors.New("agent closed")
	}
	if s.Revision < a.snap.Revision {
		a.mu.Unlock()
		return s, errors.New("cloud snapshot revision regressed")
	}
	a.snap = s
	a.reconcileLocked()
	a.mu.Unlock()
	return s, nil
}
func (a *Agent) Snapshot() model.ClientSnapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()
	// Callers must not mutate the authorization snapshot used by serving flows.
	b, _ := json.Marshal(a.snap)
	var s model.ClientSnapshot
	_ = json.Unmarshal(b, &s)
	return s
}
func (a *Agent) watch() {
	defer a.wg.Done()
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
			a.mu.Lock()
			a.reconcileLocked()
			a.mu.Unlock()
		}
	}
}
func (a *Agent) reconcileLocked() {
	valid := time.Now().Before(a.snap.ExpiresAt) && time.Now().Before(a.snap.Device.ExpiresAt)
	a.pruneEndpointHealthLocked()
	edges := map[string]model.Edge{}
	rules := map[string]model.Rule{}
	for _, e := range a.snap.Edges {
		edges[e.ID] = e
	}
	for _, r := range a.snap.Rules {
		if r.Enabled && !r.Deleting {
			rules[r.ID] = r
		}
	}
	for k, c := range a.carriers {
		edge, exists := edges[c.EdgeID]
		previous, hasPrevious := a.carrierEdges[k]
		if !valid || !exists || hasPrevious && !sameEdgeAuthority(previous, edge) || c.Device.Generation != a.snap.Device.Generation || c.Device.SessionID != a.snap.Device.SessionID {
			_ = c.Close()
			delete(a.carriers, k)
			delete(a.carrierEdges, k)
			continue
		}
		select {
		case <-c.Done():
			delete(a.carriers, k)
			delete(a.carrierEdges, k)
		default:
		}
	}
	for _, f := range a.flows {
		r, ok := rules[f.rule.ID]
		_, edgeExists := edges[f.edgeID]
		if !valid || !edgeExists || !ok || r.Version != f.rule.Version || r.EdgeID != f.edgeID || f.generation != a.snap.Device.Generation {
			f.cancel()
		}
	}
	for k, t := range a.transports {
		keep := false
		for _, r := range rules {
			if valid && k == transportKey(r) {
				keep = true
				break
			}
		}
		if !keep {
			t.CloseIdleConnections()
			delete(a.transports, k)
		}
	}
}
