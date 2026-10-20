// Package client implements the outbound DraFRP agent.
package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
	"github.com/quic-go/quic-go"
)

type Config struct {
	CloudURL     string        `json:"cloud_url"`
	CAFile       string        `json:"ca_file"`
	StateDir     string        `json:"state_dir"`
	Name         string        `json:"name"`
	SyncInterval time.Duration `json:"sync_interval"`
	Transport    string        `json:"transport"`
	Bind         bool          `json:"bind"`
	BindCode     string        `json:"bind_code"`
	PollToken    string        `json:"poll_token"`
}

func (c *Config) defaults() {
	if c.SyncInterval <= 0 {
		c.SyncInterval = 20 * time.Second
	}
	if c.StateDir == "" {
		if v := os.Getenv("DRAFRP_STATE_DIR"); v != "" {
			c.StateDir = v
		} else {
			c.StateDir = ".drafrp"
		}
	}
	if c.Transport == "" {
		c.Transport = "auto"
	}
}

type state struct {
	DeviceID   string `json:"device_id"`
	PrivateKey string `json:"private_key"`
	SessionID  string `json:"session_id"`
	Generation uint64 `json:"generation"`
	Name       string `json:"name"`
}
type Agent struct {
	cfg      Config
	mu       sync.RWMutex
	st       state
	key      ed25519.PrivateKey
	snap     model.ClientSnapshot
	carriers map[string]*protocol.Carrier
	closed   chan struct{}
	wg       sync.WaitGroup
}

func New(c Config) (*Agent, error) {
	c.defaults()
	if c.CloudURL == "" {
		return nil, errors.New("cloud_url is required")
	}
	a := &Agent{cfg: c, carriers: map[string]*protocol.Carrier{}, closed: make(chan struct{})}
	if e := a.load(); e != nil {
		return nil, e
	}
	if a.st.DeviceID == "" {
		pub, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		a.key = k
		a.st.PrivateKey = base64.StdEncoding.EncodeToString(k)
		if c.Name != "" {
			a.st.Name = c.Name
		}
		_ = pub
	} else {
		b, e := base64.StdEncoding.DecodeString(a.st.PrivateKey)
		if e != nil || len(b) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid persisted private key")
		}
		a.key = ed25519.PrivateKey(b)
	}
	return a, nil
}
func (a *Agent) load() error {
	if a.cfg.StateDir == "" {
		return nil
	}
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
	if err := os.MkdirAll(a.cfg.StateDir, 0700); err != nil {
		return err
	}
	b, e := json.MarshalIndent(a.st, "", "  ")
	if e != nil {
		return e
	}
	tmp := filepath.Join(a.cfg.StateDir, "device.json.tmp")
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, filepath.Join(a.cfg.StateDir, "device.json"))
}
func (a *Agent) Close() {
	select {
	case <-a.closed:
		return
	default:
		close(a.closed)
	}
	a.mu.Lock()
	for _, c := range a.carriers {
		_ = c.Close()
	}
	a.mu.Unlock()
	a.wg.Wait()
}
func (a *Agent) Bind(ctx context.Context) (model.BindResponse, error) {
	if len(a.key) != ed25519.PrivateKeySize {
		return model.BindResponse{}, errors.New("device key unavailable")
	}
	client, e := protocol.HTTPClient(a.cfg.CAFile)
	if e != nil {
		return model.BindResponse{}, e
	}
	req := model.BindRequest{Name: a.st.Name, PublicKey: base64.StdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey))}
	b, _ := json.Marshal(req)
	u := strings.TrimRight(a.cfg.CloudURL, "/") + "/api/v1/runtime/client/bind"
	hr, _ := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(string(b)))
	hr.Header.Set("Content-Type", "application/json")
	res, e := client.Do(hr)
	if e != nil {
		return model.BindResponse{}, e
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return model.BindResponse{}, fmt.Errorf("bind: HTTP %s", res.Status)
	}
	var br model.BindResponse
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&br); e != nil {
		return br, e
	}
	return br, nil
}
func (a *Agent) PollBind(ctx context.Context, id, token string) (model.BindResponse, error) {
	client, e := protocol.HTTPClient(a.cfg.CAFile)
	if e != nil {
		return model.BindResponse{}, e
	}
	b, _ := json.Marshal(map[string]string{"id": id, "poll_token": token})
	u := strings.TrimRight(a.cfg.CloudURL, "/") + "/api/v1/runtime/client/bind/poll"
	hr, _ := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(string(b)))
	hr.Header.Set("Content-Type", "application/json")
	res, e := client.Do(hr)
	if e != nil {
		return model.BindResponse{}, e
	}
	defer res.Body.Close()
	var br model.BindResponse
	_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&br)
	if res.StatusCode/100 != 2 {
		return br, fmt.Errorf("poll bind: HTTP %s", res.Status)
	}
	if br.Status == "approved" && br.DeviceID != "" {
		a.st.DeviceID = br.DeviceID
		a.st.SessionID = ""
		if e = a.save(); e != nil {
			return br, e
		}
	}
	return br, nil
}
func (a *Agent) Sync(ctx context.Context) (model.ClientSnapshot, error) {
	a.mu.RLock()
	id, sess := a.st.DeviceID, a.st.SessionID
	rev := a.snap.Revision
	a.mu.RUnlock()
	if id == "" {
		return model.ClientSnapshot{}, errors.New("device is not bound")
	}
	ts := time.Now().Unix()
	p := model.SyncPayload(id, sess, ts)
	req := model.ClientSyncRequest{DeviceID: id, SessionID: sess, Timestamp: ts, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(a.key, p)), AppliedRevision: rev}
	cl, e := protocol.HTTPClient(a.cfg.CAFile)
	if e != nil {
		return model.ClientSnapshot{}, e
	}
	b, _ := json.Marshal(req)
	u := strings.TrimRight(a.cfg.CloudURL, "/") + "/api/v1/runtime/client/sync"
	hr, _ := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(string(b)))
	hr.Header.Set("Content-Type", "application/json")
	res, e := cl.Do(hr)
	if e != nil {
		return model.ClientSnapshot{}, e
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return model.ClientSnapshot{}, fmt.Errorf("client sync: HTTP %s", res.Status)
	}
	var s model.ClientSnapshot
	if e = json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&s); e != nil {
		return s, e
	}
	a.mu.Lock()
	a.snap = s
	if a.st.SessionID == "" {
		a.st.SessionID = s.Device.SessionID
	}
	a.st.Generation = s.Device.Generation
	_ = a.save()
	a.mu.Unlock()
	return s, nil
}
func (a *Agent) Snapshot() model.ClientSnapshot { a.mu.RLock(); defer a.mu.RUnlock(); return a.snap }
func (a *Agent) DialEdge(ctx context.Context, e model.Edge) (*protocol.Carrier, error) {
	var last error
	for _, ep := range e.Endpoints {
		if a.cfg.Transport == "quic_only" && ep.Transport != "quic" {
			continue
		}
		if a.cfg.Transport == "tls_only" && ep.Transport != "tls" {
			continue
		}
		switch ep.Transport {
		case "quic":
			tlsConf, er := protocol.TLSClient(a.cfg.CAFile, "", ep.ServerName)
			if er != nil {
				last = er
				continue
			}
			q, er := quic.DialAddr(ctx, ep.Address, tlsConf, protocol.QUICConfig())
			if er != nil {
				last = er
				continue
			}
			c := protocol.WrapQUIC(q, e.ID)
			d := a.deviceGrant(e.ID)
			if er = protocol.AuthenticateClient(ctx, c, d, a.key); er != nil {
				c.Close()
				last = er
				continue
			}
			return c, nil
		case "tls":
			tlsConf, er := protocol.TLSClient(a.cfg.CAFile, "", ep.ServerName)
			if er != nil {
				last = er
				continue
			}
			conn, er := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ep.Address, tlsConf)
			if er != nil {
				last = er
				continue
			}
			c, er := protocol.WrapTLS(conn, false, e.ID)
			if er != nil {
				last = er
				continue
			}
			d := a.deviceGrant(e.ID)
			if er = protocol.AuthenticateClient(ctx, c, d, a.key); er != nil {
				c.Close()
				last = er
				continue
			}
			return c, nil
		}
	}
	if last == nil {
		last = errors.New("no compatible edge endpoint")
	}
	return nil, last
}
func (a *Agent) deviceGrant(edgeID string) model.DeviceGrant {
	a.mu.RLock()
	defer a.mu.RUnlock()
	d := a.snap.Device
	for _, e := range a.snap.Edges {
		if e.ID == edgeID {
			_ = e
		}
	}
	return d
}
func (a *Agent) ConnectEdge(ctx context.Context, e model.Edge) error {
	c, err := a.DialEdge(ctx, e)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.carriers[e.ID] = c
	a.mu.Unlock()
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer c.Close()
		for {
			st, e := c.Accept(ctx)
			if e != nil {
				return
			}
			a.wg.Add(1)
			go func() { defer a.wg.Done(); a.serveStream(st) }()
		}
	}()
	return nil
}
func (a *Agent) serveStream(st protocol.Stream) {
	defer protocol.Abort(st)
	var f protocol.Flow
	if e := protocol.ReadJSON(st, &f); e != nil {
		return
	}
	a.mu.RLock()
	var rr *model.Rule
	for i := range a.snap.Rules {
		if a.snap.Rules[i].ID == f.RuleID {
			rr = &a.snap.Rules[i]
			break
		}
	}
	a.mu.RUnlock()
	if rr == nil || rr.Version != f.Version || !rr.Enabled {
		return
	}
	switch f.Protocol {
	case "tcp":
		a.serveTCP(st, *rr)
	case "udp":
		a.serveUDP(st, *rr)
	}
}
func (a *Agent) serveTCP(st protocol.Stream, r model.Rule) {
	target, e := net.DialTimeout("tcp", r.Target, 8*time.Second)
	if e != nil {
		_ = protocol.WriteJSON(st, protocol.Result{Code: "target_unreachable", Error: e.Error()})
		return
	}
	defer target.Close()
	_ = protocol.WriteJSON(st, protocol.Result{})
	err := make(chan error, 2)
	go func() { _, e := io.Copy(st, target); err <- e }()
	go func() { _, e := io.Copy(target, st); err <- e }()
	<-err
}
func (a *Agent) serveUDP(st protocol.Stream, r model.Rule) {
	for {
		b, e := protocol.ReadPacket(st)
		if e != nil {
			return
		}
		conn, e := net.DialTimeout("udp", r.Target, 3*time.Second)
		if e != nil {
			return
		}
		_, _ = conn.Write(b)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64<<10)
		n, e := conn.Read(buf)
		conn.Close()
		if e == nil {
			_ = protocol.WritePacket(st, buf[:n])
		}
	}
}
func ParseEndpointAddress(e model.Endpoint) string {
	if strings.Contains(e.Address, "://") {
		u, _ := url.Parse(e.Address)
		return u.Host
	}
	return e.Address
}
