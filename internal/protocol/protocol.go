// Package protocol implements DraFRP's authenticated, bounded carrier protocol.
package protocol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"drafrp/internal/model"
	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
)

const ALPN = "drafrp/1"
const MaxFrame = 64 << 10
const MaxPacket = 65507

type Stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}
type Challenge struct {
	Version      int    `json:"version"`
	Nonce        string `json:"nonce"`
	EdgeID       string `json:"edge_id"`
	ProbeVersion int    `json:"probe_version,omitempty"`
}
type admissionHello struct {
	Version      int `json:"version"`
	ProbeVersion int `json:"probe_version,omitempty"`
}
type Proof struct {
	DeviceID   string    `json:"device_id"`
	SessionID  string    `json:"session_id"`
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
	Signature  string    `json:"signature"`
}
type Result struct {
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}
type AdmissionError struct {
	Code, Message string
}

func (e *AdmissionError) Error() string {
	return fmt.Sprintf("edge admission %s: %s", e.Code, e.Message)
}

type Flow struct {
	RuleID      string `json:"rule_id"`
	Version     uint64 `json:"version"`
	ID          uint64 `json:"id"`
	Protocol    string `json:"protocol"`
	Peer        string `json:"peer"`
	Host        string `json:"host,omitempty"`
	Scheme      string `json:"scheme,omitempty"`
	Generation  uint64 `json:"generation"`
	Datagram    bool   `json:"datagram,omitempty"`
	IngressPort int    `json:"ingress_port,omitempty"`
}

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}
func FlowID() uint64 { b := make([]byte, 8); _, _ = rand.Read(b); return binary.BigEndian.Uint64(b) }
func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return errors.New("frame too large")
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if err = WriteFull(w, n[:]); err != nil {
		return err
	}
	return WriteFull(w, b)
}
func ReadJSON(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > MaxFrame {
		return errors.New("invalid frame size")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func WritePacket(w io.Writer, b []byte) error {
	if len(b) > MaxPacket {
		return errors.New("UDP packet too large")
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(b)))
	if e := WriteFull(w, h[:]); e != nil {
		return e
	}
	return WriteFull(w, b)
}
func WriteFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func ReadPacket(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > MaxPacket {
		return nil, errors.New("UDP packet too large")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func ProofPayload(ch Challenge, p Proof) []byte {
	return []byte("drafrp-carrier-v1\n" + ch.EdgeID + "\n" + ch.Nonce + "\n" + p.DeviceID + "\n" + p.SessionID + "\n" + strconv.FormatUint(p.Generation, 10) + "\n" + p.ExpiresAt.UTC().Format(time.RFC3339Nano))
}
func AuthenticateClient(ctx context.Context, c *Carrier, d model.DeviceGrant, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid device signing key")
	}
	timer := time.AfterFunc(10*time.Second, func() { _ = c.Close() })
	defer timer.Stop()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	s, e := c.Open(ctx)
	if e != nil {
		return e
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	// A newly opened QUIC stream is not visible to AcceptStream until it
	// carries data. Send a bounded preface before waiting for the challenge.
	if e = WriteJSON(s, admissionHello{Version: model.ProtocolVersion, ProbeVersion: 1}); e != nil {
		return e
	}
	var ch Challenge
	if e = ReadJSON(s, &ch); e != nil {
		return e
	}
	if ch.Version != model.ProtocolVersion || ch.EdgeID != c.EdgeID || len(ch.Nonce) != 32 {
		return errors.New("unexpected edge identity or protocol")
	}
	p := Proof{DeviceID: d.DeviceID, SessionID: d.SessionID, Generation: d.Generation, ExpiresAt: d.ExpiresAt}
	p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, ProofPayload(ch, p)))
	if e = WriteJSON(s, p); e != nil {
		return e
	}
	var result Result
	if e = ReadJSON(s, &result); e != nil {
		return e
	}
	if result.Error != "" || result.Code != "" {
		return &AdmissionError{Code: result.Code, Message: result.Error}
	}
	c.Device = d
	c.probe.enabled.Store(ch.ProbeVersion == 1)
	return nil
}
func AuthenticateEdge(ctx context.Context, c *Carrier, lookup func(string) (model.DeviceGrant, bool)) error {
	timer := time.AfterFunc(10*time.Second, func() { _ = c.Close() })
	defer timer.Stop()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	s, e := c.Accept(ctx)
	if e != nil {
		return e
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	var hello admissionHello
	if e = ReadJSON(s, &hello); e != nil {
		return e
	}
	if hello.Version != model.ProtocolVersion {
		return errors.New("unsupported carrier protocol")
	}
	ch := Challenge{Version: 1, Nonce: ID(), EdgeID: c.EdgeID}
	if hello.ProbeVersion == 1 {
		ch.ProbeVersion = 1
	}
	if e = WriteJSON(s, ch); e != nil {
		return e
	}
	var p Proof
	if e = ReadJSON(s, &p); e != nil {
		return e
	}
	d, ok := lookup(p.DeviceID)
	pub, e := base64.StdEncoding.DecodeString(d.PublicKey)
	sig, se := base64.StdEncoding.DecodeString(p.Signature)
	if !ok || e != nil || se != nil || len(pub) != ed25519.PublicKeySize || d.DeviceID != p.DeviceID || d.SessionID != p.SessionID || d.Generation != p.Generation || p.ExpiresAt.After(d.ExpiresAt) || !time.Now().Before(p.ExpiresAt) || !ed25519.Verify(ed25519.PublicKey(pub), ProofPayload(ch, p), sig) {
		_ = WriteJSON(s, Result{Code: "unauthorized", Error: "device grant or proof invalid"})
		return errors.New("invalid device admission")
	}
	c.Device = d
	if e = WriteJSON(s, Result{}); e != nil {
		return e
	}
	c.probe.enabled.Store(ch.ProbeVersion == 1)
	return nil
}

type assembly struct {
	parts    [][]byte
	total    int
	received int
	bytes    int
	expires  time.Time
}
type outboundPacket struct {
	id      uint64
	payload []byte
	expires time.Time
}
type Carrier struct {
	EdgeID    string
	Device    model.DeviceGrant
	Transport string
	// Set by the dialing Agent before publication. This is local observation,
	// not authority and not an estimate of an application's response time.
	Endpoint          model.Endpoint
	EstablishedAt     time.Time
	HandshakeDuration time.Duration
	q                 *quic.Conn
	mux               *yamux.Session
	closed            chan struct{}
	once              sync.Once
	active            atomic.Int64
	msg               atomic.Uint32
	mu                sync.Mutex
	packets           map[uint64]chan []byte
	pending           map[[2]uint64]*assembly
	pendingBytes      int
	replays           map[uint64]*replayWindow
	openSlots         chan struct{}
	sendQueue         chan outboundPacket
	probe             carrierProbeState
}

func WrapQUIC(q *quic.Conn, edgeID string) *Carrier {
	c := &Carrier{q: q, EdgeID: edgeID, Transport: "quic", closed: make(chan struct{}), packets: map[uint64]chan []byte{}, pending: map[[2]uint64]*assembly{}, replays: map[uint64]*replayWindow{}, sendQueue: make(chan outboundPacket, 16)}
	go c.receive()
	go c.sendPackets()
	return c
}
func WrapTLS(conn net.Conn, server bool, edgeID string) (*Carrier, error) {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 64
	cfg.MaxStreamWindowSize = 256 << 10
	cfg.StreamOpenTimeout = 10 * time.Second
	cfg.StreamCloseTimeout = 15 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.LogOutput = io.Discard
	var m *yamux.Session
	var e error
	if server {
		m, e = yamux.Server(conn, cfg)
	} else {
		m, e = yamux.Client(conn, cfg)
	}
	if e != nil {
		return nil, e
	}
	return &Carrier{mux: m, EdgeID: edgeID, Transport: "tls", closed: make(chan struct{}), openSlots: make(chan struct{}, 16)}, nil
}
func (c *Carrier) Open(ctx context.Context) (Stream, error) {
	if c.q != nil {
		s, err := c.q.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	select {
	case c.openSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.Done():
		return nil, errors.New("carrier closed")
	}
	type result struct {
		// Keep the concrete pointer until after checking nil. Boxing a failed
		// (*yamux.Stream)(nil) as Stream makes it non-nil and can panic in the
		// cancellation cleanup below.
		s   *yamux.Stream
		err error
	}
	results := make(chan result, 1)
	go func() {
		s, err := c.mux.OpenStream()
		<-c.openSlots
		results <- result{s, err}
	}()
	select {
	case r := <-results:
		if r.err != nil {
			return nil, r.err
		}
		return r.s, r.err
	case <-ctx.Done():
		go func() {
			r := <-results
			if r.s != nil {
				Abort(r.s)
			}
		}()
		return nil, ctx.Err()
	}
}
func (c *Carrier) Accept(ctx context.Context) (Stream, error) {
	if c.q != nil {
		s, err := c.q.AcceptStream(ctx)
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	s, err := c.mux.AcceptStreamWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (c *Carrier) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.q != nil {
			_ = c.q.CloseWithError(0, "closed")
		} else {
			_ = c.mux.Close()
		}
		c.clearProbeSamples()
		c.mu.Lock()
		clear(c.pending)
		clear(c.packets)
		clear(c.replays)
		c.pendingBytes = 0
		c.mu.Unlock()
	})
	return nil
}
func (c *Carrier) Done() <-chan struct{} {
	if c.q != nil {
		return c.q.Context().Done()
	}
	return c.mux.CloseChan()
}
func (c *Carrier) Datagram() bool {
	if c.q == nil {
		return false
	}
	support := c.q.ConnectionState().SupportsDatagrams
	return support.Local && support.Remote
}
func (c *Carrier) Active() int64         { return c.active.Load() }
func (c *Carrier) AddActive(delta int64) { c.active.Add(delta) }
func (c *Carrier) Register(id uint64) (<-chan []byte, func(), error) {
	if id == 0 {
		return nil, nil, errors.New("invalid UDP flow id")
	}
	if !c.Datagram() {
		return nil, nil, errors.New("DATAGRAM was not negotiated")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.Done():
		return nil, nil, errors.New("carrier closed")
	default:
	}
	if len(c.packets) >= 128 {
		return nil, nil, errors.New("UDP flow capacity")
	}
	if _, ok := c.packets[id]; ok {
		return nil, nil, errors.New("duplicate UDP flow")
	}
	ch := make(chan []byte, 8)
	c.packets[id] = ch
	c.replays[id] = &replayWindow{}
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			c.mu.Lock()
			delete(c.packets, id)
			delete(c.replays, id)
			for k, a := range c.pending {
				if k[0] == id {
					c.pendingBytes -= a.total
					delete(c.pending, k)
				}
			}
			c.mu.Unlock()
		})
	}, nil
}
func (c *Carrier) SendPacket(id uint64, b []byte) error {
	if !c.Datagram() {
		return errors.New("DATAGRAM was not negotiated")
	}
	if len(b) > MaxPacket {
		return errors.New("UDP packet too large")
	}
	if id == 0 {
		return errors.New("invalid UDP flow id")
	}
	packet := outboundPacket{id: id, payload: append([]byte{}, b...), expires: time.Now().Add(time.Second)}
	select {
	case <-c.Done():
		return errors.New("carrier closed")
	case c.sendQueue <- packet:
		return nil
	default:
		return errors.New("UDP send queue is full")
	}
}
func (c *Carrier) sendPackets() {
	for {
		select {
		case <-c.Done():
			return
		case packet := <-c.sendQueue:
			if time.Now().Before(packet.expires) {
				_ = c.sendPacket(packet)
			}
		}
	}
}
func (c *Carrier) sendPacket(packet outboundPacket) error {
	id, b := packet.id, packet.payload
	seq := c.msg.Add(1)
	count := (len(b) + 999) / 1000
	if count == 0 {
		count = 1
	}
	for i := 0; i < count; i++ {
		if time.Now().After(packet.expires) {
			return errors.New("UDP packet expired in send queue")
		}
		end := min((i+1)*1000, len(b))
		p := make([]byte, 18+end-i*1000)
		binary.BigEndian.PutUint64(p[0:8], id)
		binary.BigEndian.PutUint32(p[8:12], seq)
		binary.BigEndian.PutUint16(p[12:14], uint16(i))
		binary.BigEndian.PutUint16(p[14:16], uint16(count))
		binary.BigEndian.PutUint16(p[16:18], uint16(len(b)))
		copy(p[18:], b[i*1000:end])
		if e := c.q.SendDatagram(p); e != nil {
			return e
		}
	}
	return nil
}
func (c *Carrier) receive() {
	for {
		p, e := c.q.ReceiveDatagram(context.Background())
		if e != nil {
			return
		}
		c.handleDatagram(p, time.Now())
	}
}

// A fixed 1024-message window accepts reasonable reordering while preventing
// complete or expired messages from being reassembled and delivered twice.
type replayWindow struct {
	initialized bool
	newest      uint32
	bits        [16]uint64
}

func (w *replayWindow) seen(seq uint32) bool {
	if !w.initialized || int32(seq-w.newest) > 0 {
		return false
	}
	d := uint32(w.newest - seq)
	return d >= 1024 || w.bits[d/64]&(uint64(1)<<(d%64)) != 0
}
func (w *replayWindow) mark(seq uint32) {
	if !w.initialized {
		w.initialized = true
		w.newest = seq
		w.bits[0] = 1
		return
	}
	if int32(seq-w.newest) > 0 {
		d := uint32(seq - w.newest)
		if d >= 1024 {
			clear(w.bits[:])
		} else {
			words, bits := int(d/64), d%64
			for i := len(w.bits) - 1; i >= 0; i-- {
				var n uint64
				j := i - words
				if j >= 0 {
					n = w.bits[j] << bits
					if bits > 0 && j > 0 {
						n |= w.bits[j-1] >> (64 - bits)
					}
				}
				w.bits[i] = n
			}
		}
		w.newest = seq
	}
	d := uint32(w.newest - seq)
	if d < 1024 {
		w.bits[d/64] |= uint64(1) << (d % 64)
	}
}

func (c *Carrier) handleDatagram(p []byte, now time.Time) {
	if len(p) < 18 {
		return
	}
	id := binary.BigEndian.Uint64(p[:8])
	seq := binary.BigEndian.Uint32(p[8:12])
	part := int(binary.BigEndian.Uint16(p[12:14]))
	count := int(binary.BigEndian.Uint16(p[14:16]))
	total := int(binary.BigEndian.Uint16(p[16:18]))
	if count < 1 || count > 66 || part >= count || total > MaxPacket || count != max(1, (total+999)/1000) || len(p)-18 != min(1000, total-part*1000) {
		return
	}
	c.mu.Lock()
	ch, ok := c.packets[id]
	if !ok {
		c.mu.Unlock()
		return
	}
	for k, a := range c.pending {
		if now.After(a.expires) {
			c.pendingBytes -= a.total
			delete(c.pending, k)
		}
	}
	k := [2]uint64{id, uint64(seq)}
	a := c.pending[k]
	if a == nil {
		window := c.replays[id]
		if window == nil || window.seen(seq) {
			c.mu.Unlock()
			return
		}
		if len(c.pending) >= 128 || c.pendingBytes+total > 4<<20 {
			c.mu.Unlock()
			return
		}
		a = &assembly{parts: make([][]byte, count), total: total, expires: now.Add(2 * time.Second)}
		c.pending[k] = a
		c.pendingBytes += total
		window.mark(seq)
	}
	if a.total != total || len(a.parts) != count || a.parts[part] != nil {
		c.mu.Unlock()
		return
	}
	a.parts[part] = append([]byte{}, p[18:]...)
	a.received++
	a.bytes += len(p) - 18
	if a.received == count {
		b := make([]byte, 0, total)
		for _, v := range a.parts {
			b = append(b, v...)
		}
		delete(c.pending, k)
		c.pendingBytes -= a.total
		select {
		case ch <- b:
		default:
		}
	}
	c.mu.Unlock()
}

func TLSClient(caFile, caPEM, serverName string) (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		b, e := os.ReadFile(caFile)
		if e != nil {
			return nil, e
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid CA file")
		}
	}
	if caPEM != "" && !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("invalid edge CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: serverName, NextProtos: []string{ALPN}}, nil
}
func HTTPClient(caFile string) (*http.Client, error) {
	cfg, e := TLSClient(caFile, "", "")
	if e != nil {
		return nil, e
	}
	cfg.NextProtos = []string{"h2", "http/1.1"}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second}}, nil
}
func QUICConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 128, MaxIncomingUniStreams: 0, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second, InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 256 << 10, InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 4 << 20, Allow0RTT: false}
}

// Abort closes both directions of QUIC streams; Close alone is only a write FIN.
func Abort(s Stream) {
	_ = s.SetDeadline(time.Now())
	if q, ok := s.(*quic.Stream); ok {
		q.CancelRead(0)
		q.CancelWrite(0)
	}
	_ = s.Close()
}

// Finish delivers the write FIN without resetting buffered output, then stops
// reading unused request bytes. In particular, an early HTTP origin failure
// must stop an in-progress upload while preserving its structured Result.
func Finish(s Stream) {
	_ = s.Close()
	if q, ok := s.(*quic.Stream); ok {
		q.CancelRead(0)
		return
	}
	if r, ok := s.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = r.SetReadDeadline(time.Now())
	} else {
		_ = s.SetDeadline(time.Now())
	}
}
func HalfClose(w io.Writer) {
	if q, ok := w.(*quic.Stream); ok {
		_ = q.Close()
		return
	}
	if h, ok := w.(interface{ CloseWrite() error }); ok {
		_ = h.CloseWrite()
		return
	}
	if h, ok := w.(interface{ Close() error }); ok {
		_ = h.Close()
	}
}
