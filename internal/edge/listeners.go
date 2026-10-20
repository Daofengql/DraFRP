package edge

import (
	"context"
	"crypto/tls"
	"drafrp/internal/protocol"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func (r *Runtime) ensureListenersLocked() {
	desired := map[string]bool{}
	for _, ep := range r.snap.Edge.Endpoints {
		key := "carrier/" + ep.Transport + "/" + ep.Address
		desired[key] = true
		if _, ok := r.listeners[key]; ok {
			continue
		}
		_, p, e := net.SplitHostPort(ep.Address)
		if e != nil {
			r.listenerErrors[key] = e.Error()
			continue
		}
		addr := net.JoinHostPort(r.cfg.ListenHost, p)
		switch ep.Transport {
		case "quic":
			l, e := ListenQUIC(r.cfg, addr)
			if e != nil {
				r.listenerErrors[key] = e.Error()
				continue
			}
			r.listeners[key] = listenerState{l, "carrier", "", addr}
			delete(r.listenerErrors, key)
			r.launchLocked(func() {
				for {
					q, e := l.Accept(r.ctx)
					if e != nil {
						r.listenerStopped(key, l, e)
						return
					}
					c := protocol.WrapQUIC(q, r.cfg.EdgeID)
					r.mu.Lock()
					if !r.launchLocked(func() { r.serveCarrier(r.ctx, c, key) }) {
						_ = c.Close()
					}
					r.mu.Unlock()
				}
			})
		case "tls":
			pair, e := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
			if e != nil {
				r.listenerErrors[key] = e.Error()
				continue
			}
			l, e := net.Listen("tcp", addr)
			if e != nil {
				r.listenerErrors[key] = e.Error()
				continue
			}
			tc := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}
			r.listeners[key] = listenerState{l, "carrier", "", addr}
			delete(r.listenerErrors, key)
			r.launchLocked(func() { r.acceptTLS(l, tc, key) })
		default:
			r.listenerErrors[key] = "unsupported carrier transport"
		}
	}
	for _, site := range []struct {
		kind string
		port int
	}{{"http", r.snap.Edge.HTTPPort}, {"https", r.snap.Edge.HTTPSPort}} {
		if site.port == 0 {
			continue
		}
		key := "site/" + site.kind + "/" + strconv.Itoa(site.port)
		desired[key] = true
		if _, ok := r.listeners[key]; ok {
			continue
		}
		addr := net.JoinHostPort(r.cfg.ListenHost, strconv.Itoa(site.port))
		l, e := net.Listen("tcp", addr)
		if e != nil {
			r.listenerErrors[key] = e.Error()
			continue
		}
		srv := &http.Server{Handler: r.HTTPHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
		if site.kind == "https" {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.siteCertificate, NextProtos: []string{"h2", "http/1.1"}}
		}
		r.listeners[key] = listenerState{srv, site.kind, "", addr}
		delete(r.listenerErrors, key)
		limited := &limitedListener{Listener: l, slots: make(chan struct{}, r.cfg.MaxConnections), ctx: r.ctx}
		r.launchLocked(func() {
			var serveErr error
			if site.kind == "https" {
				serveErr = srv.ServeTLS(limited, "", "")
			} else {
				serveErr = srv.Serve(limited)
			}
			r.listenerStopped(key, srv, serveErr)
		})
	}
	for id, rr := range r.rules {
		if rr.policyError != "" || rr.rule.Protocol != "tcp" && rr.rule.Protocol != "udp" {
			continue
		}
		key := "rule/" + id
		desired[key] = true
		if _, ok := r.listeners[key]; ok {
			continue
		}
		addr := r.ruleAddress(rr.rule)
		if rr.rule.Protocol == "tcp" {
			l, e := net.Listen("tcp", addr)
			if e != nil {
				r.listenerErrors[key] = e.Error()
				continue
			}
			r.listeners[key] = listenerState{l, "tcp", id, addr}
			delete(r.listenerErrors, key)
			r.launchLocked(func() { r.acceptTCP(id, l) })
		} else {
			pc, e := net.ListenPacket("udp", addr)
			if e != nil {
				r.listenerErrors[key] = e.Error()
				continue
			}
			r.listeners[key] = listenerState{pc, "udp", id, addr}
			delete(r.listenerErrors, key)
			r.launchLocked(func() { r.acceptUDP(id, pc) })
		}
	}
	for key, l := range r.listeners {
		if !desired[key] {
			_ = l.closer.Close()
			delete(r.listeners, key)
			delete(r.listenerErrors, key)
			if l.kind == "carrier" {
				for ckey, cs := range r.carriers {
					if cs.endpoint == key {
						_ = cs.c.Close()
						delete(r.carriers, ckey)
					}
				}
			}
		}
	}
}
func (r *Runtime) acceptTLS(l net.Listener, tc *tls.Config, endpoint string) {
	for {
		conn, e := l.Accept()
		if e != nil {
			r.listenerStopped(endpoint, l, e)
			return
		}
		select {
		case r.handshakeSlots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		r.mu.Lock()
		ok := r.launchLocked(func() {
			tlsConn := tls.Server(conn, tc)
			ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
			e := tlsConn.HandshakeContext(ctx)
			cancel()
			<-r.handshakeSlots
			if e != nil || tlsConn.ConnectionState().NegotiatedProtocol != protocol.ALPN {
				_ = conn.Close()
				return
			}
			c, e := protocol.WrapTLS(tlsConn, true, r.cfg.EdgeID)
			if e != nil {
				_ = conn.Close()
				return
			}
			r.serveCarrier(r.ctx, c, endpoint)
		})
		r.mu.Unlock()
		if !ok {
			<-r.handshakeSlots
			_ = conn.Close()
		}
	}
}
func (r *Runtime) siteCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closing || !time.Now().Before(r.snap.ExpiresAt) {
		return nil, errors.New("edge authorization expired")
	}
	for _, rr := range r.rules {
		if rr.rule.Protocol == "https" && rr.rule.Domain == host && rr.policyError == "" {
			if cert := r.certificates[rr.rule.CertificateID]; cert != nil {
				if cert.Leaf == nil || time.Now().Before(cert.Leaf.NotBefore) || !time.Now().Before(cert.Leaf.NotAfter) || cert.Leaf.VerifyHostname(host) != nil {
					return nil, errors.New("site certificate expired or mismatched")
				}
				return cert, nil
			}
		}
	}
	return nil, errors.New("unrecognized or unavailable HTTPS site")
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
	ctx   context.Context
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
	c, e := l.Listener.Accept()
	if e != nil {
		<-l.slots
		return nil, e
	}
	return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
}

type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
