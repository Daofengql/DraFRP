package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"drafrp/internal/model"
	"drafrp/internal/protocol"
)

// Source identity is request scoped. Neither the visitor's headers nor the
// origin connection pool is an authority for these values.
var managedHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Server", "X-Original-Forwarded-For", "True-Client-IP", "CF-Connecting-IP"}

func deleteHeader(h http.Header, key string) {
	for k := range h {
		if strings.EqualFold(k, key) {
			delete(h, k)
		}
	}
}
func stripHopHeaders(h http.Header) {
	for k, vals := range h {
		if strings.EqualFold(k, "Connection") {
			for _, v := range vals {
				for _, token := range strings.Split(v, ",") {
					deleteHeader(h, strings.TrimSpace(token))
				}
			}
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		deleteHeader(h, k)
	}
}
func hasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}
func ruleTimeout(r model.Rule) time.Duration {
	if r.TimeoutSeconds < 1 {
		return 30 * time.Second
	}
	return time.Duration(min(r.TimeoutSeconds, 3600)) * time.Second
}
func transportKey(r model.Rule) string { return fmt.Sprintf("%s/%d", r.ID, r.Version) }

func (a *Agent) originTransport(r model.Rule) (*http.Transport, error) {
	key := transportKey(r)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		return nil, errors.New("agent closed")
	}
	if t := a.transports[key]; t != nil {
		return t, nil
	}
	tc, err := protocol.TLSClient(a.cfg.OriginCAFile, "", r.ServerName)
	if err != nil {
		return nil, err
	}
	// HTTP/1.1 deliberately supports both streaming and upgrades. The carrier
	// still multiplexes independent requests, and origin keep-alive is reused.
	tc.NextProtos = []string{"http/1.1"}
	t := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return a.dialTargetFamily(ctx, network, address, "", false)
	}, TLSClientConfig: tc, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: ruleTimeout(r), ExpectContinueTimeout: time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 64, MaxResponseHeaderBytes: 64 << 10, ForceAttemptHTTP2: false}
	a.transports[key] = t
	return t, nil
}

// joinURLPath retains escaped slashes, rather than decoding and re-encoding a
// path in a way that could change which origin resource the request selects.
func joinURLPath(a, b *url.URL) (string, string) {
	join := func(x, y string) string {
		as, bs := strings.HasSuffix(x, "/"), strings.HasPrefix(y, "/")
		if as && bs {
			return x + y[1:]
		}
		if !as && !bs {
			return x + "/" + y
		}
		return x + y
	}
	if a.RawPath == "" && b.RawPath == "" {
		return join(a.Path, b.Path), ""
	}
	return join(a.Path, b.Path), join(a.EscapedPath(), b.EscapedPath())
}
func buildOriginRequest(ctx context.Context, req *http.Request, r model.Rule, f protocol.Flow) (*http.Request, error) {
	target, err := url.Parse(r.Target)
	if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || target.Fragment != "" || target.RawQuery != "" {
		return nil, errors.New("invalid origin URL")
	}
	peer, err := netip.ParseAddrPort(f.Peer)
	if err != nil || peer.Addr().IsUnspecified() || peer.Addr().IsMulticast() || peer.Port() == 0 {
		return nil, errors.New("invalid trusted peer")
	}
	if req.Method == http.MethodConnect || req.URL == nil || !strings.HasPrefix(req.URL.Path, "/") {
		return nil, errors.New("unsupported origin request")
	}
	out := req.Clone(ctx)
	out.URL.Scheme = target.Scheme
	out.URL.Host = target.Host
	out.URL.User = nil
	out.URL.Opaque = ""
	out.URL.Fragment = ""
	out.URL.Path, out.URL.RawPath = joinURLPath(target, req.URL)
	out.RequestURI = ""
	out.Close = false
	out.Host = f.Host
	if r.Host != "" {
		out.Host = r.Host
	}
	upgrade := req.Header.Get("Upgrade")
	isUpgrade := hasToken(req.Header, "Connection", "upgrade") && strings.EqualFold(upgrade, "websocket")
	stripHopHeaders(out.Header)
	stripHopHeaders(out.Trailer)
	for _, k := range managedHeaders {
		deleteHeader(out.Header, k)
		deleteHeader(out.Trailer, k)
	}
	out.Header.Set("X-Forwarded-For", peer.Addr().Unmap().String())
	out.Header.Set("X-Real-IP", peer.Addr().Unmap().String())
	out.Header.Set("X-Forwarded-Proto", f.Scheme)
	out.Header.Set("X-Forwarded-Host", f.Host)
	out.Header.Set("X-Forwarded-Port", strconv.Itoa(f.IngressPort))
	if isUpgrade {
		out.Header.Set("Connection", "Upgrade")
		out.Header.Set("Upgrade", "websocket")
	}
	return out, nil
}

type bufferedStream struct {
	protocol.Stream
	reader *bufio.Reader
}

// net/http's server-side request body Close drains unread bytes. On a tunnel
// that would wait for an unbounded upload before returning an origin failure.
// The stream owns cancellation; the Transport only owns this reader wrapper.
type tunnelRequestBody struct{ io.Reader }

func (tunnelRequestBody) Close() error { return nil }

func (s *bufferedStream) Read(b []byte) (int, error) { return s.reader.Read(b) }
func (s *bufferedStream) CloseWrite() error          { protocol.HalfClose(s.Stream); return nil }

func (a *Agent) serveHTTP(ctx context.Context, st protocol.Stream, r model.Rule, f protocol.Flow) {
	br := bufio.NewReaderSize(&headerLimitedReader{r: st, remaining: 64 << 10}, 32<<10)
	// Header parsing is bounded independently of an arbitrarily large upload.
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = protocol.WriteJSON(st, protocol.Result{Code: "bad_request", Error: "invalid request headers"})
		return
	}
	_ = st.SetDeadline(time.Time{})
	out, err := buildOriginRequest(ctx, req, r, f)
	if err != nil {
		_ = protocol.WriteJSON(st, protocol.Result{Code: "bad_request", Error: err.Error()})
		return
	}
	if out.Body != nil && out.Body != http.NoBody {
		out.Body = tunnelRequestBody{Reader: out.Body}
	}
	t, err := a.originTransport(r)
	if err != nil {
		_ = protocol.WriteJSON(st, protocol.Result{Code: "origin_configuration", Error: err.Error()})
		return
	}
	resp, err := t.RoundTrip(out)
	if err != nil {
		code := "target_unreachable"
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			code = "target_timeout"
		}
		_ = protocol.WriteJSON(st, protocol.Result{Code: code, Error: err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		upstream, ok := resp.Body.(io.ReadWriteCloser)
		if !ok || !hasToken(out.Header, "Connection", "upgrade") || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
			_ = protocol.WriteJSON(st, protocol.Result{Code: "bad_upgrade", Error: "invalid origin protocol upgrade"})
			return
		}
		stripHopHeaders(resp.Header)
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", "websocket")
		if protocol.WriteJSON(st, protocol.Result{}) != nil {
			return
		}
		// Writing a 101 response with its live upgraded body would read the
		// socket as an HTTP entity; write only the handshake before relaying.
		head := *resp
		head.Body = nil
		head.ContentLength = 0
		if head.Write(st) != nil {
			return
		}
		_ = protocol.Relay(ctx, &bufferedStream{Stream: st, reader: br}, upstream)
		return
	}
	stripHopHeaders(resp.Header)
	stripHopHeaders(resp.Trailer)
	if protocol.WriteJSON(st, protocol.Result{}) != nil {
		return
	}
	_ = resp.Write(st)
}

// Only the header section is limited; after its terminator the same reader
// streams an unlimited body without buffering it. ReadRequest's private
// buffer remains attached to req.Body, preserving read-ahead body bytes.
type headerLimitedReader struct {
	r         io.Reader
	remaining int
	matched   int
	done      bool
}

func (r *headerLimitedReader) Read(p []byte) (int, error) {
	if r.done {
		return r.r.Read(p)
	}
	if r.remaining <= 0 {
		return 0, errors.New("HTTP headers exceed limit")
	}
	// A one-byte boundary scan ensures the limit never counts body bytes.
	n, err := r.r.Read(p[:1])
	if n == 0 {
		return n, err
	}
	r.remaining--
	const end = "\r\n\r\n"
	if p[0] == end[r.matched] {
		r.matched++
	} else if p[0] == '\r' {
		r.matched = 1
	} else {
		r.matched = 0
	}
	if r.matched == len(end) {
		r.done = true
	}
	return n, err
}
