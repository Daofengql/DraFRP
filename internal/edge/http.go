package edge

import (
	"bufio"
	"context"
	"drafrp/internal/protocol"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"
)

func (r *Runtime) HTTPHandler() http.Handler { return http.HandlerFunc(r.serveHTTP) }
func (r *Runtime) serveHTTP(w http.ResponseWriter, q *http.Request) {
	// HTTP/1 servers otherwise drain unread uploads before writing a response,
	// which would race the tunnel's request writer for streaming duplex origins.
	_ = http.NewResponseController(w).EnableFullDuplex()
	host := strings.ToLower(strings.TrimSuffix(q.Host, "."))
	if h, _, e := net.SplitHostPort(q.Host); e == nil {
		host = strings.ToLower(strings.TrimSuffix(h, "."))
	}
	requestID := protocol.ID()
	w.Header().Set("X-DraFRP-Request-ID", requestID)
	r.mu.RLock()
	var ruleID string
	for id, rr := range r.rules {
		if (rr.rule.Protocol == "http" || rr.rule.Protocol == "https") && rr.rule.Domain == host {
			ruleID = id
			break
		}
	}
	var redirectPort int
	if ruleID != "" {
		rr := r.rules[ruleID]
		if rr.rule.Protocol == "https" && q.TLS == nil {
			redirectPort = r.snap.Edge.HTTPSPort
		}
		if rr.rule.Protocol == "http" && q.TLS != nil {
			ruleID = ""
		}
	}
	valid := time.Now().Before(r.snap.ExpiresAt)
	r.mu.RUnlock()
	if !valid {
		systemError(w, 503, "authorization_expired", "边缘授权已过期", requestID)
		return
	}
	if ruleID == "" {
		systemError(w, 404, "site_not_found", "未找到此站点", requestID)
		return
	}
	if redirectPort > 0 {
		publicHost := host
		if redirectPort != 443 {
			publicHost = net.JoinHostPort(host, strconv.Itoa(redirectPort))
		}
		http.Redirect(w, q, "https://"+publicHost+q.URL.RequestURI(), http.StatusPermanentRedirect)
		return
	}
	if q.TLS != nil && strings.ToLower(strings.TrimSuffix(q.TLS.ServerName, ".")) != host {
		systemError(w, 421, "authority_mismatch", "TLS 站点身份与请求 Host 不一致", requestID)
		return
	}
	f, e := r.beginFlow(q.Context(), ruleID, q.RemoteAddr)
	if e != nil {
		var ae *admissionError
		if errors.As(e, &ae) {
			if ae.status == 429 {
				w.Header().Set("Retry-After", "1")
			}
			systemError(w, ae.status, ae.code, ae.message, requestID)
		} else {
			systemError(w, 503, "edge_unavailable", e.Error(), requestID)
		}
		return
	}
	defer r.finishFlow(f)
	scheme := "http"
	port := r.Snapshot().Edge.HTTPPort
	if q.TLS != nil {
		scheme = "https"
		port = r.Snapshot().Edge.HTTPSPort
	}
	transport := &tunnelTransport{r: r, f: f, host: host, scheme: scheme, port: port, abortUpload: func() { _ = http.NewResponseController(w).SetReadDeadline(time.Now()) }}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = host
			pr.Out.Host = host
			stripSourceHeaders(pr.Out.Header)
		},
		Transport: transport, BufferPool: httpBuffers{}, FlushInterval: 100 * time.Millisecond,
		ErrorHandler: func(w http.ResponseWriter, q *http.Request, err error) {
			status := 502
			code := "target_unreachable"
			var te *tunnelError
			if errors.As(err, &te) {
				status = te.status
				code = te.code
			}
			if errors.Is(err, context.DeadlineExceeded) {
				status = 504
				code = "target_timeout"
			}
			systemError(w, status, code, "目标服务回源失败", requestID)
		},
	}
	proxy.ServeHTTP(w, q)
}

type tunnelError struct {
	status int
	code   string
	err    error
}

func (e *tunnelError) Error() string { return e.code + ": " + e.err.Error() }
func (e *tunnelError) Unwrap() error { return e.err }

type tunnelTransport struct {
	r            *Runtime
	f            *flowState
	host, scheme string
	port         int
	abortUpload  func()
}

func (t *tunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s, e := t.r.openStream(t.f, protocol.Flow{Host: t.host, Scheme: t.scheme, IngressPort: t.port})
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(t.f.ctx, func() { protocol.Abort(s) })
	_ = s.SetDeadline(time.Now().Add(time.Duration(t.f.rule.TimeoutSeconds) * time.Second))
	metered := &meteredStream{r: t.r, f: t.f, stream: s}
	writeDone := make(chan error, 1)
	req = req.Clone(req.Context())
	req.RequestURI = ""
	stripSourceHeaders(req.Header)
	go func() { writeDone <- req.Write(metered) }()
	var result protocol.Result
	if e = protocol.ReadJSON(s, &result); e != nil {
		stop()
		protocol.Abort(s)
		t.cancelRequestUpload(req, writeDone)
		return nil, e
	}
	if result.Error != "" || result.Code != "" {
		stop()
		protocol.Abort(s)
		t.cancelRequestUpload(req, writeDone)
		status := 502
		if result.Code == "target_timeout" {
			status = 504
		}
		err := &tunnelError{status, result.Code, errors.New(result.Error)}
		t.r.markStatus(t.f.rule, "error", err)
		return nil, err
	}
	reader := bufio.NewReader(&headerGuard{r: metered, remaining: 1 << 20})
	resp, e := http.ReadResponse(reader, req)
	if e != nil {
		stop()
		protocol.Abort(s)
		t.cancelRequestUpload(req, writeDone)
		return nil, e
	}
	_ = s.SetDeadline(time.Time{})
	t.r.markStatus(t.f.rule, "ready", nil)
	// After a 101 the buffered reader belongs to the upgraded byte stream.
	var body io.ReadWriteCloser
	if resp.StatusCode == http.StatusSwitchingProtocols {
		body = &upgradeBody{r: reader, w: metered}
	} else {
		body = &readBody{Reader: resp.Body, close: resp.Body.Close}
	}
	resp.Body = &tunnelBody{ReadWriteCloser: body, stream: s, stop: stop, writeDone: writeDone, abortUpload: func() {
		if t.abortUpload != nil {
			t.abortUpload()
		}
		if req.Body != nil {
			_ = req.Body.Close()
		}
	}}
	return resp, nil
}

func (t *tunnelTransport) cancelRequestUpload(req *http.Request, done <-chan error) {
	select {
	case <-done:
		return
	default:
	}
	if t.abortUpload != nil {
		t.abortUpload()
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	<-done
}

type headerGuard struct {
	r         io.Reader
	remaining int
	tail      [4]byte
	seen      int
	done      bool
}

func (g *headerGuard) Read(p []byte) (int, error) {
	if g.done {
		return g.r.Read(p)
	}
	if g.remaining <= 0 {
		return 0, errors.New("response headers exceed 1 MiB")
	}
	if len(p) > g.remaining {
		p = p[:g.remaining]
	}
	n, e := g.r.Read(p)
	for i, b := range p[:n] {
		g.tail[0], g.tail[1], g.tail[2], g.tail[3] = g.tail[1], g.tail[2], g.tail[3], b
		g.seen++
		if g.seen >= 4 && g.tail == [4]byte{'\r', '\n', '\r', '\n'} {
			g.done = true
			g.remaining -= i + 1
			return n, e
		}
	}
	g.remaining -= n
	return n, e
}

type readBody struct {
	io.Reader
	close func() error
}

func (b *readBody) Write([]byte) (int, error) { return 0, errors.New("response is not upgraded") }
func (b *readBody) Close() error              { return b.close() }

type upgradeBody struct {
	r io.Reader
	w io.Writer
}

func (b *upgradeBody) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *upgradeBody) Write(p []byte) (int, error) { return b.w.Write(p) }
func (b *upgradeBody) Close() error                { return nil }

type tunnelBody struct {
	io.ReadWriteCloser
	stream      protocol.Stream
	stop        func() bool
	writeDone   <-chan error
	abortUpload func()
	once        sync.Once
}

func (b *tunnelBody) Close() error {
	var result error
	b.once.Do(func() {
		b.stop()
		protocol.Abort(b.stream)
		result = b.ReadWriteCloser.Close()
		select {
		case <-b.writeDone:
		default:
			if b.abortUpload != nil {
				b.abortUpload()
			}
			<-b.writeDone
		}
	})
	return result
}

var responseBuffers = sync.Pool{New: func() any { return make([]byte, 32<<10) }}

type httpBuffers struct{}

func (httpBuffers) Get() []byte { return responseBuffers.Get().([]byte) }
func (httpBuffers) Put(b []byte) {
	if cap(b) == 32<<10 {
		responseBuffers.Put(b[:32<<10])
	}
}
func stripSourceHeaders(h http.Header) {
	for key := range h {
		lower := strings.ToLower(key)
		if lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") {
			h.Del(key)
		}
	}
}
func systemError(w http.ResponseWriter, status int, code, message, requestID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.Header().Set("X-DraFRP-Error", code)
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><html lang=zh-CN><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>DraFRP %d</title><style>body{font:16px system-ui;background:#f5f7fb;color:#1d2a42;max-width:42rem;margin:12vh auto;padding:2rem}code{word-break:break-all}</style><h1>%d · %s</h1><p>%s</p><p>请求编号 <code>%s</code></p><p><a href=''>重试</a></p></html>", status, status, html.EscapeString(message), html.EscapeString(code), html.EscapeString(requestID))
}
