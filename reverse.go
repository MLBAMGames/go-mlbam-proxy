package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var onExitFlushLoop func()

const defaultTimeout = time.Minute * 15

// ReverseProxy is an HTTP Handler that takes an incoming request
// and sends it to another server
type ReverseProxy struct {
	Timeout        time.Duration
	Director       func(*http.Request)
	Transport      http.RoundTripper
	FlushInterval  time.Duration
	ErrorLog       *log.Logger
	ModifyResponse func(*http.Response) error
}

type requestCanceler interface {
	CancelRequest(req *http.Request)
}

// NewReverseProxy returns a new ReverseProxy that routes URLs
func NewReverseProxy(target *url.URL) *ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)

		req.Host = req.URL.Host
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}

		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}

	return &ReverseProxy{Director: director}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func (p *ReverseProxy) copyResponse(dst io.Writer, src io.Reader) {
	if p.FlushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: p.FlushInterval,
				done:    make(chan bool),
			}

			go mlw.flushLoop()
			defer mlw.stop()
			dst = mlw
		}
	}

	io.Copy(dst, src)
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration
	mu      sync.Mutex
	done    chan bool
}

func (m *maxLatencyWriter) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dst.Write(b)
}

func (m *maxLatencyWriter) flushLoop() {
	t := time.NewTicker(m.latency)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			if onExitFlushLoop != nil {
				onExitFlushLoop()
			}
			return
		case <-t.C:
			m.mu.Lock()
			m.dst.Flush()
			m.mu.Unlock()
		}
	}
}

func (m *maxLatencyWriter) stop() {
	m.done <- true
}

func (p *ReverseProxy) logf(format string, args ...interface{}) {
	if p.ErrorLog != nil {
		p.ErrorLog.Printf(format, args...)
	} else {
		logf(format, args...)
	}
}

func removeHeaders(header http.Header) {
	// Remove hop-by-hop headers listed in the "Connection" header.
	if c := header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				header.Del(f)
			}
		}
	}

	// Remove hop-by-hop headers
	for _, h := range hopHeaders {
		if header.Get(h) != "" {
			header.Del(h)
		}
	}
}

func addXForwardedForHeader(req *http.Request) {
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}
}

func (p *ReverseProxy) ProxyHTTP(rw http.ResponseWriter, req *http.Request) {
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	outreq := new(http.Request)
	// Shallow copies of maps, like header
	*outreq = *req

	if cn, ok := rw.(http.CloseNotifier); ok {
		if requestCanceler, ok := transport.(requestCanceler); ok {
			// After the Handler has returned, there is no guarantee
			// that the channel receives a value, so to make sure
			reqDone := make(chan struct{})
			defer close(reqDone)
			clientGone := cn.CloseNotify()

			go func() {
				select {
				case <-clientGone:
					requestCanceler.CancelRequest(outreq)
				case <-reqDone:
				}
			}()
		}
	}

	p.Director(outreq)
	outreq.Close = false

	// We may modify the header (shallow copied above), so we only copy it.
	outreq.Header = make(http.Header)
	copyHeader(outreq.Header, req.Header)

	// Remove hop-by-hop headers listed in the "Connection" header, Remove hop-by-hop headers.
	removeHeaders(outreq.Header)

	// Add X-Forwarded-For Header.
	addXForwardedForHeader(outreq)

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}

	// Remove hop-by-hop headers listed in the "Connection" header of the response, Remove hop-by-hop headers.
	removeHeaders(res.Header)

	if p.ModifyResponse != nil {
		if err := p.ModifyResponse(res); err != nil {
			p.logf("http: proxy error: %v", err)
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
	}

	// Copy header from response to client.
	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response, Build it up from Trailer.
	if len(res.Trailer) > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)
	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	p.copyResponse(rw, res.Body)
	// close now, instead of defer, to populate res.Trailer
	res.Body.Close()
	copyHeader(rw.Header(), res.Trailer)
}

// ProxyHTTPS uses an HTTPS protocol when the proxy makes its requests
func (p *ReverseProxy) ProxyHTTPS(rw http.ResponseWriter, req *http.Request) {
	hij, ok := rw.(http.Hijacker)
	if !ok {
		p.logf("http server does not support hijacker")
		time.Sleep(500 * time.Millisecond)
		return
	}

	clientConn, _, err := hij.Hijack()
	if err != nil {
		p.logf("http: proxy error: %v", err)
		if clientConn != nil {
			clientConn.Close()
		}
		return
	}

	proxyConn, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		p.logf("dial stopped %v", req.URL)
		p.logf("client connection stopped")
		clientConn.Close()
		if proxyConn != nil {
			proxyConn.Close()
		}
		return
	}

	deadline := time.Now()
	if p.Timeout == 0 {
		deadline = deadline.Add(defaultTimeout)
	} else {
		deadline = deadline.Add(p.Timeout)
	}

	err = clientConn.SetDeadline(deadline)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		clientConn.Close()
		proxyConn.Close()
		time.Sleep(500 * time.Millisecond)
		return
	}

	err = proxyConn.SetDeadline(deadline)
	if err != nil {
		p.logf("http: proxy error: %v", err)
		clientConn.Close()
		proxyConn.Close()
		time.Sleep(500 * time.Millisecond)
		return
	}

	_, err = clientConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		proxyConn.Close()
		return
	}

	stop := make(chan bool)

	go transfer(clientConn, proxyConn, stop)
	go transfer(proxyConn, clientConn, stop)

	select {
	case <-stop:
		return
	}
}

func transfer(dest io.WriteCloser, src io.ReadCloser, stop chan bool) {
	defer func() { _ = dest.Close() }()
	defer func() { _ = src.Close() }()
	_, err := io.Copy(dest, src)
	if err != nil {
		stop <- true
		return
	}
}

// ServeHTTP determines if the request is a secured scheme or not
// and reroute to the proper proxy method
func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.ProxyHTTPS(rw, req)
	} else {
		p.ProxyHTTP(rw, req)
	}
}
