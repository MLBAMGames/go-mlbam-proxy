package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const version = "1.1.1"

type baseHandle struct{}

var (
	_port        int
	_destination string
	_sources     []string
	_debug       bool
	_version     bool
)

func contains(domains []string, url string) bool {
	for _, domain := range domains {
		if strings.HasSuffix(url, domain) {
			return true
		}
	}

	return false
}

func logError(err error) bool {
	if err != nil {
		log.Printf("[MLBAMProxy] Error: %v", err)
		return true
	}

	return false
}

func printf(format string, args ...interface{}) {
	log.Printf("[MLBAMProxy] "+format, args...)
}

func logf(format string, args ...interface{}) {
	if _debug {
		log.Printf("[MLBAMProxy] Debug: "+format, args...)
	}
}

func canRedirect() bool {
	return len(_sources) > 0 && _destination != ""
}

func getScheme(r *http.Request) string {
	if r.Method == http.MethodConnect {
		return "https://"
	}
	return "http://"
}

func getPort(r *http.Request) string {
	if r.URL.Port() != "" {
		return r.URL.Port()
	}
	if r.Method == http.MethodConnect {
		return "433"
	}
	return "80"
}

func getURL(r *http.Request, isDestination bool) (*url.URL, error) {
	hostname := r.URL.Hostname()
	port := getPort(r)

	if isDestination {
		hostname = _destination
	}

	raw := fmt.Sprintf("%v%v:%v", getScheme(r), hostname, port)
	if port == "" {
		raw = fmt.Sprintf("%v%v", getScheme(r), hostname)
	}
	if r.URL.Path != "" {
		raw = fmt.Sprintf("%v%v", raw, r.URL.Path)
	}

	newURL, err := url.Parse(raw)
	if logError(err) {
		return nil, err
	}

	return newURL, nil
}

func initParameters() {
	_sources = []string{}

	flag.BoolVar(&_debug, "debug", false, "Debug mode")
	flag.BoolVar(&_version, "v", false, "Version")
	flag.IntVar(&_port, "p", 17070, "Port used by the local proxy")
	flag.StringVar(&_destination, "d", "", "Destination domain to forward source domains requests to.")
	sources := flag.String("s", "", "Source domains to redirect requests from, separated by commas. (e.g.: --s google.com,facebook.com)")

	flag.Parse()

	if _version {
		fmt.Printf("version %v", version)
		os.Exit(1)
	}

	for _, hostname := range strings.Split(*sources, ",") {
		if hostname != "" {
			_sources = append(_sources, hostname)
		}
	}

	if !canRedirect() {
		printf("Proxy will act as a default proxy and won't redirect a domain to another, no sources and/or destination were specified")
	}
}

func copyRequest(u *url.URL, r *http.Request) (*http.Request, error) {
	target, _ := getURL(r, false)
	target.Scheme = u.Scheme
	target.Host = u.Host

	req, err := http.NewRequest(r.Method, target.String(), r.Body)
	if logError(err) {
		return nil, err
	}

	for key := range r.Header {
		req.Header.Set(key, r.Header.Get(key))
	}

	req.Header.Set("Host", u.Host)

	if r.Referer() != "" {
		req.Header.Set("Referer", strings.Replace(r.Referer(), r.Host, u.Host, -1))
	}

	req.Header.Set("X-Forwarded-Proto", "http")
	if r.TLS != nil {
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Proto"), "https")
		req.Header.Set(http.CanonicalHeaderKey("X-Forwarded-Port"), fmt.Sprintf("%v", _port))
	}

	req.Header.Del("Accept-Encoding")

	return req, nil
}

func setupResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, accessToken, Authorization, Accept, Range")
}

func dialTLS(network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if logError(err) {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if logError(err) {
		conn.Close()
		return nil, err
	}

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Client(conn, cfg)
	err = tlsConn.Handshake()
	if logError(err) {
		conn.Close()
		tlsConn.Close()
		return nil, err
	}

	cs := tlsConn.ConnectionState()
	cert := cs.PeerCertificates[0]

	cert.VerifyHostname(host)
	logf("%v", cert.Subject)

	return tlsConn, nil
}

func (h *baseHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyURL, err := getURL(r, false)
	if logError(err) {
		return
	}

	logf("Request URL: %v", proxyURL)

	if canRedirect() && contains(_sources, r.URL.Hostname()) {
		url, err := getURL(r, true)
		if logError(err) {
			return
		}
		proxyURL = url

		logf("Request URL redirected to: %v", proxyURL)
	}

	proxy := NewReverseProxy(proxyURL)
	proxy.Timeout = 60 * time.Minute

	r, _ = copyRequest(proxyURL, r)

	setupResponse(&w)

	proxy.Transport = &http.Transport{
		DialTLS: dialTLS,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		Proxy:        http.ProxyURL(proxyURL),
		Dial: (&net.Dialer{
			Timeout:       3 * time.Minute,
			KeepAlive:     30 * time.Second,
			FallbackDelay: 300 * time.Millisecond,
			Deadline:      time.Now().Add(60 * time.Second),
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        100,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}

	proxy.Director = func(r *http.Request) {
		r.URL.Host = proxyURL.Host
		r.Host = proxyURL.Host
	}

	proxy.ServeHTTP(w, r)
}

func runProxyServer() {
	h := &baseHandle{}
	http.Handle("/", h)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", _port),
		Handler:           h,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	printf("Proxy server listening on port: %d", _port)
	err := server.ListenAndServe()

	if logError(err) {
		return
	}
}

func main() {
	log.SetOutput(os.Stdout)
	initParameters()
	runProxyServer()
}
