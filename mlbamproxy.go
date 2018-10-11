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

	"github.com/cssivision/reverseproxy"
)

type baseHandle struct{}

var (
	_port        int
	_destination string
	_sources     []string
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
		log.Fatalf("[MLBAMProxy] Error: %v", err)
		return true
	}

	return false
}

func logf(format string, args ...interface{}) {
	log.Printf("[MLBAMProxy] "+format, args...)
}

func canRedirect() bool {
	return len(_sources) > 0 && _destination != ""
}

func getScheme(r *http.Request) string {
	if r.TLS != nil || r.Method == "CONNECT" || r.URL.Scheme == "https" {
		return "https"
	}

	return "http"
}

func getURL(r *http.Request, isDestination bool) (*url.URL, error) {
	hostname := r.URL.Hostname()
	port := r.URL.Port()

	if isDestination {
		hostname = _destination
	}

	raw := fmt.Sprintf("%v://%v:%v", getScheme(r), hostname, port)
	if port == "" {
		raw = fmt.Sprintf("%v://%v", getScheme(r), hostname)
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

	flag.IntVar(&_port, "p", 8080, "Port used by the local proxy")
	flag.StringVar(&_destination, "d", "", "Destination domain to forward source domains requests to.")
	sources := flag.String("s", "", "Source domains to redirect requests from, separated by commas.")

	flag.Parse()

	for _, hostname := range strings.Split(*sources, ",") {
		if hostname != "" {
			_sources = append(_sources, hostname)
		}
	}

	if !canRedirect() {
		logf("Proxy won't redirect, missing flags -s (sources) and/or -d (destination)")
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

	if r.Referer() != "" {
		req.Header.Set("Referer", strings.Replace(r.Referer(), r.Host, u.Host, -1))
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
		return nil, err
	}

	cfg := &tls.Config{ServerName: host}

	tlsConn := tls.Client(conn, cfg)
	err = tlsConn.Handshake()
	if logError(err) {
		conn.Close()
		return nil, err
	}

	cs := tlsConn.ConnectionState()
	cert := cs.PeerCertificates[0]

	cert.VerifyHostname(host)
	log.Println(cert.Subject)

	return tlsConn, nil
}

func (h *baseHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyURL, err := getURL(r, false)
	if logError(err) {
		return
	}

	if canRedirect() && contains(_sources, r.URL.Hostname()) {
		url, err := getURL(r, true)
		if logError(err) {
			return
		}
		proxyURL = url
	}

	proxy := reverseproxy.NewReverseProxy(proxyURL)

	r, _ = copyRequest(proxyURL, r)

	setupResponse(&w)

	proxy.Transport = &http.Transport{
		DialTLS:         dialTLS,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		TLSNextProto:    make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}

	proxy.Director = func(r *http.Request) {
		r.Header.Add("X-Forwarded-Host", r.Host)
		r.Header.Add("X-Origin-Host", proxyURL.Host)
		r.URL.Scheme = getScheme(r)
		r.URL.Host = proxyURL.Host
		r.Host = proxyURL.Host
	}

	proxy.ServeHTTP(w, r)
}

func runProxyServer() {
	h := &baseHandle{}
	http.Handle("/", h)

	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", _port),
		Handler:        h,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	logf("Proxy server listening on port: %d", _port)

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
