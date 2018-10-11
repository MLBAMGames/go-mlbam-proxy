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
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return newURL, nil
}

func initParameters() {
	log.SetOutput(os.Stdout)
	_sources = []string{}

	// removed defaults tags
	flag.IntVar(&_port, "p", 17070, "Port used by the local proxy")
	flag.StringVar(&_destination, "d", "freegamez.ga", "Destination domain to forward source domains requests to.")

	sources := flag.String("s", "mf.svc.nhl.com", "Source domains to redirect requests from, separated by commas.")
	for _, hostname := range strings.Split(*sources, ",") {
		_sources = append(_sources, hostname)
	}

	flag.Parse()

	if _destination == "" || *sources == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func copyRequest(u *url.URL, r *http.Request) (*http.Request, error) {

	target, _ := getURL(r, false)
	target.Scheme = u.Scheme
	target.Host = u.Host

	log.Printf("url %v, host %v", target, r.Host)

	req, err := http.NewRequest(r.Method, target.String(), r.Body)
	if err != nil {
		log.Fatalf("Error: %v", err)
		return nil, err
	}

	for key := range r.Header {
		req.Header.Set(key, r.Header.Get(key))
	}

	if r.Referer() != "" {
		req.Header.Set("Referer", strings.Replace(r.Referer(), r.Host, u.Host, -1))
	}

	req.Header.Del("Accept-Encoding")

	// Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			log.Printf("header %v: %v", name, h)
		}
	}

	return req, nil
}

func setupResponse(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, accessToken, Authorization, Accept, Range")
}

func dialTLS(network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	cfg := &tls.Config{ServerName: host}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		log.Fatal(err)
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
	if err != nil {
		log.Fatalf("Error: %v", err)
		return
	}

	if contains(_sources, r.URL.Hostname()) {
		url, err := getURL(r, true)
		if err != nil {
			log.Fatalf("Error: %v", err)
			return
		}
		log.Printf("destination: %v", _destination)
		proxyURL = url
		log.Printf("url1: %v", proxyURL)
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

	log.Printf("proxy server listening on port: %d", _port)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Error: %v", err)
		return
	}
}

func main() {
	initParameters()
	runProxyServer()
}
