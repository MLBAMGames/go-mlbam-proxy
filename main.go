package main
import (
    "flag"
    "fmt"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "time"
    "crypto/tls"
    "net"
    "strings"
)

type baseHandle struct{}

var (
    _port        int
    _destination string
    _sources   []string
)

func contains(domains []string, url string) bool {
    log.Printf("source: %v, value: %v", domains, url)
    for _, domain := range domains {
        log.Printf("element: %v", domain)
		if strings.HasSuffix(url, domain) {
			return true
		}
	}
	return false
}

func getScheme(r *http.Request) string {
    if r.TLS != nil {
        return "https"
    }
    return "http"
}

func initParameters() {
    log.SetOutput(os.Stdout)
    _sources = []string {}
	
    // removed defaults tags
    flag.IntVar(&_port, "p", 17070, "Port used by the local proxy")
    flag.StringVar(&_destination, "d", "freegamez.ga", "Destination domain to forward source domains requests to.")
    
    sources := flag.String("s", "mf.svc.nhl.com", "Source domains to redirect requests from, separated by commas.")
    for _, hostname := range strings.Split(*sources, ",") {
        _sources = append(_sources, hostname)
    }

    flag.Parse()
                        
    if (_destination == "" || *sources == "") {
        flag.PrintDefaults()
        os.Exit(1)
    }
}

func copyRequest(u *url.URL, r *http.Request) (*http.Request, error) {
	target := r.URL
	target.Scheme = u.Scheme
    target.Host = u.Host

    req, err := http.NewRequest(r.Method, target.String(), r.Body)
	if err != nil {
		return nil, err
	}
	for key := range r.Header {
		req.Header.Set(key, r.Header.Get(key))
	}

	if r.Referer() != "" {
		req.Header.Set("Referer", strings.Replace(r.Referer(), r.Host, u.Host, -1))
    }
    
    r.Header.Add("X-Forwarded-Host", r.Host)
    r.Header.Add("X-Origin-Host", target.Host)

	req.Header.Del("Accept-Encoding")
	return req, nil
}

func setupResponse(w *http.ResponseWriter) {
    (*w).Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, accessToken, Authorization, Accept, Range")
}

func dialTLS(network, addr string) (net.Conn, error) {
    conn, err := net.Dial(network, addr)
    if err != nil {
        return nil, err
    }

    host, _, err := net.SplitHostPort(addr)
    if err != nil {
        return nil, err
    }
    cfg := &tls.Config{ServerName: host}

    tlsConn := tls.Client(conn, cfg)
    if err := tlsConn.Handshake(); err != nil {
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
    host := r.Host

    proxyurl:= r.URL
    if contains(_sources, host) {
        url, err := url.Parse(fmt.Sprintf("%s://%s", getScheme(r), _destination))
        if err != nil {
            log.Fatalf("Error: %v", err)
            return
        }
        log.Printf("destination: %v", _destination)
        proxyurl = url
        log.Printf("url1: %v", proxyurl)
    }

    proxy := httputil.NewSingleHostReverseProxy(proxyurl)
    log.Printf("url2: %v", proxyurl)
    r, _ = copyRequest(proxyurl, r)
    log.Printf("proxy request: %v", r.URL)
    
    setupResponse(&w)
    proxy.Transport = &http.Transport {
        DialTLS: dialTLS,
        TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
    }
    proxy.Director = func(r *http.Request) {
        r.URL = proxyurl
        r.Host = proxyurl.Host
    }

    proxy.ServeHTTP(w, r)
}

func runProxyServer() {
    h := &baseHandle{}
    http.Handle("/", h)

    server := &http.Server {
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