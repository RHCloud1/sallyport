// Package server is the drive-site front: every request goes to the decoy
// application unless it is a WebSocket upgrade on the door path carrying a
// valid token, in which case it becomes a tunnel.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"

	"github.com/RHCloud1/sallyport/internal/door"
	"github.com/RHCloud1/sallyport/internal/proto"
	"github.com/RHCloud1/sallyport/internal/wire"
)

type User struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type Config struct {
	// Listen is the address to serve on, e.g. ":443".
	Listen string `json:"listen"`
	// TLSCert and TLSKey enable HTTPS. Leave both empty only when another
	// local server terminates TLS in front of this one.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// Decoy is the real application everybody else sees, e.g. a File Browser
	// listening on "http://127.0.0.1:8080".
	Decoy string `json:"decoy"`
	// Door is the path prefix tunnel requests use; it must match the clients.
	Door string `json:"door"`
	// Proxy turns tunnelling on. With it off the site is only the decoy.
	Proxy *bool  `json:"proxy"`
	Users []User `json:"users"`
	// AllowPrivate lets tunnels reach loopback and private addresses on the
	// server's network. Off by default so a user cannot reach the decoy's
	// admin side or a cloud metadata service.
	AllowPrivate bool `json:"allow_private"`
	// LogTargets logs every destination. Off by default.
	LogTargets bool `json:"log_targets"`
}

const DefaultDoor = "/api/sync/"

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if c.Door == "" {
		c.Door = DefaultDoor
	}
	if !strings.HasPrefix(c.Door, "/") || !strings.HasSuffix(c.Door, "/") {
		return nil, errors.New("door must start and end with /")
	}
	if c.Decoy == "" {
		return nil, errors.New("decoy is required")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("set both tls_cert and tls_key, or neither")
	}
	return &c, nil
}

// state is what a reload may change.
type state struct {
	proxy      bool
	door       string
	names      []string
	keys       []door.Key
	logTargets bool
	allowPriv  bool
	cert       *tls.Certificate
}

func buildState(c *Config) (*state, error) {
	st := &state{
		proxy:      c.Proxy == nil || *c.Proxy,
		door:       c.Door,
		logTargets: c.LogTargets,
		allowPriv:  c.AllowPrivate,
	}
	seen := map[string]bool{}
	for _, u := range c.Users {
		if u.Name == "" || seen[u.Name] {
			return nil, fmt.Errorf("user names must be unique and non-empty (%q)", u.Name)
		}
		seen[u.Name] = true
		k, err := door.ParseKey(u.Key)
		if err != nil {
			return nil, fmt.Errorf("user %s: %w", u.Name, err)
		}
		st.names = append(st.names, u.Name)
		st.keys = append(st.keys, k)
	}
	if c.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, err
		}
		st.cert = &cert
	}
	return st, nil
}

type Server struct {
	cfgPath  string
	listen   string
	useTLS   bool
	decoy    *httputil.ReverseProxy
	verifier *door.Verifier
	state    atomic.Pointer[state]
	upgrader websocket.Upgrader
	dialer   net.Dialer

	mu       sync.Mutex
	sessions map[*smux.Session]string
}

func New(cfgPath string) (*Server, error) {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	st, err := buildState(cfg)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(cfg.Decoy)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("bad decoy url %q", cfg.Decoy)
	}
	s := &Server{
		cfgPath:  cfgPath,
		listen:   cfg.Listen,
		useTLS:   cfg.TLSCert != "",
		verifier: door.NewVerifier(),
		sessions: map[*smux.Session]string{},
		upgrader: websocket.Upgrader{
			ReadBufferSize:  64 * 1024,
			WriteBufferSize: 64 * 1024,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
	}
	s.state.Store(st)
	s.decoy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			r.SetXForwarded()
			if ip := r.In.Header.Get("CF-Connecting-IP"); ip != "" {
				r.Out.Header.Set("X-Forwarded-For", ip)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Server") // the front's own header is the only one
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: log.New(discard{}, "", 0),
	}
	s.dialer = net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			if s.state.Load().allowPriv {
				return nil
			}
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if ip := ap.Addr().Unmap(); !publicAddr(ip) {
				return fmt.Errorf("%s is not a public address", ip)
			}
			return nil
		},
	}
	return s, nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func publicAddr(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(ip) && // CGNAT
		!netip.MustParsePrefix("fc00::/7").Contains(ip)
}

// Reload re-reads the config: users, the proxy switch, logging and the
// certificate change in place. Listen, decoy and door need a restart.
func (s *Server) Reload() error {
	cfg, err := LoadConfig(s.cfgPath)
	if err != nil {
		return err
	}
	st, err := buildState(cfg)
	if err != nil {
		return err
	}
	if s.useTLS && st.cert == nil {
		return errors.New("tls_cert cannot be removed by a reload")
	}
	st.door = s.state.Load().door
	s.state.Store(st)

	// Drop tunnels of users that were removed, and all of them when the proxy
	// is switched off.
	keep := map[string]bool{}
	if st.proxy {
		for _, n := range st.names {
			keep[n] = true
		}
	}
	s.mu.Lock()
	for sess, name := range s.sessions {
		if !keep[name] {
			sess.Close()
		}
	}
	s.mu.Unlock()
	log.Printf("reloaded: proxy=%v users=%d", st.proxy, len(st.names))
	return nil
}

func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.listen,
		Handler:           s,
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(discard{}, "", 0),
	}
	st := s.state.Load()
	log.Printf("serving on %s (tls=%v, proxy=%v, users=%d)", s.listen, s.useTLS, st.proxy, len(st.names))
	if !s.useTLS {
		return srv.ListenAndServe()
	}
	srv.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.state.Load().cert, nil
		},
	}
	return srv.ListenAndServeTLS("", "")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Caddy")
	st := s.state.Load()
	if st.proxy && strings.HasPrefix(r.URL.Path, st.door) && websocket.IsWebSocketUpgrade(r) {
		if i, nonce := s.verifier.Check(st.keys, r.URL.Path[len(st.door):], time.Now()); i >= 0 {
			s.serveTunnel(w, r, st.names[i], st.keys[i], nonce)
			return
		}
	}
	s.decoy.ServeHTTP(w, r)
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (s *Server) serveTunnel(w http.ResponseWriter, r *http.Request, name string, key door.Key, nonce []byte) {
	c2s, s2c, err := wire.SessionKeys(key[:], nonce)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	ws, err := s.upgrader.Upgrade(w, r, http.Header{"Server": {"Caddy"}})
	if err != nil {
		return
	}
	conn, err := wire.New(ws, s2c, c2s, 5*time.Minute)
	if err != nil {
		ws.Close()
		return
	}
	sess, err := smux.Server(conn, proto.SmuxConfig())
	if err != nil {
		conn.Close()
		return
	}
	s.mu.Lock()
	s.sessions[sess] = name
	s.mu.Unlock()

	from := clientIP(r)
	start := time.Now()
	var up, down atomic.Int64
	var streams int
	log.Printf("tunnel open: user=%s from=%s", name, from)
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			break
		}
		streams++
		go s.handleStream(stream, name, &up, &down)
	}
	sess.Close()
	s.mu.Lock()
	delete(s.sessions, sess)
	s.mu.Unlock()
	log.Printf("tunnel closed: user=%s from=%s streams=%d up=%s down=%s age=%s",
		name, from, streams, size(up.Load()), size(down.Load()), time.Since(start).Round(time.Second))
}

func (s *Server) handleStream(stream *smux.Stream, user string, up, down *atomic.Int64) {
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	target, err := proto.ReadAddr(stream)
	if err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	if s.state.Load().logTargets {
		log.Printf("user=%s target=%s", user, target)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, err := s.dialer.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		if s.state.Load().logTargets {
			log.Printf("user=%s target=%s: %v", user, target, err)
		}
		return
	}
	u, d := proto.Relay(stream, out, time.Minute)
	up.Add(u)
	down.Add(d)
}

func size(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
