// Package client exposes a local SOCKS5/HTTP proxy and carries every
// connection through tunnels to the server.
package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/RHCloud1/sallyport/internal/door"
	"github.com/RHCloud1/sallyport/internal/proto"
)

type Config struct {
	// Listen is the local proxy address; it speaks both SOCKS5 and HTTP.
	Listen string `json:"listen"`
	// Server is the site's domain name.
	Server string `json:"server"`
	Port   int    `json:"port"`
	Door   string `json:"door"`
	Key    string `json:"key"`
	// Endpoints are addresses to connect to instead of resolving Server,
	// normally a handful of Cloudflare IPs; the fastest is used and failing
	// ones are skipped.
	Endpoints []string `json:"endpoints"`
	// Tunnels is the most WebSockets open at once.
	Tunnels int `json:"tunnels"`
	// DriveUser and DrivePass are a real account on the decoy drive; when
	// set, the client signs in to it before tunnelling, as its web page would.
	DriveUser string `json:"drive_user"`
	DrivePass string `json:"drive_pass"`
	// CAFile and Insecure are for testing against a private certificate.
	CAFile   string `json:"ca_file"`
	Insecure bool   `json:"insecure"`
}

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
		c.Listen = "127.0.0.1:1080"
	}
	if c.Server == "" {
		return nil, errors.New("server is required")
	}
	if c.Port == 0 {
		c.Port = 443
	}
	if c.Door == "" {
		c.Door = "/api/sync/"
	}
	if !strings.HasPrefix(c.Door, "/") || !strings.HasSuffix(c.Door, "/") {
		return nil, errors.New("door must start and end with /")
	}
	if c.Tunnels <= 0 {
		c.Tunnels = 2
	}
	return &c, nil
}

type Client struct {
	cfg  *Config
	pool *pool
	eps  *endpoints
}

func New(cfg *Config) (*Client, error) {
	key, err := door.ParseKey(cfg.Key)
	if err != nil {
		return nil, err
	}
	d, err := newDialer(cfg, key)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, pool: newPool(d, cfg.Tunnels), eps: d.eps}, nil
}

func (c *Client) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("local proxy on %s (socks5 + http) -> %s", ln.Addr(), c.cfg.Server)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go c.pool.maintain(ctx)
	go c.remeasure(ctx)
	go func() {
		// Open the first tunnel right away so the first request is fast.
		if s, err := c.pool.open(ctx); err == nil {
			s.Close()
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go c.serveLocal(ctx, conn)
	}
}

func (c *Client) remeasure(ctx context.Context) {
	for {
		c.eps.measure(ctx)
		if len(c.cfg.Endpoints) > 1 {
			log.Printf("endpoints:%s", c.eps.summary())
		} else {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Minute):
		}
	}
}

// localConn reads through the buffered reader that sniffed the protocol.
type localConn struct {
	*bufio.Reader
	net.Conn
}

func (l localConn) Read(p []byte) (int, error) { return l.Reader.Read(p) }

func (l localConn) CloseWrite() error {
	if cw, ok := l.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return l.Conn.Close()
}

func (c *Client) serveLocal(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReaderSize(conn, 16*1024)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	var target string
	var prefix []byte // bytes to send right after the stream header
	var req *http.Request
	if first[0] == 5 {
		target, err = socks5(conn, br)
	} else {
		req, err = http.ReadRequest(br)
		if err == nil {
			target, err = httpTarget(conn, req)
		}
	}
	if err != nil {
		return
	}
	if req == nil || req.Method == http.MethodConnect {
		// Send the address together with the first bytes the application
		// writes (a TLS ClientHello, usually), which saves a round trip.
		prefix = peekInitial(conn, br)
	}
	_ = conn.SetReadDeadline(time.Time{})

	stream, err := c.pool.open(ctx)
	if err != nil {
		return
	}
	defer stream.Close()
	head, err := proto.AppendAddr(make([]byte, 0, 300+len(prefix)), target)
	if err != nil {
		return
	}
	if _, err := stream.Write(append(head, prefix...)); err != nil {
		return
	}
	if req != nil && req.Method != http.MethodConnect {
		if err := req.Write(stream); err != nil {
			return
		}
	}
	proto.Relay(localConn{br, conn}, stream, time.Minute)
}

// peekInitial returns what the application sends within a few milliseconds
// of the proxy handshake finishing; protocols where the server talks first
// just get nothing.
func peekInitial(conn net.Conn, br *bufio.Reader) []byte {
	if br.Buffered() == 0 {
		_ = conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
		_, _ = br.Peek(1)
	}
	n := br.Buffered()
	if n == 0 {
		return nil
	}
	b := make([]byte, n)
	_, _ = io.ReadFull(br, b)
	return b
}

func socks5(conn net.Conn, br *bufio.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return "", err
	}
	if _, err := br.Discard(int(hdr[1])); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return "", err
	}
	if req[0] != 5 || req[1] != 1 { // only CONNECT
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", errors.New("socks5: unsupported command")
	}
	var host string
	switch req[3] {
	case 1, 4:
		n := 4
		if req[3] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", errors.New("socks5: bad address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(br, port[:]); err != nil {
		return "", err
	}
	// Reply before the remote side is connected; a failure shows up as the
	// connection closing, which every application handles.
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func httpTarget(conn net.Conn, req *http.Request) (string, error) {
	if req.Method == http.MethodConnect {
		target := req.Host
		if _, _, err := net.SplitHostPort(target); err != nil {
			target = net.JoinHostPort(target, "443")
		}
		_, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		return target, err
	}
	if !req.URL.IsAbs() || req.URL.Scheme != "http" {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return "", errors.New("http: not a proxy request")
	}
	target := req.URL.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "80")
	}
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	// One request per connection keeps forwarding trivial: the next request,
	// possibly to another host, comes on a new connection.
	req.Close = true
	return target, nil
}
