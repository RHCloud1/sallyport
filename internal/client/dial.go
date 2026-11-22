package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"

	"github.com/RHCloud1/sallyport/internal/door"
	"github.com/RHCloud1/sallyport/internal/proto"
	"github.com/RHCloud1/sallyport/internal/wire"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// endpoint is one address the CDN answers on (or the server itself in tests).
type endpoint struct {
	addr      string
	rtt       time.Duration
	failures  int
	failUntil time.Time
}

// endpoints keeps the candidate addresses ordered by measured latency and
// skips the ones that recently failed.
type endpoints struct {
	mu       sync.Mutex
	list     []*endpoint
	measured time.Time
}

func newEndpoints(addrs []string, host string, port int) *endpoints {
	e := &endpoints{}
	if len(addrs) == 0 {
		addrs = []string{host}
	}
	for _, a := range addrs {
		if _, _, err := net.SplitHostPort(a); err != nil {
			a = net.JoinHostPort(a, strconv.Itoa(port))
		}
		e.list = append(e.list, &endpoint{addr: a})
	}
	return e
}

// pick returns the best endpoint that is not cooling down, or the one whose
// cooldown ends first when all of them are.
func (e *endpoints) pick() *endpoint {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	var soonest *endpoint
	for _, ep := range e.list {
		if now.After(ep.failUntil) {
			return ep
		}
		if soonest == nil || ep.failUntil.Before(soonest.failUntil) {
			soonest = ep
		}
	}
	return soonest
}

func (e *endpoints) report(ep *endpoint, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		ep.failures = 0
		ep.failUntil = time.Time{}
		return
	}
	ep.failures++
	cool := time.Duration(1<<min(ep.failures, 6)) * 5 * time.Second // 10s .. 5m20s
	ep.failUntil = time.Now().Add(cool)
}

// measure times a few TCP connects to every endpoint and re-sorts the list.
// It only runs when there is more than one endpoint to choose from.
func (e *endpoints) measure(ctx context.Context) {
	e.mu.Lock()
	list := append([]*endpoint(nil), e.list...)
	e.mu.Unlock()
	if len(list) < 2 {
		return
	}
	rtts := make([]time.Duration, len(list))
	var wg sync.WaitGroup
	for i, ep := range list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			best := time.Duration(1<<63 - 1)
			for range 3 {
				var d net.Dialer
				cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				start := time.Now()
				c, err := d.DialContext(cctx, "tcp", ep.addr)
				cancel()
				if err == nil {
					best = min(best, time.Since(start))
					c.Close()
				}
				time.Sleep(time.Duration(100+rand.IntN(400)) * time.Millisecond)
			}
			rtts[i] = best
		}()
	}
	wg.Wait()
	e.mu.Lock()
	for i, ep := range list {
		ep.rtt = rtts[i]
	}
	sort.SliceStable(e.list, func(i, j int) bool { return e.list[i].rtt < e.list[j].rtt })
	e.measured = time.Now()
	e.mu.Unlock()
}

func (e *endpoints) summary() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := ""
	for i, ep := range e.list {
		if i == 3 {
			s += " ..."
			break
		}
		rtt := "timeout"
		if ep.rtt < time.Minute {
			rtt = ep.rtt.Round(time.Millisecond).String()
		}
		s += fmt.Sprintf(" %s=%s", ep.addr, rtt)
	}
	return s
}

// dialer opens TLS connections that look like Chrome and turns them into tunnels.
type dialer struct {
	cfg   *Config
	key   door.Key
	eps   *endpoints
	roots *x509.CertPool
}

func newDialer(cfg *Config, key door.Key) (*dialer, error) {
	d := &dialer{cfg: cfg, key: key, eps: newEndpoints(cfg.Endpoints, cfg.Server, cfg.Port)}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		d.roots = x509.NewCertPool()
		if !d.roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file has no certificates")
		}
	}
	return d, nil
}

// tlsConn connects to the best endpoint with Chrome's ClientHello. Chrome
// opens WebSocket connections offering only http/1.1, and page loads offering
// h2 and http/1.1, so forWebSocket picks which of the two this connection is.
func (d *dialer) tlsConn(ctx context.Context, forWebSocket bool) (net.Conn, error) {
	ep := d.eps.pick()
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", ep.addr)
	if err != nil {
		d.eps.report(ep, err)
		return nil, err
	}
	uc := utls.UClient(raw, &utls.Config{
		ServerName:         d.cfg.Server,
		RootCAs:            d.roots,
		InsecureSkipVerify: d.cfg.Insecure,
	}, utls.HelloChrome_Auto)
	if forWebSocket {
		if err := uc.BuildHandshakeState(); err != nil {
			raw.Close()
			return nil, err
		}
		for _, ext := range uc.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
				break
			}
		}
		if err := uc.BuildHandshakeState(); err != nil {
			raw.Close()
			return nil, err
		}
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		d.eps.report(ep, err)
		return nil, err
	}
	d.eps.report(ep, nil)
	return uc, nil
}

func (d *dialer) origin() string {
	if d.cfg.Port == 443 {
		return "https://" + d.cfg.Server
	}
	return "https://" + net.JoinHostPort(d.cfg.Server, strconv.Itoa(d.cfg.Port))
}

// tunnel is one WebSocket carrying a smux session.
type tunnel struct {
	sess     *smux.Session
	conn     *wire.Conn
	born     time.Time
	maxAge   time.Duration
	draining bool
	idleFrom time.Time // when the stream count last dropped to zero
	nextPing time.Time
}

func (d *dialer) tunnel(ctx context.Context) (*tunnel, error) {
	token, nonce := door.Token(d.key, time.Now())
	c2s, s2c, err := wire.SessionKeys(d.key[:], nonce)
	if err != nil {
		return nil, err
	}
	wd := websocket.Dialer{
		NetDialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.tlsConn(ctx, true)
		},
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   64 * 1024,
		WriteBufferSize:  64 * 1024,
	}
	u := "wss" + d.origin()[len("https"):] + d.cfg.Door + token
	h := http.Header{}
	h.Set("User-Agent", userAgent)
	h.Set("Origin", d.origin())
	h.Set("Pragma", "no-cache")
	h.Set("Cache-Control", "no-cache")
	h.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	ws, resp, err := wd.DialContext(ctx, u, h)
	if err != nil {
		if resp != nil {
			if resp.StatusCode >= 500 {
				return nil, fmt.Errorf("site unavailable (HTTP %d)", resp.StatusCode)
			}
			// The door did not open: the decoy answered instead.
			return nil, fmt.Errorf("door refused (HTTP %d): check key, door path and clock", resp.StatusCode)
		}
		return nil, err
	}
	conn, err := wire.New(ws, c2s, s2c, 150*time.Second)
	if err != nil {
		ws.Close()
		return nil, err
	}
	sess, err := smux.Client(conn, proto.SmuxConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}
	now := time.Now()
	return &tunnel{
		sess:     sess,
		conn:     conn,
		born:     now,
		maxAge:   time.Duration(20+rand.IntN(25)) * time.Minute,
		idleFrom: now,
		nextPing: now.Add(pingDelay()),
	}, nil
}

// pingDelay is irregular on purpose; Cloudflare drops WebSockets that stay
// silent for 100 seconds.
func pingDelay() time.Duration {
	return time.Duration(20+rand.IntN(45)) * time.Second
}
