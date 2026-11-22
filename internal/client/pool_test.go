package client

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/smux"

	"github.com/RHCloud1/sallyport/internal/door"
	"github.com/RHCloud1/sallyport/internal/proto"
	"github.com/RHCloud1/sallyport/internal/server"
)

// stack runs a decoy, the real server front and a TCP echo service, and
// returns a pool pointed at the front plus the echo address.
func stack(t *testing.T) (*pool, string) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "decoy")
	}))
	t.Cleanup(decoy.Close)

	key := door.NewKey()
	path := filepath.Join(t.TempDir(), "server.json")
	b, _ := json.Marshal(server.Config{
		Decoy:        decoy.URL,
		AllowPrivate: true,
		Users:        []server.User{{Name: "t", Key: key.String()}},
	})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(path)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTLSServer(srv)
	t.Cleanup(front.Close)

	cfg := &Config{
		Server:    "drive.test",
		Port:      443,
		Door:      server.DefaultDoor,
		Endpoints: []string{front.Listener.Addr().String()},
		Insecure:  true,
	}
	d, err := newDialer(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	return newPool(d, 2), echo.Addr().String()
}

func roundTrip(t *testing.T, p *pool, target string) *smux.Stream {
	t.Helper()
	s, err := p.open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	head, _ := proto.AppendAddr(nil, target)
	if _, err := s.Write(append(head, "ping"...)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(s, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo: %q %v", got, err)
	}
	return s
}

func (p *pool) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tunnels)
}

// settle waits for closed streams to leave the session's books.
func settle(t *testing.T, p *pool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		busy := 0
		p.mu.Lock()
		for _, tn := range p.tunnels {
			busy += tn.sess.NumStreams()
		}
		p.mu.Unlock()
		if busy == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("streams did not close")
}

func TestPoolLifecycle(t *testing.T) {
	p, target := stack(t)

	roundTrip(t, p, target).Close()
	if n := p.count(); n != 1 {
		t.Fatalf("after one stream: %d tunnels", n)
	}
	settle(t, p)
	now := time.Now()
	p.tick(now.Add(warmFor / 2))
	if n := p.count(); n != 1 {
		t.Fatalf("within the warm period: %d tunnels, want 1", n)
	}

	// Enough concurrent streams to need a second tunnel.
	var mu sync.Mutex
	var streams []*smux.Stream
	var wg sync.WaitGroup
	for range streamsPerTunnel + 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := roundTrip(t, p, target)
			mu.Lock()
			streams = append(streams, s)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if n := p.count(); n != 2 {
		t.Fatalf("under load: %d tunnels, want 2", n)
	}
	for _, s := range streams {
		s.Close()
	}
	settle(t, p)
	now = time.Now()
	p.tick(now)
	p.tick(now.Add(spareIdle + time.Second))
	if n := p.count(); n != 1 {
		t.Fatalf("spare not retired: %d tunnels", n)
	}

	// An old tunnel is drained and replaced.
	p.mu.Lock()
	old := p.tunnels[0]
	old.born = now.Add(-time.Hour)
	p.mu.Unlock()
	p.tick(time.Now())
	if !old.sess.IsClosed() {
		t.Fatal("expired, empty tunnel still open")
	}
	roundTrip(t, p, target).Close()
	if n := p.count(); n != 1 {
		t.Fatalf("after replacement: %d tunnels", n)
	}

	settle(t, p)
	p.tick(time.Now())
	p.tick(time.Now().Add(warmFor + time.Second))
	if n := p.count(); n != 0 {
		t.Fatalf("after the warm period: %d tunnels, want 0", n)
	}
}
