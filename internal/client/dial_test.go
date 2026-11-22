package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/RHCloud1/sallyport/internal/door"
)

// TestALPNMatchesChrome checks the two ClientHello flavours: Chrome offers
// only http/1.1 on a WebSocket connection and h2 first on a page load.
func TestALPNMatchesChrome(t *testing.T) {
	offered := make(chan []string, 1)
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			offered <- h.SupportedProtos
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	cfg := &Config{Server: "drive.test", Endpoints: []string{net.JoinHostPort(host, port)}, Insecure: true}
	d, err := newDialer(cfg, door.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ws   bool
		want []string
	}{
		{true, []string{"http/1.1"}},
		{false, []string{"h2", "http/1.1"}},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := d.tlsConn(ctx, tc.ws)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if got := <-offered; !slices.Equal(got, tc.want) {
			t.Errorf("websocket=%v: ALPN %q, want %q", tc.ws, got, tc.want)
		}
	}
}

func TestEndpointsSkipFailures(t *testing.T) {
	e := newEndpoints([]string{"192.0.2.1", "192.0.2.2:8443"}, "drive.test", 443)
	if e.list[0].addr != "192.0.2.1:443" || e.list[1].addr != "192.0.2.2:8443" {
		t.Fatalf("addresses: %s, %s", e.list[0].addr, e.list[1].addr)
	}
	first := e.pick()
	e.report(first, net.ErrClosed)
	if e.pick() == first {
		t.Fatal("failed endpoint picked again during its cooldown")
	}
	e.report(e.list[1], net.ErrClosed)
	if e.pick() != first {
		t.Fatal("with all endpoints cooling down, the one that recovers first should be picked")
	}
}
