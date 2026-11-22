package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RHCloud1/sallyport/internal/door"
)

// front starts the server handler in front of a decoy that answers every
// request with "decoy" and returns the front's URL.
func front(t *testing.T, key door.Key, proxy bool) (*Server, string) {
	t.Helper()
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "filebrowser")
		io.WriteString(w, "decoy")
	}))
	t.Cleanup(decoy.Close)
	cfg := Config{
		Listen: "127.0.0.1:0",
		Decoy:  decoy.URL,
		Proxy:  &proxy,
		Users:  []User{{Name: "alice", Key: key.String()}},
	}
	path := filepath.Join(t.TempDir(), "server.json")
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return s, ts.URL
}

func upgrade(t *testing.T, url string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return resp.StatusCode, "", resp.Header
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

func TestProbesSeeOnlyTheDecoy(t *testing.T) {
	key := door.NewKey()
	_, base := front(t, key, true)
	stranger, _ := door.Token(door.NewKey(), time.Now())

	cases := map[string]string{
		"site root":            base + "/",
		"door prefix":          base + DefaultDoor,
		"short token":          base + DefaultDoor + "abc",
		"token from other key": base + DefaultDoor + stranger,
	}
	for name, url := range cases {
		code, body, h := upgrade(t, url)
		if code != http.StatusOK || body != "decoy" {
			t.Errorf("%s: got %d %q, want the decoy", name, code, body)
		}
		if got := h.Values("Server"); len(got) != 1 || got[0] != "Caddy" {
			t.Errorf("%s: Server header %q", name, got)
		}
	}

	// A valid token without the upgrade is an ordinary request.
	tok, _ := door.Token(key, time.Now())
	resp, err := http.Get(base + DefaultDoor + tok)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "decoy" {
		t.Errorf("plain GET of a valid token: %q", body)
	}
}

func TestDoorOpensOnceAndObeysTheSwitch(t *testing.T) {
	key := door.NewKey()
	_, base := front(t, key, true)
	tok, _ := door.Token(key, time.Now())
	if code, _, _ := upgrade(t, base+DefaultDoor+tok); code != http.StatusSwitchingProtocols {
		t.Fatalf("valid token: HTTP %d, want 101", code)
	}
	if code, body, _ := upgrade(t, base+DefaultDoor+tok); code != http.StatusOK || body != "decoy" {
		t.Fatalf("replayed token: %d %q, want the decoy", code, body)
	}

	_, off := front(t, key, false)
	tok, _ = door.Token(key, time.Now())
	if code, body, _ := upgrade(t, off+DefaultDoor+tok); body != "decoy" {
		t.Fatalf("proxy off: %d %q, want the decoy", code, body)
	}
}
