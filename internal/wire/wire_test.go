package wire

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// pair returns the client and server ends of one WebSocket wrapped in Conns.
func pair(t *testing.T, clientKeys, serverKeys [2][]byte) (*Conn, *Conn) {
	t.Helper()
	ch := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		ch <- ws
	}))
	t.Cleanup(srv.Close)
	cws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(cws, clientKeys[0], clientKeys[1], time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(<-ch, serverKeys[0], serverKeys[1], time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func TestRoundTrip(t *testing.T) {
	c2s, s2c, err := SessionKeys(bytes.Repeat([]byte{7}, 32), []byte("nonce-nonce!"))
	if err != nil {
		t.Fatal(err)
	}
	c, s := pair(t, [2][]byte{c2s, s2c}, [2][]byte{s2c, c2s})

	for _, n := range []int{1, 100, padCeiling - 1, padCeiling, MaxChunk, 3*MaxChunk + 17} {
		msg := make([]byte, n)
		rand.Read(msg)
		go func() {
			if _, err := c.Write(msg); err != nil {
				t.Error(err)
			}
		}()
		got := make([]byte, n)
		if _, err := io.ReadFull(s, got); err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("%d bytes: payload mismatch", n)
		}
	}
}

func TestWrongKeyFails(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	c, s := pair(t, [2][]byte{k1, k1}, [2][]byte{k2, k2})
	go c.Write([]byte("hello"))
	if _, err := s.Read(make([]byte, 16)); err != errBadRecord {
		t.Fatalf("Read with the wrong key = %v, want errBadRecord", err)
	}
}

func TestSmallRecordsArePadded(t *testing.T) {
	sizes := map[int]bool{}
	for range 50 {
		sizes[randPad(10)] = true
	}
	if randPad(padCeiling) != 0 || randPad(MaxChunk) != 0 {
		t.Error("bulk records were padded")
	}
	if len(sizes) < 10 {
		t.Fatalf("padding hardly varies: %d distinct sizes in 50 records", len(sizes))
	}
}
