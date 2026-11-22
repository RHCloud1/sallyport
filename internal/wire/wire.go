// Package wire turns a WebSocket into an encrypted, padded byte stream.
//
// Every binary message is one AEAD record: seal(len16 || data || padding).
// Nonces are per-direction counters, so records cannot be replayed, dropped or
// reordered without the connection failing. Small records are padded to a
// random size so short control writes and inner TLS handshakes do not show up
// as recognisable message lengths.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// MaxChunk is the largest payload carried by a single record.
	MaxChunk = 32 * 1024
	// MaxMessage bounds an incoming message; anything larger is a protocol error.
	MaxMessage = MaxChunk + 2 + padCeiling + 64

	padCeiling = 1400
)

var errBadRecord = errors.New("wire: bad record")

// SessionKeys derives the client-to-server and server-to-client keys of one
// tunnel from the user's key and the door nonce.
func SessionKeys(secret, nonce []byte) (c2s, s2c []byte, err error) {
	if c2s, err = hkdf.Key(sha256.New, secret, nonce, "sallyport c2s", 32); err != nil {
		return nil, nil, err
	}
	if s2c, err = hkdf.Key(sha256.New, secret, nonce, "sallyport s2c", 32); err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

// Conn is an io.ReadWriteCloser over a WebSocket. One goroutine may Read and
// one may Write at a time; Ping and Close may be called from anywhere.
type Conn struct {
	ws      *websocket.Conn
	seal    cipher.AEAD
	open    cipher.AEAD
	sendCtr uint64
	recvCtr uint64
	nonce   [12]byte
	rnonce  [12]byte
	rbuf    []byte
	wbuf    []byte
	idle    time.Duration

	wmu sync.Mutex
}

// New wraps ws. If idle is non-zero the connection fails when nothing,
// including pings and pongs, arrives for that long.
func New(ws *websocket.Conn, sendKey, recvKey []byte, idle time.Duration) (*Conn, error) {
	seal, err := newAEAD(sendKey)
	if err != nil {
		return nil, err
	}
	open, err := newAEAD(recvKey)
	if err != nil {
		return nil, err
	}
	c := &Conn{ws: ws, seal: seal, open: open, idle: idle}
	ws.SetReadLimit(MaxMessage)
	ws.SetPingHandler(func(data string) error {
		c.touch()
		err := ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(10*time.Second))
		if errors.Is(err, websocket.ErrCloseSent) {
			return nil
		}
		return err
	})
	ws.SetPongHandler(func(string) error {
		c.touch()
		return nil
	})
	return c, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *Conn) touch() {
	if c.idle > 0 {
		_ = c.ws.SetReadDeadline(time.Now().Add(c.idle))
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		c.touch()
		mt, msg, err := c.ws.ReadMessage()
		if err != nil {
			return 0, err
		}
		if mt != websocket.BinaryMessage || len(msg) < c.open.Overhead()+2 {
			return 0, errBadRecord
		}
		binary.BigEndian.PutUint64(c.rnonce[4:], c.recvCtr)
		plain, err := c.open.Open(msg[:0], c.rnonce[:], msg, nil)
		if err != nil {
			return 0, errBadRecord
		}
		c.recvCtr++
		n := int(binary.BigEndian.Uint16(plain))
		if n > len(plain)-2 {
			return 0, errBadRecord
		}
		c.rbuf = plain[2 : 2+n]
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxChunk {
			chunk = chunk[:MaxChunk]
		}
		if err := c.writeRecord(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *Conn) writeRecord(data []byte) error {
	size := 2 + len(data) + randPad(len(data))
	if cap(c.wbuf) < size+c.seal.Overhead() {
		c.wbuf = make([]byte, 0, MaxMessage)
	}
	buf := c.wbuf[:size]
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	copy(buf[2:], data)
	clear(buf[2+len(data):])
	binary.BigEndian.PutUint64(c.nonce[4:], c.sendCtr)
	c.sendCtr++
	return c.ws.WriteMessage(websocket.BinaryMessage, c.seal.Seal(buf[:0], c.nonce[:], buf, nil))
}

// randPad spreads records shorter than padCeiling uniformly over
// [n, padCeiling]; larger ones already look like bulk data and are left alone.
func randPad(n int) int {
	if n >= padCeiling {
		return 0
	}
	return rand.IntN(padCeiling - n + 1)
}

// Ping sends a WebSocket ping, which keeps proxies from timing out an idle
// connection and lets the peer's idle timer see that we are alive.
func (c *Conn) Ping() error {
	return c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
}

func (c *Conn) Close() error {
	_ = c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	return c.ws.Close()
}
