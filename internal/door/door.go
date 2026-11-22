// Package door mints and checks the one-time path segment that opens a tunnel.
//
// A token is hex(nonce || mac): 56 hex characters, the same shape as a SHA-224
// file name, so a door request reads like a request for some stored object.
// The MAC binds the token to a two-minute time window; each nonce is accepted
// once, so a token copied from a log is useless.
package door

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	// Window is the lifetime granularity of a token, in seconds. A token is
	// accepted in its own window and the windows on either side, which
	// tolerates a couple of minutes of clock skew.
	Window = 120

	NonceLen = 12
	macLen   = 16
	TokenLen = 2 * (NonceLen + macLen)
)

// Key is a user's shared secret.
type Key [32]byte

func NewKey() Key {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return k
}

func ParseKey(s string) (Key, error) {
	var k Key
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == len(k) {
			copy(k[:], b)
			return k, nil
		}
	}
	return k, errors.New("key must be 32 bytes in base64")
}

func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func window(t time.Time) uint64 {
	return uint64(t.Unix()) / Window
}

func mac(k Key, w uint64, nonce []byte) []byte {
	h := hmac.New(sha256.New, k[:])
	h.Write([]byte("sallyport door v1"))
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], w)
	h.Write(wb[:])
	h.Write(nonce)
	return h.Sum(nil)[:macLen]
}

// Token returns a fresh token for k and the nonce inside it.
func Token(k Key, now time.Time) (string, []byte) {
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	raw := append(nonce, mac(k, window(now), nonce)...)
	return hex.EncodeToString(raw), nonce
}

// Verifier checks tokens and remembers the nonces it has accepted.
type Verifier struct {
	mu        sync.Mutex
	seen      map[[NonceLen]byte]time.Time
	nextSweep time.Time
}

func NewVerifier() *Verifier {
	return &Verifier{seen: make(map[[NonceLen]byte]time.Time)}
}

// Check returns the index in keys of the key that minted token and the token's
// nonce, or -1 when the token is malformed, expired, forged or replayed.
func (v *Verifier) Check(keys []Key, token string, now time.Time) (int, []byte) {
	if len(token) != TokenLen {
		return -1, nil
	}
	raw, err := hex.DecodeString(token)
	if err != nil {
		return -1, nil
	}
	nonce, got := raw[:NonceLen], raw[NonceLen:]
	w := window(now)
	match := -1
	for i, k := range keys {
		for _, cw := range [...]uint64{w, w - 1, w + 1} {
			if hmac.Equal(got, mac(k, cw, nonce)) {
				match = i
				break
			}
		}
		if match >= 0 {
			break
		}
	}
	if match < 0 {
		return -1, nil
	}

	var id [NonceLen]byte
	copy(id[:], nonce)
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.After(v.nextSweep) {
		for n, exp := range v.seen {
			if now.After(exp) {
				delete(v.seen, n)
			}
		}
		v.nextSweep = now.Add(time.Minute)
	}
	if _, dup := v.seen[id]; dup {
		return -1, nil
	}
	// Outlive every window the token could still be accepted in.
	v.seen[id] = now.Add(4 * Window * time.Second)
	return match, nonce
}
