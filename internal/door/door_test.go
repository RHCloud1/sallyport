package door

import (
	"strings"
	"testing"
	"time"
)

func TestTokenRoundTrip(t *testing.T) {
	a, b := NewKey(), NewKey()
	keys := []Key{a, b}
	now := time.Now()
	v := NewVerifier()

	tok, nonce := Token(b, now)
	if len(tok) != TokenLen || strings.Trim(tok, "0123456789abcdef") != "" {
		t.Fatalf("token %q is not %d hex chars", tok, TokenLen)
	}
	i, got := v.Check(keys, tok, now)
	if i != 1 || string(got) != string(nonce) {
		t.Fatalf("Check = %d, want 1", i)
	}
	if i, _ := v.Check(keys, tok, now); i != -1 {
		t.Fatal("replayed token was accepted")
	}
}

func TestTokenRejects(t *testing.T) {
	k := NewKey()
	now := time.Now()
	v := NewVerifier()

	tok, _ := Token(k, now)
	if i, _ := v.Check([]Key{NewKey()}, tok, now); i != -1 {
		t.Error("token accepted under the wrong key")
	}
	if i, _ := v.Check([]Key{k}, tok, now.Add(3*Window*time.Second)); i != -1 {
		t.Error("expired token accepted")
	}
	flipped := []byte(tok)
	flipped[len(flipped)-1] ^= 1
	if i, _ := v.Check([]Key{k}, string(flipped), now); i != -1 {
		t.Error("forged token accepted")
	}
	for _, bad := range []string{"", "abc", strings.Repeat("z", TokenLen)} {
		if i, _ := v.Check([]Key{k}, bad, now); i != -1 {
			t.Errorf("malformed token %q accepted", bad)
		}
	}
	// Clock skew of one window either way is fine.
	tok, _ = Token(k, now.Add(-Window*time.Second))
	if i, _ := v.Check([]Key{k}, tok, now); i != 0 {
		t.Error("token from the previous window rejected")
	}
}

func TestParseKey(t *testing.T) {
	k := NewKey()
	got, err := ParseKey(" " + k.String() + "\n")
	if err != nil || got != k {
		t.Fatalf("ParseKey(String()) = %v, %v", got, err)
	}
	if _, err := ParseKey("c2hvcnQ="); err == nil {
		t.Error("short key accepted")
	}
}
