// Package proto holds what both ends agree on inside a tunnel: the target
// address that opens each stream, the multiplexer settings, and the relay loop.
package proto

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// AppendAddr appends the stream header for hostport ("host:port").
func AppendAddr(b []byte, hostport string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, errors.New("bad port")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b = append(b, atypIPv4)
		} else {
			b = append(b, atypIPv6)
		}
		b = append(b, ip.AsSlice()...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("bad host")
		}
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// ReadAddr reads a stream header and returns "host:port".
func ReadAddr(r io.Reader) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	var host string
	switch t[0] {
	case atypIPv4, atypIPv6:
		n := 4
		if t[0] == atypIPv6 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		ip, _ := netip.AddrFromSlice(b)
		host = ip.String()
	case atypDomain:
		if _, err := io.ReadFull(r, t[:]); err != nil {
			return "", err
		}
		b := make([]byte, t[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("bad address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

// SmuxConfig is shared by both ends. Keep-alives are off: the WebSocket layer
// pings at irregular intervals instead of smux's fixed ten-second beat. The
// per-stream window is large because every round trip goes through a CDN.
func SmuxConfig() *smux.Config {
	return &smux.Config{
		Version:           2,
		KeepAliveDisabled: true,
		MaxFrameSize:      16 * 1024,
		MaxReceiveBuffer:  16 * 1024 * 1024,
		MaxStreamBuffer:   4 * 1024 * 1024,
	}
}

type closeWriter interface {
	CloseWrite() error
}

// Relay copies both ways until both directions finish. Once one direction
// ends the other gets lingerTime to drain, after which both are closed.
func Relay(a, b io.ReadWriteCloser, lingerTime time.Duration) (ab, ba int64) {
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() {
		a.Close()
		b.Close()
	}
	copyHalf := func(dst io.ReadWriteCloser, src io.Reader, n *int64) {
		*n, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			once.Do(closeBoth)
		}
		done <- struct{}{}
	}
	go copyHalf(b, a, &ab)
	go copyHalf(a, b, &ba)
	<-done
	select {
	case <-done:
	case <-time.After(lingerTime):
		once.Do(closeBoth)
		<-done
	}
	once.Do(closeBoth)
	return ab, ba
}
