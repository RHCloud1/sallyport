package client

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

const (
	// streamsPerTunnel is how busy a tunnel gets before another is opened.
	streamsPerTunnel = 24
	// spareIdle is how long an extra, empty tunnel is kept.
	spareIdle = 90 * time.Second
	// warmFor is how long the last tunnel stays open after the last stream.
	warmFor = 10 * time.Minute
	// coldAfter is the pause after which the next tunnel is preceded by the
	// drive page being opened again.
	coldAfter = 30 * time.Minute
)

var errUnavailable = errors.New("tunnel unavailable, retrying shortly")

// pool keeps a few tunnels open, spreads streams across them, and retires
// them: old ones drain and close, idle ones close, and the last one stays
// warm for a while so the next request does not wait for a handshake.
type pool struct {
	d   *dialer
	max int

	mu        sync.Mutex
	tunnels   []*tunnel
	dialing   chan struct{}
	failedAt  time.Time
	backoff   time.Duration
	lastEmpty time.Time // when the pool last had no tunnels
	warmed    bool      // prelude done for the current period of use
}

func newPool(d *dialer, max int) *pool {
	return &pool{d: d, max: max, lastEmpty: time.Now()}
}

// open returns a new stream, dialing a tunnel if needed.
func (p *pool) open(ctx context.Context) (*smux.Stream, error) {
	for range 3 {
		t, err := p.pick(ctx)
		if err != nil {
			return nil, err
		}
		s, err := t.sess.OpenStream()
		if err == nil {
			return s, nil
		}
		p.drop(t)
	}
	return nil, errUnavailable
}

func (p *pool) pick(ctx context.Context) (*tunnel, error) {
	for {
		p.mu.Lock()
		p.pruneLocked()
		var best *tunnel
		active := 0
		for _, t := range p.tunnels {
			if t.draining {
				continue
			}
			active++
			if best == nil || t.sess.NumStreams() < best.sess.NumStreams() {
				best = t
			}
		}
		if best != nil && (best.sess.NumStreams() < streamsPerTunnel || active >= p.max || p.dialing != nil) {
			p.mu.Unlock()
			return best, nil
		}
		if wait := p.dialing; wait != nil {
			p.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if wait := p.backoff - time.Since(p.failedAt); wait > 0 {
			p.mu.Unlock()
			if best != nil {
				return best, nil
			}
			// Hold the request until the next attempt rather than failing
			// it; applications see a slow connect instead of an error.
			if wait > 10*time.Second {
				return nil, errUnavailable
			}
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		p.dialing = done
		cold := !p.warmed
		p.mu.Unlock()

		t, err := p.dial(ctx, cold)

		p.mu.Lock()
		p.dialing = nil
		close(done)
		if err != nil {
			p.failedAt = time.Now()
			p.backoff = min(max(2*p.backoff, time.Second), 30*time.Second)
			p.mu.Unlock()
			log.Printf("tunnel: %v", err)
			if best != nil {
				return best, nil
			}
			return nil, errUnavailable
		}
		p.backoff = 0
		p.warmed = true
		p.tunnels = append(p.tunnels, t)
		n := len(p.tunnels)
		p.mu.Unlock()
		log.Printf("tunnel up (%d open)", n)
		return t, nil
	}
}

func (p *pool) dial(ctx context.Context, cold bool) (*tunnel, error) {
	// A dial outlives the request that triggered it so that other waiting
	// requests can use the tunnel.
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	if cold {
		p.d.prelude(dctx)
	}
	return p.d.tunnel(dctx)
}

func (p *pool) drop(t *tunnel) {
	p.mu.Lock()
	t.draining = true
	p.mu.Unlock()
	t.sess.Close()
}

// pruneLocked removes closed tunnels.
func (p *pool) pruneLocked() {
	had := len(p.tunnels) > 0
	kept := p.tunnels[:0]
	for _, t := range p.tunnels {
		if !t.sess.IsClosed() {
			kept = append(kept, t)
		}
	}
	clear(p.tunnels[len(kept):])
	p.tunnels = kept
	if had && len(kept) == 0 {
		p.lastEmpty = time.Now()
	}
}

// maintain runs until ctx ends, retiring tunnels and pinging the rest.
func (p *pool) maintain(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			p.mu.Lock()
			for _, t := range p.tunnels {
				t.sess.Close()
			}
			p.mu.Unlock()
			return
		case <-tick.C:
		}
		p.tick(time.Now())
	}
}

func (p *pool) tick(now time.Time) {
	var closing, pinging []*tunnel
	p.mu.Lock()
	p.pruneLocked()
	hadTunnels := len(p.tunnels) > 0
	busy := 0
	for _, t := range p.tunnels {
		if t.sess.NumStreams() > 0 {
			busy++
			t.idleFrom = now
		}
	}
	kept := p.tunnels[:0]
	for _, t := range p.tunnels {
		n := t.sess.NumStreams()
		idle := now.Sub(t.idleFrom)
		if now.Sub(t.born) > t.maxAge {
			t.draining = true // takes no new streams; closes once empty
		}
		spare := len(kept) > 0 || busy > 0
		retire := n == 0 && (t.draining || spare && idle > spareIdle || idle > warmFor)
		if retire {
			closing = append(closing, t)
			continue
		}
		kept = append(kept, t)
		if now.After(t.nextPing) {
			t.nextPing = now.Add(pingDelay())
			pinging = append(pinging, t)
		}
	}
	clear(p.tunnels[len(kept):])
	p.tunnels = kept
	if hadTunnels && len(p.tunnels) == 0 {
		p.lastEmpty = now
	}
	if len(p.tunnels) == 0 && now.Sub(p.lastEmpty) > coldAfter {
		p.warmed = false
	}
	p.mu.Unlock()

	for _, t := range closing {
		t.sess.Close()
	}
	for _, t := range pinging {
		if err := t.conn.Ping(); err != nil {
			t.sess.Close()
		}
	}
}
