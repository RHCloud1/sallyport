package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// prelude does what the drive's web page does when it is opened: load the
// page, sign in and list the files. It runs before the first tunnel after
// start-up or a long pause, so a tunnel never appears out of nowhere. Every
// error is ignored; the decoy is a real application and answers normally.
func (d *dialer) prelude(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return d.tlsConn(ctx, false)
		},
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr}
	base := d.origin()

	get := func(path, accept, auth string) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return
		}
		browserHeaders(req, accept)
		if auth != "" {
			req.Header.Set("X-Auth", auth)
		}
		if resp, err := hc.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
		}
	}
	pause := func() {
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(200+rand.IntN(700)) * time.Millisecond):
		}
	}

	get("/", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "")
	if d.cfg.DriveUser == "" {
		return
	}
	pause()
	body, _ := json.Marshal(map[string]string{
		"username":  d.cfg.DriveUser,
		"password":  d.cfg.DrivePass,
		"recaptcha": "",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/login", bytes.NewReader(body))
	if err != nil {
		return
	}
	browserHeaders(req, "*/*")
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return
	}
	jwt, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	pause()
	get("/api/resources/", "*/*", strings.TrimSpace(string(jwt)))
}

func browserHeaders(req *http.Request, accept string) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Sec-Ch-Ua", `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
}
