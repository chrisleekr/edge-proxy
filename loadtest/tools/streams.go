package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 fixes SHA-1 for the handshake
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // RFC 6455 §4.2.2
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsEcho is the mock upstream's WebSocket echo (RFC 6455, text frames up to
// 125 bytes, which is all the stream test sends).
func wsEcho(w http.ResponseWriter, r *http.Request) {
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAccept(r.Header.Get("Sec-WebSocket-Key")))
	_ = rw.Flush()
	for {
		op, payload, err := readFrame(rw.Reader)
		if err != nil || op == 8 {
			return
		}
		if err := writeFrame(conn, op, payload, false); err != nil {
			return
		}
	}
}

func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[1] & 0x7f)
	if n > 125 {
		return 0, nil, errors.New("frame too long for this mock")
	}
	var mask [4]byte
	masked := h[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range p {
			p[i] ^= mask[i%4]
		}
	}
	return h[0] & 0x0f, p, nil
}

// writeFrame sends one final frame; clients must mask (RFC 6455 §5.3).
func writeFrame(w io.Writer, op byte, p []byte, mask bool) error {
	if len(p) > 125 {
		return errors.New("frame too long for this mock")
	}
	b := []byte{0x80 | op, byte(len(p) & 0x7f)}
	if mask {
		var k [4]byte
		_, _ = rand.Read(k[:])
		b[1] |= 0x80
		b = append(b, k[:]...)
		for i, c := range p {
			b = append(b, c^k[i%4])
		}
	} else {
		b = append(b, p...)
	}
	_, err := w.Write(b)
	return err
}

// streams holds SSE and WebSocket connections through the edges for a
// duration and reports how many opened, failed and ended
// early. It exits non-zero if more than 0.1% failed or ended early.
func streams(args []string) error {
	fs := flag.NewFlagSet("streams", flag.ContinueOnError)
	target := fs.String("url", "http://lb:8000", "edge or LB base URL")
	sse := fs.Int("sse", 5000, "SSE connections")
	ws := fs.Int("ws", 5000, "WebSocket connections")
	hold := fs.Duration("for", time.Hour, "how long to hold them")
	rate := fs.Int("rate", 500, "connections opened per second")
	if err := fs.Parse(args); err != nil {
		return err
	}
	u, err := url.Parse(*target)
	if err != nil {
		return err
	}
	var opened, failed, ended, messages atomic.Int64
	deadline := time.Now().Add(*hold)
	run := func(i int, isWS bool) {
		var err error
		if isWS {
			err = holdWS(u, i, deadline, &opened, &messages)
		} else {
			err = holdSSE(u, i, deadline, &opened, &messages)
		}
		switch {
		case err == nil:
		case errors.Is(err, errEnded):
			ended.Add(1)
		default:
			if failed.Add(1) <= 5 {
				log.Printf("stream %d failed: %v", i, err)
			}
		}
	}
	total := *sse + *ws
	done := make(chan struct{}, total)
	tick := time.NewTicker(time.Second / time.Duration(*rate))
	go func() {
		for i := range total {
			<-tick.C
			go func() { run(i, i >= *sse); done <- struct{}{} }()
		}
		tick.Stop()
	}()
	report := time.NewTicker(30 * time.Second)
	defer report.Stop()
	for finished := 0; finished < total; {
		select {
		case <-done:
			finished++
		case <-report.C:
			log.Printf("streams: open %d, failed %d, ended early %d, messages %d", opened.Load(), failed.Load(), ended.Load(), messages.Load())
		}
	}
	log.Printf("streams done: %d opened of %d, %d failed, %d ended early, %d messages", opened.Load(), total, failed.Load(), ended.Load(), messages.Load())
	if bad := failed.Load() + ended.Load(); bad*1000 > int64(total) {
		return fmt.Errorf("%d of %d streams failed or ended early", bad, total)
	}
	return nil
}

var errEnded = errors.New("stream ended before its time")

func streamHeaders(h http.Header, i int) {
	h.Set("Host", "api.example.com")
	h.Set("CloudFront-Viewer-Address", fmt.Sprintf("198.19.%d.%d:443", (i>>8)&255, i&255))
}

func holdSSE(u *url.URL, i int, deadline time.Time, opened, messages *atomic.Int64) error {
	req, _ := http.NewRequest(http.MethodGet, u.String()+"/sse", nil)
	streamHeaders(req.Header, i)
	// As EventSource sends it; the edge counts SSE against MAX_STREAMS by it.
	req.Header.Set("Accept", "text/event-stream")
	req.Host = "api.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sse status %d", resp.StatusCode)
	}
	opened.Add(1)
	go func() { time.Sleep(time.Until(deadline)); _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			messages.Add(1)
		}
	}
	if time.Now().Before(deadline) {
		return errEnded
	}
	return nil
}

func holdWS(u *url.URL, i int, deadline time.Time, opened, messages *atomic.Int64) error {
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	var k [16]byte
	_, _ = rand.Read(k[:])
	key := base64.StdEncoding.EncodeToString(k[:])
	req, _ := http.NewRequest(http.MethodGet, "http://api.example.com/ws", nil)
	streamHeaders(req.Header, i+40000)
	for h, v := range map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13"} {
		req.Header.Set(h, v)
	}
	if err := req.Write(conn); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close() // a 101 has no body; the connection carries frames
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return fmt.Errorf("ws handshake status %d", resp.StatusCode)
	}
	opened.Add(1)
	msg := make([]byte, 8)
	for time.Now().Before(deadline) {
		binary.BigEndian.PutUint64(msg, uint64(time.Now().UnixNano()))
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := writeFrame(conn, 1, msg, true); err != nil {
			return errEnded
		}
		if _, _, err := readFrame(br); err != nil {
			return errEnded
		}
		messages.Add(1)
		time.Sleep(min(10*time.Second, time.Until(deadline)))
	}
	_ = writeFrame(conn, 8, nil, true)
	return nil
}
