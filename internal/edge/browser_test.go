package edge

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
)

// Real browsers (Chromium, Firefox, WebKit) use SSE, a streamed fetch and
// WebSockets through one edge (web/admin/edge-streams/streams.spec.ts). Browsers
// differ from hand-written clients: EventSource reconnects with
// Last-Event-ID, WebSocket frames are masked, and Origin is always sent.
// Needs Playwright browsers: run with BROWSER_SMOKE=1 (scripts/ci/ui.sh).
func TestBrowserStreams(t *testing.T) {
	if os.Getenv("BROWSER_SMOKE") == "" {
		t.Skip("set BROWSER_SMOKE=1 with Playwright browsers installed")
	}
	page, err := os.ReadFile("testdata/browser/index.html")
	if err != nil {
		t.Fatal(err)
	}
	// The browser connects directly, so its peer address is the client.
	h := newHarness(t, map[string]string{"CLIENT_IP_SOURCE": "remote_addr"})
	h.load(envelope(testConfig(1)))
	next := make(chan struct{}, 1)
	h.appHandler = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(page)
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			if id := r.Header.Get("Last-Event-ID"); id != "" {
				_, _ = fmt.Fprintf(w, "data: resumed after %s\n\n", id)
				http.NewResponseController(w).Flush()
				<-r.Context().Done()
				return
			}
			// Reports how the edge counted this request, then ends so the
			// browser reconnects quickly.
			_, _ = fmt.Fprintf(w, "retry: 50\nid: 1\ndata: streams=%d inflight=%d\n\n", h.srv.m.streams.Load(), h.srv.m.inflight.Load())
		case "/ndjson":
			w.Header().Set("Content-Type", "application/x-ndjson")
			_, _ = io.WriteString(w, `{"n":1}`+"\n")
			http.NewResponseController(w).Flush()
			<-next
			_, _ = io.WriteString(w, `{"n":2}`+"\n")
		case "/next":
			next <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
		case "/ws":
			browserEcho(w, r)
		default:
			http.NotFound(w, r)
		}
	}

	cmd := exec.Command("npx", "playwright", "test", "-c", "playwright.browser.config.ts")
	cmd.Dir = "../../web/admin"
	cmd.Env = append(os.Environ(), "BASE_URL="+h.front.URL)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("playwright: %v", err)
	}
	// Every stream a browser opened was released when it closed.
	waitFor(t, func() bool { return h.srv.m.streams.Load() == 0 })
}

// browserEcho answers a browser WebSocket: it accepts the "chat"
// subprotocol and echoes each text message with the Origin it saw.
func browserEcho(w http.ResponseWriter, r *http.Request) {
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(sum[:]))
	w.Header().Set("Sec-WebSocket-Protocol", "chat")
	w.WriteHeader(http.StatusSwitchingProtocols)
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		msg, err := readMasked(brw.Reader)
		if err != nil {
			return
		}
		reply := []byte(msg + " origin=" + r.Header.Get("Origin"))
		_, _ = conn.Write(append([]byte{0x81, byte(len(reply))}, reply...)) // FIN, text, short length
	}
}

// readMasked reads one short client frame (RFC 6455 §5.2). A close frame
// or anything longer than 125 bytes ends the echo.
func readMasked(br *bufio.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return "", err
	}
	n := int(hdr[1] & 0x7f)
	if hdr[0]&0x0f == 0x8 || n > 125 {
		return "", errors.New("close or long frame")
	}
	var mask [4]byte
	p := make([]byte, n)
	if _, err := io.ReadFull(br, mask[:]); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(br, p); err != nil {
		return "", err
	}
	for i := range p {
		p[i] ^= mask[i%4]
	}
	return string(p), nil
}
