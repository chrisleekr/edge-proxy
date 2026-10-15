package main

import (
	"bufio"
	"bytes"
	"testing"
)

// The handshake answer from RFC 6455 §1.3's worked example.
func TestWebSocketAccept(t *testing.T) {
	if got := wsAccept("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("got %s", got)
	}
}

// A masked client frame reads back as the payload that was sent.
func TestMaskedFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := writeFrame(&b, 1, []byte("ping"), true); err != nil {
		t.Fatal(err)
	}
	op, p, err := readFrame(bufio.NewReader(&b))
	if err != nil || op != 1 || string(p) != "ping" {
		t.Fatalf("op %d payload %q err %v", op, p, err)
	}
}
