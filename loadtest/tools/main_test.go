package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A service that accepts the first probe but never answers it doesn't hang
// the smoke: the probe times out and retries until it gets 200.
func TestProbeRetriesAHungRequest(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			<-release
		}
	}))
	defer srv.Close()
	defer close(release)
	done := make(chan error, 1)
	go func() { done <- probe([]string{srv.URL}) }()
	select {
	case err := <-done:
		if err != nil || calls.Load() != 2 {
			t.Fatalf("probe: %v after %d calls", err, calls.Load())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("probe hung on an unanswered request")
	}
}
