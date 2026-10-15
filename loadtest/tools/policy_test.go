package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// The seeded policy must pass the one validator, or the load environment
// fails at seed time with a less direct error.
func TestPolicyCompiles(t *testing.T) {
	var p struct {
		Config snapshot.Config `json:"config"`
		Tests  json.RawMessage `json:"tests"`
	}
	dec := json.NewDecoder(bytes.NewReader(policy))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatal(err)
	}
	p.Config.Version = 1
	if _, warns, errs := snapshot.Compile(&p.Config, snapshot.Deployment{Upstreams: []string{"app"}}); errs != nil || warns != nil {
		t.Fatalf("errors %v, warnings %v", errs, warns)
	}
}
