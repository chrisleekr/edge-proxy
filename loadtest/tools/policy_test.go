package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// The seeded policies must pass the one validator, or the load and demo
// environments fail at seed time with a less direct error.
func TestPolicyCompiles(t *testing.T) {
	for name, b := range map[string][]byte{"load": policy, "demo": demoPolicy} {
		t.Run(name, func(t *testing.T) {
			var p struct {
				Config snapshot.Config `json:"config"`
				Tests  json.RawMessage `json:"tests"`
			}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil {
				t.Fatal(err)
			}
			p.Config.Version = 1
			if _, warns, errs := snapshot.Compile(&p.Config, snapshot.Deployment{}); errs != nil || warns != nil {
				t.Fatalf("errors %v, warnings %v", errs, warns)
			}
		})
	}
}
