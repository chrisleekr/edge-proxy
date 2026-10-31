package main

// tools agent is a scripted autopilot runner for the load-full attacks: it
// claims cases from admin as the real runner does and answers each from a
// fixed plan, over admin's MCP, so the edge, admin's checks and the rule
// lifecycle run for real while no model is called.

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// autopilotPlan names the sensor for each load-full attack.
//
//go:embed autopilot-plan.json
var autopilotPlan []byte

// planSensor is one sensor the agent proposes on a sweep and enforces on its
// anomaly. Rules are as propose takes them.
type planSensor struct {
	Name string         `json:"name"`
	Rule map[string]any `json:"rule"`
	// Block is the rule enforce proposes. It narrows Rule: admin refuses
	// an enforce with the same expression and key as a live rule.
	Block map[string]any `json:"block"`
	TTL   string         `json:"ttl"`
	// FirstTry is an enforce rule proposed before Block, which admin is
	// expected to refuse, so a load test sees the refusal.
	FirstTry map[string]any `json:"first_try,omitempty"`
}

type plan struct {
	Sensors []planSensor `json:"sensors"`
}

// step is one MCP call.
type step struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

// live is what the run's reads answered so far.
type live struct {
	Sensors  map[string]string // plan sensor name to the id of its live rule
	Subjects []string          // the top subjects get_rule_stats named
	Evidence []int             // evidence ids of the run's stats reads
}

func readPlan(b []byte) (plan, error) {
	var p plan
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return plan{}, fmt.Errorf("autopilot plan: %w", err)
	}
	return p, nil
}

// sensorRule reads ap-<name>-<proposal id>, the id admin gives a rule.
var sensorRule = regexp.MustCompile(`^ap-([a-z0-9-]+)-\d+$`)

// steps is every call the agent makes for a case, given what its reads
// answered, and the verdict. It is pure: the run loop calls it again after
// each answer, and the calls already made stay first.
func (p plan) steps(kind string, brief map[string]any, l live) ([]step, string) {
	none := map[string]any{}
	getCase := step{"get_case", none}
	switch kind {
	case "sweep":
		out := []step{getCase, {"get_autopilot_state", none}}
		for _, s := range p.Sensors {
			if _, ok := l.Sensors[s.Name]; !ok {
				out = append(out, step{"propose", map[string]any{"action": "add_sensor", "name": s.Name, "rule": s.Rule,
					"rationale": "The load-test plan watches this route for its attack"}})
			}
		}
		return out, "benign"
	case "anomaly":
		rule, _ := brief["rule"].(string)
		m := sensorRule.FindStringSubmatch(rule)
		i := -1
		if m != nil {
			i = slices.IndexFunc(p.Sensors, func(s planSensor) bool { return s.Name == m[1] })
		}
		if i < 0 {
			break
		}
		s := p.Sensors[i]
		out := []step{getCase, {"get_autopilot_state", none}, {"get_rule_stats", map[string]any{"rule": rule}}, {"list_rules", none}}
		for _, sub := range l.Subjects {
			// check_subject takes an IP; a user id or an AS number is skipped.
			if _, err := netip.ParseAddr(sub); err == nil {
				out = append(out, step{"check_subject", map[string]any{"ip": sub}})
			}
		}
		enforce := func(r map[string]any) step {
			return step{"propose", map[string]any{"action": "enforce", "name": s.Name + "-block", "rule": r, "ttl": s.TTL, "cites": rule,
				"evidence": map[string]any{"evidence_ids": l.Evidence}, "rationale": "The sensor's anomaly is the load-test attack it watches"}}
		}
		if s.FirstTry != nil {
			out = append(out, enforce(s.FirstTry))
		}
		return append(out, enforce(s.Block)), "attack"
	}
	return []step{getCase}, "benign"
}

// absorb adds what a read answered to l.
func absorb(l *live, tool string, out map[string]any) {
	if id, ok := out["evidence_id"].(float64); ok {
		l.Evidence = append(l.Evidence, int(id))
	}
	switch tool {
	case "get_autopilot_state":
		rules, _ := out["rules"].([]any)
		l.Sensors = map[string]string{}
		for _, r := range rules {
			r, _ := r.(map[string]any)
			id, _ := r["id"].(string)
			state, _ := r["state"].(string)
			if m := sensorRule.FindStringSubmatch(id); m != nil && slices.Contains([]string{"proposed", "observing", "enforcing"}, state) {
				l.Sensors[m[1]] = id
			}
		}
	case "get_rule_stats":
		top, _ := out["top_subjects"].(map[string]any)
		list, _ := top["untrusted"].([]any)
		for _, t := range list {
			t, _ := t.(map[string]any)
			if d, ok := t["display"].(string); ok && len(l.Subjects) < 5 {
				l.Subjects = append(l.Subjects, d)
			}
		}
	}
}

// claimed is the part of a claim the agent reads.
type claimed struct {
	CaseID int64          `json:"case_id"`
	Kind   string         `json:"kind"`
	Brief  map[string]any `json:"brief"`
	RunID  int64          `json:"run_id"`
}

type agentRunner struct {
	admin string
	token string
	plan  plan
	http  *http.Client
}

var providers = []string{"claude"}

func (a *agentRunner) post(ctx context.Context, path string, in, out any) (int, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.admin+path, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		var p struct{ Detail string }
		_ = json.NewDecoder(resp.Body).Decode(&p)
		return resp.StatusCode, fmt.Errorf("%s: %d %s", path, resp.StatusCode, p.Detail)
	}
	if out != nil && resp.StatusCode == http.StatusOK {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

// headerTransport adds the token and the run to every MCP request.
type headerTransport struct {
	headers map[string]string
}

func (t headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// run answers one claimed case and posts its result.
func (a *agentRunner) run(ctx context.Context, c claimed) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := a.post(ctx, fmt.Sprintf("/v1/autopilot/cases/%d/heartbeat", c.CaseID), map[string]any{"run_id": c.RunID, "providers": providers}, nil); err != nil {
					log.Printf("case %d heartbeat: %v", c.CaseID, err)
				}
			}
		}
	}()
	hc := &http.Client{Transport: headerTransport{map[string]string{"Authorization": "Bearer " + a.token, "X-Autopilot-Run": fmt.Sprint(c.RunID)}}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "tools-agent", Version: "1"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: a.admin + "/v1/mcp", HTTPClient: hc, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = cs.Close() }()
	var l live
	var proposals []int64
	var verdict string
	made := 0
	for {
		var all []step
		all, verdict = a.plan.steps(c.Kind, c.Brief, l)
		if made == len(all) {
			break
		}
		s := all[made]
		made++
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: s.Tool, Arguments: s.Arguments})
		if err != nil {
			return fmt.Errorf("%s: %w", s.Tool, err)
		}
		out, _ := res.StructuredContent.(map[string]any)
		if res.IsError {
			log.Printf("case %d: %s refused: %s", c.CaseID, s.Tool, text(res))
			continue
		}
		absorb(&l, s.Tool, out)
		if s.Tool == "propose" {
			log.Printf("case %d: propose %s %s accepted %v reasons %v", c.CaseID, s.Arguments["action"], s.Arguments["name"], out["accepted"], out["reasons"])
			if ok, _ := out["accepted"].(bool); ok {
				id, _ := out["proposal_id"].(float64)
				proposals = append(proposals, int64(id))
			}
		}
	}
	result := map[string]any{"run_id": c.RunID, "status": "ok", "error_category": "", "verdict": verdict, "summary": "Answered by the load-test plan",
		"proposals": orEmpty(proposals), "turns": made + 1, "tool_calls": made, "usage": map[string]int{"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0},
		"provider_cost_usd": nil, "transcript_bytes": 0, "transcript_sha256": "", "last_seq": 0}
	_, err = a.post(ctx, fmt.Sprintf("/v1/autopilot/cases/%d/result", c.CaseID), result, nil)
	log.Printf("case %d (%s) answered %s with proposals %v", c.CaseID, c.Kind, verdict, proposals)
	return err
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

// loop claims and answers cases until ctx ends.
func (a *agentRunner) loop(ctx context.Context) {
	body := map[string]any{"runner": "tools-agent", "version": "1", "sdk_version": "go-sdk", "providers": providers, "wait": "20s"}
	for ctx.Err() == nil {
		var c claimed
		cctx, cancel := context.WithTimeout(ctx, 35*time.Second)
		status, err := a.post(cctx, "/v1/autopilot/claim", body, &c)
		cancel()
		switch {
		case err != nil:
			log.Printf("claim: %v", err)
			time.Sleep(2 * time.Second)
		case status == http.StatusOK:
			if err := a.run(ctx, c); err != nil {
				log.Printf("case %d: %v", c.CaseID, err)
			}
		}
	}
}

func agent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	admin := fs.String("admin", "http://admin:8081", "admin's base URL")
	tokenFile := fs.String("token-file", "", "file holding admin's autopilot runner token")
	planFile := fs.String("plan", "", "plan JSON in place of the embedded one")
	concurrency := fs.Int("concurrency", 4, "cases answered at once, 1 to 4")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *concurrency < 1 || *concurrency > 4 {
		return errors.New("-concurrency is 1 to 4")
	}
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		return fmt.Errorf("-token-file: %w", err)
	}
	b := autopilotPlan
	if *planFile != "" {
		if b, err = os.ReadFile(*planFile); err != nil {
			return err
		}
	}
	p, err := readPlan(b)
	if err != nil {
		return err
	}
	a := &agentRunner{admin: strings.TrimRight(*admin, "/"), token: strings.TrimSpace(string(token)), plan: p, http: &http.Client{}}
	log.Printf("agent: %d plan sensors, %d at once, admin %s", len(p.Sensors), *concurrency, a.admin)
	var wg sync.WaitGroup
	for range *concurrency {
		wg.Go(func() { a.loop(context.Background()) })
	}
	wg.Wait()
	return nil
}
