package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// secretFile writes value to a file of its own and returns the path, as a
// deployment mounts a secret.
func secretFile(t *testing.T, value string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(value); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// Datadog's sites, from https://docs.datadoghq.com/getting_started/site/:
// the site parameter and its API host (https://docs.datadoghq.com/api/latest/metrics/).
var datadogSites = []struct{ site, api string }{
	{"datadoghq.com", "https://api.datadoghq.com"},
	{"us3.datadoghq.com", "https://api.us3.datadoghq.com"},
	{"us5.datadoghq.com", "https://api.us5.datadoghq.com"},
	{"datadoghq.eu", "https://api.datadoghq.eu"},
	{"ap1.datadoghq.com", "https://api.ap1.datadoghq.com"},
	{"ap2.datadoghq.com", "https://api.ap2.datadoghq.com"},
	{"uk1.datadoghq.com", "https://api.uk1.datadoghq.com"},
	{"ddog-gov.com", "https://api.ddog-gov.com"},
	{"us2.ddog-gov.com", "https://api.us2.ddog-gov.com"},
}

// Connector URLs and credentials come only from deployment config. A bad
// one stops admin at start, naming the variable and never the secret.
func TestLoadConfigConnectors(t *testing.T) {
	const (
		grafanaSecret = "glsa_viewer0123456789abcdefABCDEF"
		ddAPISecret   = "0123456789abcdef0123456789abcdef"
		ddAppSecret   = "abcdef0123456789abcdef0123456789abcdef01"
		promSecret    = "prom-bearer-0123456789abcdef"
	)
	grafanaToken := secretFile(t, grafanaSecret+"\n")
	ddAPIKey, ddAppKey := secretFile(t, ddAPISecret+"\n"), secretFile(t, ddAppSecret+"\n")
	promToken := secretFile(t, promSecret)
	empty := secretFile(t, "\n")
	spaced := secretFile(t, "glsa_viewer 0123456789abcdef\n")
	nonASCII := secretFile(t, "glsa_viewér0123456789abcdef\n")
	missing := filepath.Join(t.TempDir(), "missing")
	datadog := map[string]string{"DATADOG_SITE": "datadoghq.eu", "DATADOG_API_KEY_FILE": ddAPIKey, "DATADOG_APP_KEY_FILE": ddAppKey}
	with := func(base map[string]string, k, v string) map[string]string {
		m := maps.Clone(base)
		m[k] = v
		return m
	}
	cases := []struct {
		name string
		set  map[string]string
		msgs []string // empty means the config loads
	}{
		{"no connector variables load", nil, nil},
		{"a Prometheus URL loads", map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090"}, nil},
		{"a Prometheus URL with a path loads, as Grafana Cloud's /api/prom", map[string]string{"PROMETHEUS_URL": "https://prometheus-prod-01.grafana.net/api/prom", "PROMETHEUS_TOKEN_FILE": promToken}, nil},
		{"a Prometheus URL that is not http or https is refused", map[string]string{"PROMETHEUS_URL": "ftp://prometheus.monitoring:9090"}, []string{"PROMETHEUS_URL"}},
		{"a Prometheus URL without a host is refused", map[string]string{"PROMETHEUS_URL": "http:///api/v1"}, []string{"PROMETHEUS_URL"}},
		{"a Prometheus URL with credentials is refused without echoing them", map[string]string{"PROMETHEUS_URL": "http://scraper:s3cret-pass@prometheus.monitoring:9090"}, []string{"PROMETHEUS_URL"}},
		{"a Prometheus URL with a query is refused", map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090/?tenant=a"}, []string{"PROMETHEUS_URL"}},
		{"a Prometheus URL with a fragment is refused", map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090/#graph"}, []string{"PROMETHEUS_URL"}},
		{"a Prometheus token file without the URL is refused", map[string]string{"PROMETHEUS_TOKEN_FILE": promToken}, []string{"PROMETHEUS_TOKEN_FILE: set it with PROMETHEUS_URL"}},
		{"a Grafana URL with a token file loads", map[string]string{"GRAFANA_URL": "https://grafana.example.com", "GRAFANA_TOKEN_FILE": grafanaToken}, nil},
		{"a Grafana URL without a token file is refused", map[string]string{"GRAFANA_URL": "https://grafana.example.com"}, []string{"GRAFANA_TOKEN_FILE"}},
		{"a Grafana URL that is not http or https is refused", map[string]string{"GRAFANA_URL": "file:///etc/grafana", "GRAFANA_TOKEN_FILE": grafanaToken}, []string{"GRAFANA_URL"}},
		{"a Grafana URL with credentials is refused without echoing them", map[string]string{"GRAFANA_URL": "https://admin:s3cret-pass@grafana.example.com", "GRAFANA_TOKEN_FILE": grafanaToken}, []string{"GRAFANA_URL"}},
		{"an empty token file is refused", map[string]string{"GRAFANA_URL": "https://grafana.example.com", "GRAFANA_TOKEN_FILE": empty}, []string{"GRAFANA_TOKEN_FILE"}},
		{"a token file holding a space is refused without echoing it", map[string]string{"GRAFANA_URL": "https://grafana.example.com", "GRAFANA_TOKEN_FILE": spaced}, []string{"GRAFANA_TOKEN_FILE"}},
		{"a token file holding a non-ASCII character is refused without echoing it", map[string]string{"GRAFANA_URL": "https://grafana.example.com", "GRAFANA_TOKEN_FILE": nonASCII}, []string{"GRAFANA_TOKEN_FILE"}},
		{"an unreadable token file is refused", map[string]string{"GRAFANA_URL": "https://grafana.example.com", "GRAFANA_TOKEN_FILE": missing}, []string{"GRAFANA_TOKEN_FILE"}},
		{"a Datadog site with both key files loads", datadog, nil},
		{"a Datadog site not on Datadog's list is refused", with(datadog, "DATADOG_SITE", "datadoghq.example.com"), []string{"DATADOG_SITE"}},
		{"a Datadog site without the application key file is refused", map[string]string{"DATADOG_SITE": "datadoghq.eu", "DATADOG_API_KEY_FILE": ddAPIKey}, []string{"DATADOG_APP_KEY_FILE"}},
		{"a Datadog site without the API key file is refused", map[string]string{"DATADOG_SITE": "datadoghq.eu", "DATADOG_APP_KEY_FILE": ddAppKey}, []string{"DATADOG_API_KEY_FILE"}},
		{"a Datadog key file without the site is refused", map[string]string{"DATADOG_API_KEY_FILE": ddAPIKey}, []string{"DATADOG_API_KEY_FILE"}},
		{"an empty Datadog key file is refused", with(datadog, "DATADOG_APP_KEY_FILE", empty), []string{"DATADOG_APP_KEY_FILE"}},
		{"a metrics link with {query} loads with Prometheus", map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090", "METRICS_LINK_URL": "https://grafana.example.com/explore?q={query}&from={from_ms}&to={to_ms}"}, nil},
		{"a metrics link without {query} is refused", map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090", "METRICS_LINK_URL": "https://grafana.example.com/explore"}, []string{"METRICS_LINK_URL"}},
		{"a metrics link that is not http or https is refused", map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090", "METRICS_LINK_URL": "javascript:alert({query})"}, []string{"METRICS_LINK_URL"}},
		{"a metrics link with credentials is refused", map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090", "METRICS_LINK_URL": "https://viewer:s3cret-pass@grafana.example.com/explore?q={query}"}, []string{"METRICS_LINK_URL"}},
		{"a metrics link without Prometheus is refused", map[string]string{"METRICS_LINK_URL": "https://grafana.example.com/explore?q={query}"}, []string{"METRICS_LINK_URL"}},
		{"every connector problem is reported at once", map[string]string{"PROMETHEUS_URL": "ftp://prometheus.monitoring", "GRAFANA_URL": "https://grafana.example.com", "DATADOG_SITE": "datadoghq.example.com"},
			[]string{"PROMETHEUS_URL", "GRAFANA_TOKEN_FILE", "DATADOG_SITE"}},
	}
	secrets := []string{grafanaSecret, ddAPISecret, ddAppSecret, promSecret, "s3cret-pass", "glsa_viewer 0123456789abcdef", "glsa_viewér"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := baseEnv("postgres://app@db/admin")
			maps.Copy(e, tc.set)
			_, err := LoadConfig(env(e))
			if len(tc.msgs) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatalf("loaded, want %q", tc.msgs)
			}
			for _, m := range tc.msgs {
				if !strings.Contains(err.Error(), m) {
					t.Errorf("err = %v, want %q", err, m)
				}
			}
			for _, s := range secrets {
				if strings.Contains(err.Error(), s) {
					t.Errorf("err echoes a secret: %v", err)
				}
			}
		})
	}
	for _, s := range datadogSites {
		t.Run("Datadog site "+s.site+" reads its API host and both keys", func(t *testing.T) {
			e := baseEnv("postgres://app@db/admin")
			maps.Copy(e, with(datadog, "DATADOG_SITE", s.site))
			c, err := LoadConfig(env(e))
			if err != nil {
				t.Fatal(err)
			}
			if c.Datadog.API != s.api || c.Datadog.APIKey != ddAPISecret || c.Datadog.AppKey != ddAppSecret {
				t.Fatalf("api %q, want %q; keys read %v", c.Datadog.API, s.api, c.Datadog.APIKey == ddAPISecret && c.Datadog.AppKey == ddAppSecret)
			}
		})
	}
}

// baseTools are the tools a runner lists with no connector configured.
var baseTools = []string{"check_subject", "describe_fields", "get_autopilot_state", "get_case", "get_route", "get_rule_stats",
	"get_stats", "list_anomalies", "list_cases", "list_routes", "list_rules", "list_versions", "propose", "record_learning", "search_notes", "simulate_rule",
	"validate_rule"}

// A connector's tools exist only where it is configured, so the model never
// spends turns on a tool that can only answer "not configured", and a run's
// tools hash names the set it really had.
func TestConnectorToolsListedOnlyWhenConfigured(t *testing.T) {
	token := secretFile(t, "glsa_viewer0123456789abcdefABCDEF\n")
	hashes := map[string]string{}
	for _, tc := range []struct {
		name string
		set  map[string]string
		adds []string
	}{
		{"no connector lists no connector tool", nil, nil},
		{"Prometheus lists its two tools", map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090"}, []string{"prom_query", "prom_query_range"}},
		{"Grafana lists its two tools", map[string]string{"GRAFANA_URL": "https://grafana.example.com", "GRAFANA_TOKEN_FILE": token}, []string{"grafana_annotations", "grafana_dashboards"}},
		{"Datadog lists its two tools", map[string]string{"DATADOG_SITE": "datadoghq.eu", "DATADOG_API_KEY_FILE": secretFile(t, "0123456789abcdef0123456789abcdef"),
			"DATADOG_APP_KEY_FILE": secretFile(t, "abcdef0123456789abcdef0123456789abcdef01")}, []string{"dd_query_metrics", "dd_search_logs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, pub, agent := autopilotHarnessWith(t, tc.set)
			first := openAndClaim(t, pub, agent)
			want := slices.Sorted(slices.Values(append(slices.Clone(baseTools), tc.adds...)))
			if got := toolNames(t, h.mcpSession(agentToken, first.RunID)); !slices.Equal(got, want) {
				t.Fatalf("runner lists %v, want %v", got, want)
			}
			// Runner-only: a connector reaches whatever its credentials do,
			// which is more than the edge stats stats.read grants.
			reader := toolNames(t, h.mcpSession(pub.userToken("autopilot.read", "config.read", "stats.read"), 0))
			for _, tool := range tc.adds {
				if slices.Contains(reader, tool) {
					t.Errorf("a person's token lists %s: %v", tool, reader)
				}
			}
			status(t, agent.result(first.CaseID, resultBody(first.RunID, "benign", usage{Input: 10}, nil, 0)), 204)
			pub.investigate("login", "Is someone guessing passwords?")
			second := agent.claimCase()
			if second.ToolsSHA256 != first.ToolsSHA256 {
				t.Fatalf("two claims on one deployment have tools hashes %s and %s", first.ToolsSHA256, second.ToolsSHA256)
			}
			for other, sum := range hashes {
				if sum == first.ToolsSHA256 {
					t.Fatalf("tools hash %s is the same as with %q", sum, other)
				}
			}
			hashes[tc.name] = first.ToolsSHA256
		})
	}
}

// contractTool is a tool as the contract lists it, in the field order the
// tools hash is taken over.
type contractTool struct {
	Name        string         `json:"name"`
	Perm        string         `json:"permission"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"input_schema"`
}

// The contract is what a claim gives the runner, minus the case, so replay
// can run a recorded case without opening a run.
func TestAutopilotContract(t *testing.T) {
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"PROMETHEUS_URL": "http://prometheus.monitoring:9090"})
	c := openAndClaim(t, pub, agent)
	resp := pub.do("GET", "/api/autopilot/contract", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("contract %d: %s", resp.StatusCode, body(resp))
	}
	raw := decode[map[string]json.RawMessage](t, resp)
	var got struct {
		Prompt       string          `json:"prompt"`
		PromptSHA256 string          `json:"prompt_sha256"`
		Tools        []contractTool  `json:"tools"`
		ToolsSHA256  string          `json:"tools_sha256"`
		OutputSchema json.RawMessage `json:"output_schema"`
	}
	b, _ := json.Marshal(raw)
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	t.Run("the prompt and its hash are the claim's", func(t *testing.T) {
		if got.Prompt != c.Prompt || got.PromptSHA256 != c.PromptSHA256 || hexSHA256([]byte(got.Prompt)) != got.PromptSHA256 {
			t.Fatalf("prompt sha %s, claim's %s", got.PromptSHA256, c.PromptSHA256)
		}
	})
	t.Run("the tools are the ones the runner lists, and their hash is the claim's", func(t *testing.T) {
		var names []string
		for _, tool := range got.Tools {
			names = append(names, tool.Name)
		}
		if want := toolNames(t, h.mcpSession(agentToken, c.RunID)); !slices.Equal(slices.Sorted(slices.Values(names)), want) {
			t.Fatalf("contract tools %v, runner lists %v", names, want)
		}
		tb, _ := json.Marshal(got.Tools)
		if sum := sha256.Sum256(tb); got.ToolsSHA256 != c.ToolsSHA256 || hex.EncodeToString(sum[:]) != got.ToolsSHA256 {
			t.Fatalf("tools_sha256 %s, claim's %s, hash of the listed tools %x", got.ToolsSHA256, c.ToolsSHA256, sum)
		}
	})
	t.Run("each tool names the permission it needs", func(t *testing.T) {
		for _, tool := range got.Tools {
			want := map[string]string{"prom_query": permAutopilot, "prom_query_range": permAutopilot, "get_stats": "stats.read", "get_case": permAutopilot, "list_rules": "config.read"}[tool.Name]
			if want != "" && tool.Perm != want {
				t.Errorf("%s needs %q, want %q", tool.Name, tool.Perm, want)
			}
		}
	})
	t.Run("the output schema is the claim's", func(t *testing.T) {
		var a, b any
		_ = json.Unmarshal(got.OutputSchema, &a)
		_ = json.Unmarshal(c.OutputSchema, &b)
		if a == nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("output schema %s, claim's %s", got.OutputSchema, c.OutputSchema)
		}
	})
	t.Run("it carries no case", func(t *testing.T) {
		for _, k := range []string{"case_id", "brief", "run_id"} {
			if _, ok := raw[k]; ok {
				t.Errorf("contract has %s", k)
			}
		}
	})
	t.Run("a token without autopilot.read is refused", func(t *testing.T) {
		stats := h.client()
		stats.token = pub.userToken("stats.read")
		status(t, stats.do("GET", "/api/autopilot/contract", nil), 403)
	})
	t.Run("the runner's token is refused", func(t *testing.T) {
		status(t, agent.do("GET", "/api/autopilot/contract", nil), 403)
	})
}

// connectorCount is the admin_connector_requests_total series line.
func connectorCount(connector, result string, n int) string {
	return fmt.Sprintf(`admin_connector_requests_total{connector=%q,result=%q} %d`, connector, result, n)
}

// listOf is the list under key, inside its untrusted wrapper when it has one.
func listOf(t *testing.T, out map[string]any, key string) []any {
	t.Helper()
	v := out[key]
	if m, ok := v.(map[string]any); ok {
		v = m["untrusted"]
	}
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("%s is %T in %v", key, out[key], out)
	}
	return l
}

func TestConnectorPrometheus(t *testing.T) {
	prom := testenv.Prometheus(t)
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"PROMETHEUS_URL": prom,
		"METRICS_LINK_URL": "https://grafana.example.com/explore?q={query}&from={from_ms}&to={to_ms}"})
	c, cs := agentCase(t, h, pub, agent)
	var calls []string

	t.Run("prom_query of up answers 1 with its labels untrusted, a link and an evidence id", func(t *testing.T) {
		out := mustCall(t, cs, "prom_query", map[string]any{"query": "up"})
		calls = append(calls, "prom_query")
		series := listOf(t, out, "series")
		if out["connector"] != "prometheus" || out["result_type"] != "vector" || len(series) != 1 {
			t.Fatalf("prom_query up %v", out)
		}
		s := series[0].(map[string]any)
		if fmt.Sprint(s["value"]) != "1" {
			t.Fatalf("up = %v", s["value"])
		}
		if p := untrustedOnly(out, "localhost:9090", "", false); p != "" {
			t.Fatalf("label value outside untrusted at %s", p)
		}
		if link, _ := out["link"].(string); !strings.HasPrefix(link, "https://grafana.example.com/explore?q=up&from=") {
			t.Fatalf("link %q", out["link"])
		}
		if _, ok := out["evidence_id"]; !ok {
			t.Fatal("no evidence_id")
		}
	})
	t.Run("prom_query keeps at most 50 series and counts the rest", func(t *testing.T) {
		out := mustCall(t, cs, "prom_query", map[string]any{"query": `{__name__=~"prometheus_.+"}`})
		calls = append(calls, "prom_query")
		if n := len(listOf(t, out, "series")); n != 50 {
			t.Fatalf("%d series, want 50", n)
		}
		if more, _ := out["more"].(float64); more < 1 {
			t.Fatalf("more = %v", out["more"])
		}
	})
	for _, tc := range []struct {
		minutes, step int
	}{{60, 60}, {1440, 1440}, {20160, 20160}} {
		t.Run(fmt.Sprintf("prom_query_range over %d minutes steps %ds and answers at most 60 points", tc.minutes, tc.step), func(t *testing.T) {
			// vector(1) has a value at every step, so a window of 61 steps shows.
			out := mustCall(t, cs, "prom_query_range", map[string]any{"query": "vector(1)", "minutes": tc.minutes})
			calls = append(calls, "prom_query_range")
			series := listOf(t, out, "series")
			if out["connector"] != "prometheus" || out["step_seconds"] != float64(tc.step) || len(series) != 1 {
				t.Fatalf("prom_query_range %v", out)
			}
			points, _ := series[0].(map[string]any)["points"].([]any)
			if len(points) < 1 || len(points) > 60 {
				t.Fatalf("%d points", len(points))
			}
			from, _ := out["from"].(float64)
			to, _ := out["to"].(float64)
			if to-from > float64(tc.minutes*60) || to <= from {
				t.Fatalf("from %v to %v for %d minutes", out["from"], out["to"], tc.minutes)
			}
		})
	}
	t.Run("prom_query_range keeps at most 10 series", func(t *testing.T) {
		out := mustCall(t, cs, "prom_query_range", map[string]any{"query": `{__name__=~"prometheus_.+"}`, "minutes": 5})
		calls = append(calls, "prom_query_range")
		if n := len(listOf(t, out, "series")); n != 10 {
			t.Fatalf("%d series, want 10", n)
		}
		if more, _ := out["more"].(float64); more < 1 {
			t.Fatalf("more = %v", out["more"])
		}
	})
	t.Run("a query Prometheus can't parse is a tool error naming bad_data", func(t *testing.T) {
		_, why := callTool(t, cs, "prom_query", map[string]any{"query": "up{"})
		calls = append(calls, "prom_query")
		if !strings.Contains(why, "bad_data") {
			t.Fatalf("refusal %q", why)
		}
	})
	for _, tc := range []struct {
		name, tool string
		args       map[string]any
	}{
		{"a query over 2000 characters is refused before Prometheus sees it", "prom_query", map[string]any{"query": strings.Repeat("u", 2001)}},
		{"an empty query is refused", "prom_query", map[string]any{"query": ""}},
		{"a window over 14 days is refused", "prom_query_range", map[string]any{"query": "up", "minutes": 20161}},
		{"an argument the tool doesn't take is refused", "prom_query", map[string]any{"query": "up", "url": "http://elsewhere"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, why := callTool(t, cs, tc.tool, tc.args); why == "" {
				t.Fatalf("answered %v", out)
			}
			calls = append(calls, tc.tool)
		})
	}
	t.Run("the run's record holds every call as an admin event", func(t *testing.T) {
		if got := adminEvents(t, h, c.RunID); !slices.Equal(got, calls) {
			t.Fatalf("recorded %v, want %v", got, calls)
		}
	})
	t.Run("a person's stats.read token is refused prom_query naming autopilot.agent, and nothing reaches Prometheus", func(t *testing.T) {
		person := h.mcpSession(pub.userToken("stats.read"), 0)
		if got := toolNames(t, person); slices.Contains(got, "prom_query") || slices.Contains(got, "prom_query_range") {
			t.Fatalf("a stats.read token lists %v", got)
		}
		if out, why := callTool(t, person, "prom_query", map[string]any{"query": "up"}); !strings.Contains(why, "autopilot.agent") {
			t.Fatalf("answered %v, refusal %q", out, why)
		}
	})
	t.Run("the counter shows each request Prometheus answered, from zero for the others", func(t *testing.T) {
		// ok: up, 50 series, three ranges and 10 series; the person's call never left admin.
		h.wantMetrics(connectorCount("prometheus", "ok", 6), connectorCount("prometheus", "error", 1),
			connectorCount("prometheus", "timeout", 0), connectorCount("prometheus", "too_large", 0),
			connectorCount("grafana", "ok", 0), connectorCount("datadog", "ok", 0))
	})
}

func TestConnectorGrafana(t *testing.T) {
	grafana, token := testenv.Grafana(t)
	var dash struct {
		UID string `json:"uid"`
	}
	if err := testenv.GrafanaAdmin(t.Context(), grafana, "POST", "/api/dashboards/db",
		map[string]any{"dashboard": map[string]any{"title": "Edge traffic", "tags": []string{"edge"}}, "overwrite": true}, &dash); err != nil {
		t.Fatal(err)
	}
	// A deploy note someone pasted a credential into: it must not reach the model.
	now := time.Now()
	if err := testenv.GrafanaAdmin(t.Context(), grafana, "POST", "/api/annotations", map[string]any{"dashboardUID": dash.UID, "time": now.Add(-10 * time.Minute).UnixMilli(),
		"tags": []string{"deploy"}, "text": "Deployed api v2.3, Authorization: Bearer grafana-leak-0123456789abcdef"}, nil); err != nil {
		t.Fatal(err)
	}
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"GRAFANA_URL": grafana, "GRAFANA_TOKEN_FILE": secretFile(t, token+"\n")})
	c, cs := agentCase(t, h, pub, agent)

	t.Run("grafana_annotations answers the deploy with its text untrusted and redacted, and an absolute link", func(t *testing.T) {
		out := mustCall(t, cs, "grafana_annotations", map[string]any{"minutes": 60, "tags": []string{"deploy"}})
		items := listOf(t, out, "annotations")
		if out["connector"] != "grafana" || len(items) != 1 {
			t.Fatalf("grafana_annotations %v", out)
		}
		a := items[0].(map[string]any)
		text := fmt.Sprint(a["text"])
		if !strings.Contains(text, "Deployed api v2.3") || !strings.Contains(text, "[redacted]") || strings.Contains(fmt.Sprint(out), "grafana-leak-0123456789abcdef") {
			t.Fatalf("text %v", a["text"])
		}
		if p := untrustedOnly(out, "Deployed api", "", false); p != "" {
			t.Fatalf("annotation text outside untrusted at %s", p)
		}
		if a["dashboard_uid"] != dash.UID || !strings.HasPrefix(fmt.Sprint(a["link"]), grafana+"/d/"+dash.UID) {
			t.Fatalf("annotation %v", a)
		}
		if _, ok := out["evidence_id"]; !ok {
			t.Fatal("no evidence_id")
		}
	})
	t.Run("grafana_annotations outside the window answers none", func(t *testing.T) {
		if items := listOf(t, mustCall(t, cs, "grafana_annotations", map[string]any{"minutes": 5, "tags": []string{"deploy"}}), "annotations"); len(items) != 0 {
			t.Fatalf("annotations %v", items)
		}
	})
	t.Run("grafana_dashboards finds the dashboard with an absolute URL", func(t *testing.T) {
		out := mustCall(t, cs, "grafana_dashboards", map[string]any{"query": "Edge"})
		items := listOf(t, out, "dashboards")
		if out["connector"] != "grafana" || len(items) != 1 {
			t.Fatalf("grafana_dashboards %v", out)
		}
		d := items[0].(map[string]any)
		if d["uid"] != dash.UID || d["url"] != grafana+"/d/"+dash.UID || !strings.Contains(fmt.Sprint(d["title"]), "Edge traffic") {
			t.Fatalf("dashboard %v", d)
		}
		if p := untrustedOnly(out, "Edge traffic", "", false); p != "" {
			t.Fatalf("title outside untrusted at %s", p)
		}
	})
	t.Run("a limit over 20 dashboards is refused", func(t *testing.T) {
		if out, why := callTool(t, cs, "grafana_dashboards", map[string]any{"limit": 21}); why == "" {
			t.Fatalf("answered %v", out)
		}
	})
	t.Run("the recorded calls hold neither the token nor the pasted credential", func(t *testing.T) {
		var payloads string
		_ = h.db.QueryRow(t.Context(), "SELECT string_agg(payload::text, ' ') FROM autopilot_run_events WHERE run_id = $1", c.RunID).Scan(&payloads)
		if payloads == "" || strings.Contains(payloads, token) || strings.Contains(payloads, "grafana-leak-0123456789abcdef") {
			t.Fatalf("recorded events leak a secret: %v", payloads != "")
		}
	})
	h.wantMetrics(connectorCount("grafana", "ok", 3))
}

// fakeDatadog answers Datadog's v1 metrics query and v2 logs search, as
// documented at https://docs.datadoghq.com/api/latest/metrics/query-timeseries-points.md
// and https://docs.datadoghq.com/api/latest/logs/search-logs-post.md, for
// the two keys it was made with. It records every request.
type fakeDatadog struct {
	srv            *httptest.Server
	apiKey, appKey string
	mu             sync.Mutex
	reqs           []ddRequest
	// overfull answers this many log lines past page.limit and no next
	// cursor, as a Datadog that ignores the limit would.
	overfull int
}

type ddRequest struct {
	method, path, apiKey, appKey string
	query                        map[string][]string
	body                         map[string]any
}

// ddLeak is a credential a log line carries.
const ddLeak = "Bearer sk-live-0123456789abcdefghijklmn"

func newFakeDatadog(t *testing.T, apiKey, appKey string) *fakeDatadog {
	t.Helper()
	dd := &fakeDatadog{apiKey: apiKey, appKey: appKey}
	dd.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := ddRequest{method: r.Method, path: r.URL.Path, apiKey: r.Header.Get("DD-API-KEY"), appKey: r.Header.Get("DD-APPLICATION-KEY"), query: r.URL.Query()}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req.body)
		dd.mu.Lock()
		dd.reqs = append(dd.reqs, req)
		dd.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if req.apiKey != dd.apiKey || req.appKey != dd.appKey {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["Forbidden"]}`))
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/query":
			from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
			to, _ := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
			// One series per host, a point every 15s: more series and points
			// than admin passes on.
			var series []map[string]any
			for i := range 12 {
				var points [][2]float64
				for ts := from; ts <= to && len(points) < 120; ts += 15 {
					points = append(points, [2]float64{float64(ts * 1000), float64(i)})
				}
				series = append(series, map[string]any{"metric": "trace.http.request.hits", "scope": fmt.Sprintf("host:web-%d,service:web", i),
					"pointlist": points, "interval": 15000, "length": len(points)})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "res_type": "time_series", "from_date": from * 1000, "to_date": to * 1000,
				"query": r.URL.Query().Get("query"), "series": series})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/logs/events/search":
			page, _ := req.body["page"].(map[string]any)
			limit := 10 // Datadog's default page size
			if l, ok := page["limit"].(float64); ok {
				limit = int(l)
			}
			dd.mu.Lock()
			extra := dd.overfull
			dd.mu.Unlock()
			after := "next-cursor"
			if extra > 0 {
				after = ""
			}
			var data []map[string]any
			for i := range limit + extra {
				msg := fmt.Sprintf("POST /login 401 for user%d", i)
				switch i {
				case 0:
					msg = "login failed, Authorization: " + ddLeak
				case 1:
					msg = strings.Repeat("x", 2000)
				}
				data = append(data, map[string]any{"id": fmt.Sprint("log-", i), "type": "log", "attributes": map[string]any{
					"timestamp": time.Now().Add(-time.Duration(i) * time.Second).UTC().Format(time.RFC3339), "service": "web", "host": "web-1", "status": "error", "message": msg, "tags": []string{"env:prod"}}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "meta": map[string]any{"page": map[string]any{"after": after}, "status": "done"}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":["Not found"]}`))
		}
	}))
	t.Cleanup(dd.srv.Close)
	return dd
}

func (dd *fakeDatadog) requests() []ddRequest {
	dd.mu.Lock()
	defer dd.mu.Unlock()
	return slices.Clone(dd.reqs)
}

func TestConnectorDatadog(t *testing.T) {
	const apiKey, appKey = "0123456789abcdef0123456789abcdef", "abcdef0123456789abcdef0123456789abcdef01"
	dd := newFakeDatadog(t, apiKey, appKey)
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"DATADOG_SITE": "datadoghq.eu",
		"DATADOG_API_KEY_FILE": secretFile(t, apiKey+"\n"), "DATADOG_APP_KEY_FILE": secretFile(t, appKey+"\n")})
	// Datadog can't run locally, so the API base points at the fake.
	h.s.cfg.Datadog.API = dd.srv.URL
	c, cs := agentCase(t, h, pub, agent)
	const metricQuery = "sum:trace.http.request.hits{service:web} by {host}"

	t.Run("dd_query_metrics sends both keys and the window, and keeps 10 series of at most 60 points", func(t *testing.T) {
		out := mustCall(t, cs, "dd_query_metrics", map[string]any{"query": metricQuery, "minutes": 30})
		reqs := dd.requests()
		last := reqs[len(reqs)-1]
		from, _ := strconv.ParseInt(last.query["from"][0], 10, 64)
		to, _ := strconv.ParseInt(last.query["to"][0], 10, 64)
		if last.path != "/api/v1/query" || last.apiKey != apiKey || last.appKey != appKey || last.query["query"][0] != metricQuery || to-from != 30*60 {
			t.Fatalf("request %s %v, keys sent %v, window %ds", last.path, last.query["query"], last.apiKey == apiKey && last.appKey == appKey, to-from)
		}
		series := listOf(t, out, "series")
		if out["connector"] != "datadog" || len(series) != 10 {
			t.Fatalf("dd_query_metrics %v", out)
		}
		if more, _ := out["more"].(float64); more != 2 {
			t.Fatalf("more = %v, want the 2 series left out", out["more"])
		}
		for _, s := range series {
			if points, _ := s.(map[string]any)["points"].([]any); len(points) < 1 || len(points) > 60 {
				t.Fatalf("%d points", len(points))
			}
		}
		if p := untrustedOnly(out, "host:web-", "", false); p != "" {
			t.Fatalf("scope outside untrusted at %s", p)
		}
		if p := untrustedOnly(out, "trace.http.request.hits", "", false); p != "" {
			t.Fatalf("metric name outside untrusted at %s", p)
		}
		if _, ok := out["evidence_id"]; !ok {
			t.Fatal("no evidence_id")
		}
	})
	t.Run("dd_search_logs sends the newest-first search and keeps 50 lines, short and redacted", func(t *testing.T) {
		out := mustCall(t, cs, "dd_search_logs", map[string]any{"query": "service:web status:error", "minutes": 15, "limit": 50})
		reqs := dd.requests()
		last := reqs[len(reqs)-1]
		filter, _ := last.body["filter"].(map[string]any)
		page, _ := last.body["page"].(map[string]any)
		if last.path != "/api/v2/logs/events/search" || last.apiKey != apiKey || last.appKey != appKey || filter["query"] != "service:web status:error" ||
			last.body["sort"] != "-timestamp" || page["limit"] != float64(50) {
			t.Fatalf("request %s body %v", last.path, last.body)
		}
		lines := listOf(t, out, "lines")
		if out["connector"] != "datadog" || len(lines) != 50 {
			t.Fatalf("%d lines", len(lines))
		}
		for _, l := range lines {
			if msg := fmt.Sprint(l.(map[string]any)["message"]); len([]rune(msg)) > 500 {
				t.Fatalf("a message of %d runes", len([]rune(msg)))
			}
		}
		b, _ := json.Marshal(out)
		if strings.Contains(string(b), "sk-live-0123456789abcdefghijklmn") || !strings.Contains(string(b), "[redacted]") {
			t.Fatal("the answer carries the credential a log line held")
		}
		if p := untrustedOnly(out, "POST /login", "", false); p != "" {
			t.Fatalf("log message outside untrusted at %s", p)
		}
	})
	t.Run("a Datadog answering more lines than asked keeps 50 and says there are more", func(t *testing.T) {
		dd.mu.Lock()
		dd.overfull = 10
		dd.mu.Unlock()
		t.Cleanup(func() {
			dd.mu.Lock()
			dd.overfull = 0
			dd.mu.Unlock()
		})
		out := mustCall(t, cs, "dd_search_logs", map[string]any{"query": "service:web", "limit": 50})
		if n := len(listOf(t, out, "lines")); n != 50 || out["more"] != true {
			t.Fatalf("%d lines, more %v", n, out["more"])
		}
	})
	t.Run("Datadog answers carry a null link", func(t *testing.T) {
		for _, tool := range []string{"dd_query_metrics", "dd_search_logs"} {
			out := mustCall(t, cs, tool, map[string]any{"query": "service:web"})
			if link, ok := out["link"]; !ok || link != nil {
				t.Fatalf("%s link %v", tool, out["link"])
			}
		}
	})
	t.Run("a limit over 50 lines is refused", func(t *testing.T) {
		if out, why := callTool(t, cs, "dd_search_logs", map[string]any{"query": "service:web", "limit": 51}); why == "" {
			t.Fatalf("answered %v", out)
		}
	})
	t.Run("the recorded calls hold neither key nor the log line's credential", func(t *testing.T) {
		var payloads string
		_ = h.db.QueryRow(t.Context(), "SELECT string_agg(payload::text, ' ') FROM autopilot_run_events WHERE run_id = $1", c.RunID).Scan(&payloads)
		if !strings.Contains(payloads, "dd_search_logs") || strings.Contains(payloads, apiKey) || strings.Contains(payloads, appKey) || strings.Contains(payloads, "sk-live-0123456789abcdefghijklmn") {
			t.Fatal("recorded events leak a secret or miss the calls")
		}
	})
	t.Run("keys Datadog rejects are a tool error naming the status", func(t *testing.T) {
		h.s.cfg.Datadog.AppKey = "revoked0123456789abcdef0123456789abcdef"
		if _, why := callTool(t, cs, "dd_query_metrics", map[string]any{"query": metricQuery}); !strings.Contains(why, "403") || strings.Contains(why, "revoked") {
			t.Fatalf("refusal %q", why)
		}
	})
	h.wantMetrics(connectorCount("datadog", "ok", 5), connectorCount("datadog", "error", 1))
}

// A connector that misbehaves costs one tool error, counted, and admin
// goes on serving. Its bearer token never leaves for another host.
func TestConnectorFailures(t *testing.T) {
	const token = "prom-bearer-0123456789abcdefghij"
	var (
		mu     sync.Mutex
		mode   = "ok"
		auth   []string
		strays int
	)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		strays++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(elsewhere.Close)
	// Over 256 KiB of well-formed series, as a query matching every series gives.
	var large strings.Builder
	large.WriteString(`{"status":"success","data":{"resultType":"vector","result":[`)
	for i := 0; large.Len() <= 256<<10; i++ {
		if i > 0 {
			large.WriteByte(',')
		}
		fmt.Fprintf(&large, `{"metric":{"__name__":"http_requests_total","pod":"web-%d","path":"/api/orders/%d"},"value":[1793221078.191,"%d"]}`, i, i, i)
	}
	large.WriteString(`]}}`)
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		m := mode
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		switch m {
		case "hang":
			<-r.Context().Done()
		case "unavailable":
			http.Error(w, "upstream unavailable, Authorization: Bearer upstream-leak-0123456789abcdef", http.StatusServiceUnavailable)
		case "redirect":
			http.Redirect(w, r, elsewhere.URL+r.URL.RequestURI(), http.StatusFound)
		case "large":
			_, _ = w.Write([]byte(large.String()))
		default:
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","job":"prometheus"},"value":[1793221078.191,"1"]}]}}`))
		}
	}))
	t.Cleanup(prom.Close)
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"PROMETHEUS_URL": prom.URL, "PROMETHEUS_TOKEN_FILE": secretFile(t, token+"\n")})
	h.s.connTimeout = 200 * time.Millisecond
	_, cs := agentCase(t, h, pub, agent)
	set := func(m string) { mu.Lock(); mode = m; mu.Unlock() }

	for _, tc := range []struct {
		name, mode string
		want       []string
	}{
		{"a connector that hangs is a tool error once the timeout passes", "hang", nil},
		{"a non-2xx answer is a tool error naming the status, its body untrusted and credentials redacted", "unavailable", []string{"503", `{"untrusted":"`, "[redacted]"}},
		{"a redirect is a tool error", "redirect", []string{"302"}},
		{"an answer over 256 KiB is a tool error", "large", []string{"256 KiB"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set(tc.mode)
			start := time.Now()
			out, why := callTool(t, cs, "prom_query", map[string]any{"query": "up"})
			if why == "" {
				t.Fatalf("answered %v", out)
			}
			if took := time.Since(start); took > 3*time.Second {
				t.Fatalf("took %s", took)
			}
			for _, w := range tc.want {
				if !strings.Contains(why, w) {
					t.Errorf("refusal %q, want %q", why, w)
				}
			}
			if strings.Contains(why, "upstream-leak") || strings.Contains(why, token) {
				t.Fatalf("refusal echoes a credential: %q", why)
			}
		})
	}
	t.Run("the token never reaches the host a redirect names", func(t *testing.T) {
		mu.Lock()
		defer mu.Unlock()
		if strays != 0 {
			t.Fatalf("%d requests followed the redirect", strays)
		}
	})
	t.Run("admin goes on serving, and a good answer follows", func(t *testing.T) {
		set("ok")
		if out := mustCall(t, cs, "prom_query", map[string]any{"query": "up"}); len(listOf(t, out, "series")) != 1 {
			t.Fatalf("prom_query %v", out)
		}
		status(t, pub.do("GET", "/api/autopilot", nil), 200)
	})
	t.Run("every request carried the deployment's bearer token", func(t *testing.T) {
		mu.Lock()
		defer mu.Unlock()
		if len(auth) == 0 {
			t.Fatal("Prometheus saw no request")
		}
		for _, a := range auth {
			if a != "Bearer "+token {
				t.Fatalf("a request had Authorization %q", strings.Repeat("*", len(a)))
			}
		}
	})
	h.wantMetrics(connectorCount("prometheus", "ok", 1), connectorCount("prometheus", "error", 2),
		connectorCount("prometheus", "timeout", 1), connectorCount("prometheus", "too_large", 1))
}

// A connector read is a stats read, so an observed note may cite it, as it
// cites admin's own stats.
func TestNoteCitesConnectorRead(t *testing.T) {
	prom := testenv.Prometheus(t)
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"PROMETHEUS_URL": prom})
	h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
	_, cs := agentCase(t, h, pub, agent)
	in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1000, lastMinutes(60)))
	in["statement"] = "Fleet requests stay over 1,000 an hour while the stuffing runs"
	in["evidence"] = []int64{evidence(t, cs, "prom_query", map[string]any{"query": "up"})}
	out := mustCall(t, cs, "record_learning", in)
	id := noteID(t, out)
	if out["trust"] != "unconfirmed" {
		t.Fatalf("record_learning %v", out)
	}
	resp := pub.do("GET", fmt.Sprintf("/api/autopilot/notes/%d", id), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("note %d: %s", resp.StatusCode, body(resp))
	}
	note := decode[struct {
		Evidence []struct {
			Tool    string          `json:"tool"`
			Payload json.RawMessage `json:"payload"`
		} `json:"evidence"`
	}](t, resp)
	if len(note.Evidence) != 1 || note.Evidence[0].Tool != "prom_query" || !strings.Contains(string(note.Evidence[0].Payload), "localhost:9090") {
		t.Fatalf("evidence %+v", note.Evidence)
	}
}

// A connector answer can hold other services' logs and metrics, beyond the
// edge stats stats.read grants, so only a person who also manages the
// autopilot reads it back, in a case or in a note's evidence.
func TestConnectorAnswersNeedAutopilotManage(t *testing.T) {
	prom := testenv.Prometheus(t)
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"PROMETHEUS_URL": prom})
	h.putStats(1, 30, 1000, 0, 0, []int64{1000}, "[]", "[]")
	c, cs := agentCase(t, h, pub, agent)
	mustCall(t, cs, "get_rule_stats", map[string]any{"rule": "login"})
	in := learning("attack_signature", scopeGlobal(), claim("requests", ">=", 1000, lastMinutes(60)))
	in["statement"] = "Fleet requests stay over 1,000 an hour while the stuffing runs"
	in["evidence"] = []int64{evidence(t, cs, "prom_query", map[string]any{"query": "up"})}
	note := noteID(t, mustCall(t, cs, "record_learning", in))
	status(t, agent.result(c.CaseID, resultBody(c.RunID, "attack", usage{Input: 10}, nil, 0)), 204)
	reader, manager := h.client(), h.client()
	reader.token = pub.userToken("autopilot.read", "stats.read", "config.read")
	manager.token = pub.userToken("autopilot.read", "stats.read", "config.read", "autopilot.manage")

	type payload struct {
		Tool         string          `json:"tool"`
		Arguments    json.RawMessage `json:"arguments"`
		Result       json.RawMessage `json:"result"`
		Hidden       bool            `json:"hidden"`
		HiddenReason string          `json:"hidden_reason"`
	}
	calls := func(t *testing.T, cl *client) map[string]payload {
		t.Helper()
		resp := cl.do("GET", fmt.Sprintf("/api/autopilot/cases/%d", c.CaseID), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("case %d: %s", resp.StatusCode, body(resp))
		}
		got := map[string]payload{}
		for _, tc := range decode[struct {
			ToolCalls []struct {
				Payload payload `json:"payload"`
			} `json:"tool_calls"`
		}](t, resp).ToolCalls {
			got[tc.Payload.Tool] = tc.Payload
		}
		return got
	}
	type cited struct {
		Tool         string          `json:"tool"`
		Payload      json.RawMessage `json:"payload"`
		Hidden       bool            `json:"hidden"`
		HiddenReason string          `json:"hidden_reason"`
	}
	evidenceOf := func(t *testing.T, cl *client) cited {
		t.Helper()
		resp := cl.do("GET", fmt.Sprintf("/api/autopilot/notes/%d", note), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("note %d: %s", resp.StatusCode, body(resp))
		}
		ev := decode[struct {
			Evidence []cited `json:"evidence"`
		}](t, resp).Evidence
		if len(ev) != 1 || ev[0].Tool != "prom_query" {
			t.Fatalf("evidence %+v", ev)
		}
		return ev[0]
	}

	t.Run("a stats and config reader sees the case's prom_query hidden, query and answer both, naming autopilot.manage", func(t *testing.T) {
		p := calls(t, reader)["prom_query"]
		if !p.Hidden || p.Result != nil || p.Arguments != nil || !strings.Contains(p.HiddenReason, "autopilot.manage") {
			t.Fatalf("prom_query %+v", p)
		}
	})
	t.Run("the same reader still sees the run's get_rule_stats answer", func(t *testing.T) {
		if p := calls(t, reader)["get_rule_stats"]; p.Hidden || p.Result == nil {
			t.Fatalf("get_rule_stats %+v", p)
		}
	})
	t.Run("a person who also manages the autopilot sees the prom_query query and answer", func(t *testing.T) {
		if p := calls(t, manager)["prom_query"]; p.Hidden || !strings.Contains(string(p.Result), "localhost:9090") || !strings.Contains(string(p.Arguments), "up") {
			t.Fatalf("prom_query %+v", p)
		}
	})
	t.Run("a stats and config reader sees the note's connector evidence hidden, naming autopilot.manage", func(t *testing.T) {
		if e := evidenceOf(t, reader); !e.Hidden || e.Payload != nil || !strings.Contains(e.HiddenReason, "autopilot.manage") {
			t.Fatalf("evidence %+v", e)
		}
	})
	t.Run("a person who also manages the autopilot sees the note's connector evidence", func(t *testing.T) {
		if e := evidenceOf(t, manager); e.Hidden || !strings.Contains(string(e.Payload), "localhost:9090") {
			t.Fatalf("evidence %+v", e)
		}
	})
}

// A refused connector call's query and the connector's error text can name
// another service's data as its answer would, so they are hidden the same way.
func TestRefusedConnectorCallHidesItsQueryAndError(t *testing.T) {
	prom := testenv.Prometheus(t)
	h, pub, agent := autopilotHarnessWith(t, map[string]string{"PROMETHEUS_URL": prom})
	c, cs := agentCase(t, h, pub, agent)
	if _, why := callTool(t, cs, "prom_query", map[string]any{"query": "up{"}); !strings.Contains(why, "bad_data") {
		t.Fatalf("refusal %q", why)
	}
	reader, manager := h.client(), h.client()
	reader.token = pub.userToken("autopilot.read", "stats.read", "config.read")
	manager.token = pub.userToken("autopilot.read", "stats.read", "config.read", "autopilot.manage")
	promCall := func(t *testing.T, cl *client) map[string]any {
		t.Helper()
		resp := cl.do("GET", fmt.Sprintf("/api/autopilot/cases/%d", c.CaseID), nil)
		if resp.StatusCode != 200 {
			t.Fatalf("case %d: %s", resp.StatusCode, body(resp))
		}
		for _, tc := range decode[struct {
			ToolCalls []struct {
				Payload map[string]any `json:"payload"`
			} `json:"tool_calls"`
		}](t, resp).ToolCalls {
			if tc.Payload["tool"] == "prom_query" {
				return tc.Payload
			}
		}
		t.Fatal("no prom_query call in the case")
		return nil
	}

	t.Run("a stats and config reader sees neither the query nor the error, and the reason names autopilot.manage", func(t *testing.T) {
		p := promCall(t, reader)
		_, args := p["arguments"]
		_, refusal := p["refusal"]
		if args || refusal || p["hidden"] != true || !strings.Contains(fmt.Sprint(p["hidden_reason"]), "autopilot.manage") {
			t.Fatalf("prom_query %v", p)
		}
	})
	t.Run("a person who also manages the autopilot sees the query and the error", func(t *testing.T) {
		if p := promCall(t, manager); p["hidden"] == true || !strings.Contains(fmt.Sprint(p["arguments"]), "up{") || !strings.Contains(fmt.Sprint(p["refusal"]), "bad_data") {
			t.Fatalf("prom_query %v", p)
		}
	})
}
