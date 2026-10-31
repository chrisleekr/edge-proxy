package admindb

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/expr"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

func connect(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) }) //nolint:usetesting // t.Context is already cancelled when Cleanup runs
	return c
}

// migrated returns owner and app connections to a fresh, migrated database.
func migrated(t *testing.T) (owner, app *pgx.Conn) {
	t.Helper()
	db := testenv.Postgres(t)
	owner = connect(t, db.Owner)
	if err := Migrate(t.Context(), owner, testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	return owner, connect(t, db.App)
}

func TestMigrationNames(t *testing.T) {
	files, _ := fs.Glob(migrations, "migrations/*")
	seen := map[string]bool{}
	for _, f := range files {
		name := strings.TrimPrefix(f, "migrations/")
		if !regexp.MustCompile(`^\d{4}_[a-z0-9_]+\.sql$`).MatchString(name) || seen[name[:4]] {
			t.Errorf("bad or duplicate migration name %s", name)
		}
		seen[name[:4]] = true
	}
}

// A second admin replica starting later finds nothing to do.
func TestMigrateTwice(t *testing.T) {
	owner, _ := migrated(t)
	if err := Migrate(t.Context(), owner, testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	files, _ := fs.Glob(migrations, "migrations/*.sql")
	var n int
	if err := owner.QueryRow(t.Context(), "SELECT count(*) FROM schema_migrations").Scan(&n); err != nil || n != len(files) {
		t.Fatalf("schema_migrations rows = %d for %d files, %v", n, len(files), err)
	}
}

func TestBrokenMigrationLeavesNothing(t *testing.T) {
	owner, _ := migrated(t)
	if _, err := owner.Exec(t.Context(), "DELETE FROM schema_migrations"); err != nil {
		t.Fatal(err)
	}
	// Re-running 0001 fails on existing tables and must not be recorded.
	if err := Migrate(t.Context(), owner, testenv.AppRole); err == nil || !strings.Contains(err.Error(), "migration 0001_init.sql") {
		t.Fatalf("err = %v", err)
	}
	var n int
	_ = owner.QueryRow(t.Context(), "SELECT count(*) FROM schema_migrations").Scan(&n)
	if n != 0 {
		t.Fatal("failed migration recorded")
	}
}

const auditInsert = `INSERT INTO audit_events (seq, occurred_at, actor, action, key_id, hmac)
	VALUES (1, now(), 'system', 'test', 'k1', decode(repeat('00', 32), 'hex'))`

// Audit rows can't be changed through the app role, nor by the owner
// without disabling triggers.
func TestAuditEventsAreAppendOnly(t *testing.T) {
	owner, app := migrated(t)
	ctx := t.Context()
	if _, err := app.Exec(ctx, auditInsert); err != nil {
		t.Fatalf("app insert: %v", err)
	}
	cases := []struct {
		name string
		conn *pgx.Conn
		sql  string
		msg  string
	}{
		{"app update", app, "UPDATE audit_events SET action = 'x'", "permission denied"},
		{"app delete", app, "DELETE FROM audit_events", "permission denied"},
		{"app truncate", app, "TRUNCATE audit_events", "permission denied"},
		{"owner update", owner, "UPDATE audit_events SET action = 'x'", "append-only"},
		{"owner delete", owner, "DELETE FROM audit_events", "append-only"},
		{"owner truncate", owner, "TRUNCATE audit_events", "append-only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.conn.Exec(ctx, tc.sql); err == nil || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want %q", err, tc.msg)
			}
		})
	}
}

// Versions are kept forever, and permissions can't be granted by the app.
func TestRuntimeRoleLimits(t *testing.T) {
	_, app := migrated(t)
	ctx := t.Context()
	for _, sql := range []string{
		"DELETE FROM config_versions",
		"INSERT INTO role_permissions VALUES ('viewer', 'users.manage')",
		"DROP TABLE settings",
	} {
		if _, err := app.Exec(ctx, sql); err == nil {
			t.Errorf("%s: allowed", sql)
		}
	}
}

func TestRolePermissions(t *testing.T) {
	_, app := migrated(t)
	var n int
	if err := app.QueryRow(t.Context(), "SELECT count(*) FROM role_permissions WHERE role = 'admin'").Scan(&n); err != nil || n != 14 {
		t.Fatalf("admin has %d permissions, %v", n, err)
	}
	// Every role reads the autopilot; publishers and admins act on it. The
	// runner's permission comes from its deployment token, never a role.
	for _, tc := range []struct {
		role, perm string
		held       bool
	}{
		{"viewer", "autopilot.read", true},
		{"editor", "autopilot.read", true},
		{"publisher", "autopilot.read", true},
		{"admin", "autopilot.read", true},
		{"viewer", "autopilot.manage", false},
		{"editor", "autopilot.manage", false},
		{"publisher", "autopilot.manage", true},
		{"admin", "autopilot.manage", true},
		{"admin", "autopilot.agent", false},
	} {
		t.Run(tc.role+" "+tc.perm, func(t *testing.T) {
			var held bool
			if err := app.QueryRow(t.Context(), "SELECT EXISTS (SELECT 1 FROM role_permissions WHERE role = $1 AND permission = $2)", tc.role, tc.perm).Scan(&held); err != nil || held != tc.held {
				t.Fatalf("held %v, want %v, err %v", held, tc.held, err)
			}
		})
	}
}

// autopilotRecords inserts, as the owner, one row in each append-only
// autopilot table and the mutable rows they refer to.
func autopilotRecords(t *testing.T, owner *pgx.Conn) {
	t.Helper()
	ctx := t.Context()
	var caseID, runID, proposalID, noteID, revisionID int64
	steps := []struct {
		sql  string
		args func() []any
		into *int64
	}{
		{`INSERT INTO autopilot_model_prices (provider, model, input_usd_micros_per_mtok, output_usd_micros_per_mtok, cache_read_usd_micros_per_mtok,
			cache_write_usd_micros_per_mtok, effective_from, author) VALUES ('claude', 'claude-opus-5-5', 5000000, 25000000, 500000, 6250000, now(), 'user:pub')`,
			func() []any { return nil }, nil},
		{`INSERT INTO autopilot_cases (kind, dedupe_key, state, opened_by) VALUES ('investigate', 'rule:login', 'running', 'user:pub') RETURNING id`,
			func() []any { return nil }, &caseID},
		{`INSERT INTO autopilot_runs (case_id, attempt, runner, runner_version, sdk_version, provider, model, prompt_sha256, tools_sha256, started_at)
			VALUES ($1, 1, 'runner-a', '0.1.0', '1.0.0', 'claude', 'claude-opus-5-5', sha256('prompt'), sha256('tools'), now()) RETURNING id`,
			func() []any { return []any{caseID} }, &runID},
		{`INSERT INTO autopilot_run_results (run_id, finished_at, status, turns, tool_calls, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
			transcript_bytes, transcript_sha256, events_sha256, telemetry_complete) VALUES ($1, now(), 'ok', 1, 0, 0, 0, 0, 0, 0, sha256(''), sha256(''), true)`,
			func() []any { return []any{runID} }, nil},
		{`INSERT INTO autopilot_run_events (run_id, source, seq, kind, at, payload, bytes, payload_sha256, cut)
			VALUES ($1, 'runner', 1, 'assistant_text', now(), '{}', 2, sha256('{}'), false)`,
			func() []any { return []any{runID} }, nil},
		{`INSERT INTO autopilot_proposals (case_id, run_id, action, rule_id, rule, ttl_seconds, rationale, evidence, checks, accepted, rule_sha256)
			VALUES ($1, $2, 'add_sensor', 'ap-login-1', '{}', 3600, 'many failed logins from one address', '{}', '[]', true, sha256('rule')) RETURNING id`,
			func() []any { return []any{caseID, runID} }, &proposalID},
		{`INSERT INTO autopilot_rules (id, proposal_id, case_id, kind, state, rule, shape_sha256, ttl_seconds, live_since, expires_at)
			VALUES ('ap-login-1', $1, $2, 'sensor', 'observing', '{}', sha256('shape'), 3600, now(), now() + interval '1 hour')`,
			func() []any { return []any{proposalID, caseID} }, nil},
		{`INSERT INTO autopilot_transitions (rule_id, case_id, proposal_id, from_state, to_state, reason, numbers, actor, at)
			VALUES ('ap-login-1', $1, $2, 'proposed', 'observing', 'accepted', '{}', 'system:autopilot', now())`,
			func() []any { return []any{caseID, proposalID} }, nil},
		{`INSERT INTO autopilot_notes (kind, basis, scope, scope_key, claim, statement, rationale, stats, links, evidence, trust, trust_since, case_id, run_id, created_at)
			VALUES ('attack_signature', 'observed', '{"kind":"rule","rule":"login"}', 'rule:login', '{"metric":"rule_limited","window":{"last_minutes":60},"op":">=","value":100}',
			'Credential stuffing on login rotates through one /24', '', '{}', '{}', '[]', 'unconfirmed', now(), $1, $2, now()) RETURNING id`,
			func() []any { return []any{caseID, runID} }, &noteID},
		{`INSERT INTO autopilot_note_revisions (note_id, change, trust, reason, fields, actor, run_id, case_id, at)
			VALUES ($1, 'written', 'unconfirmed', '', '{}', 'deployment:autopilot', $2, $3, now()) RETURNING id`,
			func() []any { return []any{noteID, runID, caseID} }, &revisionID},
		{`INSERT INTO autopilot_note_uses (note_id, revision_id, source, run_id, case_id, matched, cited, at)
			VALUES ($1, $2, 'search', $3, $4, true, false, now())`,
			func() []any { return []any{noteID, revisionID, runID, caseID} }, nil},
	}
	for i, st := range steps {
		var err error
		if st.into != nil {
			err = owner.QueryRow(ctx, st.sql, st.args()...).Scan(st.into)
		} else {
			_, err = owner.Exec(ctx, st.sql, st.args()...)
		}
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
}

// The autopilot's record of what it was told, did and cost is kept like
// the audit log: the runtime role can only add rows, and triggers stop the
// owner from changing them.
func TestAutopilotTablesAreAppendOnly(t *testing.T) {
	owner, app := migrated(t)
	autopilotRecords(t, owner)
	ctx := t.Context()
	for _, table := range []string{"autopilot_model_prices", "autopilot_runs", "autopilot_run_results", "autopilot_run_events", "autopilot_proposals", "autopilot_transitions",
		"autopilot_note_revisions", "autopilot_note_uses"} {
		for _, tc := range []struct {
			name string
			conn *pgx.Conn
			sql  string
			msg  string
		}{
			{"app update", app, "UPDATE %s SET %s = %s", "permission denied"},
			{"app delete", app, "DELETE FROM %s", "permission denied"},
			{"app truncate", app, "TRUNCATE %s", "permission denied"},
			{"owner update", owner, "UPDATE %s SET %s = %s", "append-only"},
			{"owner delete", owner, "DELETE FROM %s", "append-only"},
			// CASCADE so a foreign key from another table is not what stops it.
			{"owner truncate", owner, "TRUNCATE %s CASCADE", "append-only"},
		} {
			t.Run(table+" "+tc.name, func(t *testing.T) {
				sql := fmt.Sprintf(tc.sql, table)
				if strings.HasPrefix(tc.sql, "UPDATE") {
					col := map[string]string{"autopilot_model_prices": "author", "autopilot_runs": "runner", "autopilot_run_results": "status",
						"autopilot_run_events": "kind", "autopilot_proposals": "rationale", "autopilot_transitions": "reason",
						"autopilot_note_revisions": "reason", "autopilot_note_uses": "matched"}[table]
					sql = fmt.Sprintf(tc.sql, table, col, col)
				}
				if _, err := tc.conn.Exec(ctx, sql); err == nil || !strings.Contains(err.Error(), tc.msg) {
					t.Fatalf("%s: err = %v, want %q", sql, err, tc.msg)
				}
			})
		}
	}
	// The runtime role adds rows, as admin does on every run.
	if _, err := app.Exec(ctx, `INSERT INTO autopilot_model_prices (provider, model, input_usd_micros_per_mtok, output_usd_micros_per_mtok,
		cache_read_usd_micros_per_mtok, cache_write_usd_micros_per_mtok, effective_from, author) VALUES ('openai', 'gpt-5', 1250000, 10000000, 125000, 0, now(), 'user:pub')`); err != nil {
		t.Fatalf("app insert: %v", err)
	}
}

// migratedBefore returns an owner connection to a fresh database with every
// migration before version applied: an install not yet upgraded.
func migratedBefore(t *testing.T, version int) *pgx.Conn {
	t.Helper()
	owner := connect(t, testenv.Postgres(t).Owner)
	ctx := t.Context()
	if _, err := owner.Exec(ctx, `CREATE TABLE schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	files, _ := fs.Glob(migrations, "migrations/*.sql")
	for _, f := range files {
		name := strings.TrimPrefix(f, "migrations/")
		v, _ := strconv.Atoi(name[:4])
		if v >= version {
			continue
		}
		sql, _ := migrations.ReadFile(f)
		if _, err := owner.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := owner.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", v); err != nil {
			t.Fatal(err)
		}
	}
	return owner
}

// policy is a stored config with one rate-limit rule and one config rule
// under the given ids.
func policy(rateLimitID, configID string) *snapshot.Config {
	c := snapshot.Starter()
	c.Version = 1
	c.RateLimitRules = []snapshot.RateLimitRule{{ID: rateLimitID, Expression: expr.True(), Algorithm: "sliding_window", Limit: 100,
		Period: snapshot.Duration(time.Minute), Key: []string{"ip"}, OnMissingKey: "fallback_ip", Action: "block", FailMode: "open"}}
	c.ConfigRules = []snapshot.ConfigRule{{ID: configID, Expression: expr.True(), Settings: snapshot.Settings{Locale: new(true)}}}
	return c
}

func withHeaderRule(c *snapshot.Config, id string) *snapshot.Config {
	c.RequestHeaderRules = []snapshot.HeaderRule{{ID: id, Expression: expr.True(), Ops: []snapshot.HeaderOp{{Op: "set", Name: "X-Feature", Value: "on"}}}}
	return c
}

// Rule ids starting "ap-" are reserved for autopilot rules once admin
// upgrades. An install whose live policy or draft already uses one stops at
// the migration, naming the rule, rather than have admin take a person's
// rule for an autopilot one. Old versions are not checked: they are not
// served.
func TestMigrationRefusesReservedPrefix(t *testing.T) {
	const reservedFrom = 12
	cases := []struct {
		name  string
		setup []string
		args  [][]any
		want  string // "" means the upgrade succeeds
	}{
		{"a rate-limit rule in the active version",
			[]string{"INSERT INTO config_versions (version, author, message, source, status, config) VALUES (1, 'user:pub', 'v1', 'manual', 'active', $1)"},
			[][]any{{policy("ap-login", "pages")}}, "ap-login"},
		{"a rate-limit rule in the canary version",
			[]string{
				"INSERT INTO config_versions (version, author, message, source, status, config) VALUES (1, 'user:pub', 'v1', 'manual', 'active', $1)",
				"INSERT INTO config_versions (version, author, message, source, status, config) VALUES (2, 'user:pub', 'v2', 'manual', 'canary', $1)",
				"INSERT INTO canary (version, percent, started_at, step_started_at, expires_at) VALUES (2, 10, now(), now(), now() + interval '1 hour')",
			},
			[][]any{{policy("login", "pages")}, {policy("ap-burst", "pages")}, nil}, "ap-burst"},
		{"a config rule in the draft",
			[]string{
				"INSERT INTO config_versions (version, author, message, source, status, config) VALUES (1, 'user:pub', 'v1', 'manual', 'active', $1)",
				"INSERT INTO config_draft (config, base_version, updated_by) VALUES ($1, 1, 'user:pub')",
			},
			[][]any{{policy("login", "pages")}, {policy("login", "ap-mobile")}}, "ap-mobile"},
		{"a request header rule in the active version",
			[]string{"INSERT INTO config_versions (version, author, message, source, status, config) VALUES (1, 'user:pub', 'v1', 'manual', 'active', $1)"},
			[][]any{{withHeaderRule(policy("login", "pages"), "ap-headers")}}, "ap-headers"},
		{"an install without reserved ids upgrades",
			[]string{
				"INSERT INTO config_versions (version, author, message, source, status, config) VALUES (1, 'user:pub', 'v1', 'manual', 'active', $1)",
				"INSERT INTO config_draft (config, base_version, updated_by) VALUES ($1, 1, 'user:pub')",
			},
			[][]any{{policy("login", "pages")}, {policy("login", "pages")}}, ""},
		{"a reserved id only in a superseded version upgrades",
			[]string{
				"INSERT INTO config_versions (version, author, message, source, status, config) VALUES (1, 'user:pub', 'v1', 'manual', 'superseded', $1)",
				"INSERT INTO config_versions (version, author, message, source, status, config) VALUES (2, 'user:pub', 'v2', 'manual', 'active', $1)",
			},
			[][]any{{policy("ap-login", "pages")}, {policy("login", "pages")}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner := migratedBefore(t, reservedFrom)
			ctx := t.Context()
			for i, sql := range tc.setup {
				if _, err := owner.Exec(ctx, sql, tc.args[i]...); err != nil {
					t.Fatalf("setup %d: %v", i, err)
				}
			}
			err := Migrate(ctx, owner, testenv.AppRole)
			var applied bool
			if qerr := owner.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", reservedFrom).Scan(&applied); qerr != nil {
				t.Fatal(qerr)
			}
			if tc.want == "" {
				if err != nil || !applied {
					t.Fatalf("upgrade: err %v, migration %d applied %v", err, reservedFrom, applied)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "rename") || applied {
				t.Fatalf("err %v, migration %d applied %v; want a refusal naming %s and saying to rename it", err, reservedFrom, applied, tc.want)
			}
		})
	}
}
