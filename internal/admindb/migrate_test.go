package admindb

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

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
	if err := app.QueryRow(t.Context(), "SELECT count(*) FROM role_permissions WHERE role = 'admin'").Scan(&n); err != nil || n != 11 {
		t.Fatalf("admin has %d permissions, %v", n, err)
	}
}
