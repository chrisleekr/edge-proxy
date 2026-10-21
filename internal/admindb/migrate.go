// Package admindb owns the admin Postgres schema: migrations, run as the
// owner role, and the grants that limit the runtime role.
package admindb

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrateLock serializes migrators across admin replicas.
const migrateLock = 0x65646765 // "edge"

// runtimeGrants are everything the runtime role may do. audit_events gets
// only INSERT and SELECT, and config_versions no DELETE: versions are kept
// forever.
var runtimeGrants = []string{
	"GRANT USAGE ON SCHEMA public TO %[1]s",
	"GRANT SELECT ON schema_migrations, roles, role_permissions TO %[1]s",
	"GRANT SELECT, INSERT ON audit_events TO %[1]s",
	"GRANT SELECT, INSERT, UPDATE ON config_versions TO %[1]s",
	"GRANT SELECT, INSERT, UPDATE, DELETE ON users, user_identities, local_credentials, user_roles, group_role_mappings, " +
		"sessions, api_tokens, config_draft, canary, jwks_keys, settings, fleet, edge_stats_minute, " +
		"observed_routes, observed_route_hour, route_patterns TO %[1]s",
	"GRANT USAGE ON SEQUENCE observed_routes_id_seq, route_patterns_id_seq TO %[1]s",
}

// Migrate applies new migrations in order, each in its own transaction,
// then grants the runtime role its permissions. conn must be the owner.
func Migrate(ctx context.Context, conn *pgx.Conn, runtimeRole string) error {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateLock); err != nil {
		return fmt.Errorf("migrate lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrateLock) }()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("migrations table: %w", err)
	}
	files, _ := fs.Glob(migrations, "migrations/*.sql") // the pattern is valid
	for _, f := range files {
		name := strings.TrimPrefix(f, "migrations/")
		v, _ := strconv.Atoi(name[:4]) // TestMigrationNames checks the prefix
		var done bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", v).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sql, _ := migrations.ReadFile(f) // embedded, so it exists
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			// No arguments: pgx sends it with the simple protocol, which
			// allows several statements.
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", v)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	role := pgx.Identifier{runtimeRole}.Sanitize()
	for _, g := range runtimeGrants {
		if _, err := conn.Exec(ctx, fmt.Sprintf(g, role)); err != nil {
			return fmt.Errorf("grant: %w", err)
		}
	}
	return nil
}
