package testenv

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PostgresImage matches compose.yaml.
const PostgresImage = "postgres:19.0"

// Roles every test database uses, as in a deployment: the
// owner runs migrations, the app role is what admin connects as.
const (
	OwnerRole = "edge_owner"
	AppRole   = "edge_app"
)

var (
	pgOnce sync.Once
	pgHost string
	pgErr  error
	pgSeq  atomic.Int64

	tplOnce sync.Once
	tplName string
	tplErr  error
)

// DB is a fresh database: DSNs for its owner and app roles.
type DB struct{ Owner, App string }

// Postgres returns a new empty database in the process-wide Postgres container,
// so tests never share tables.
func Postgres(t testing.TB) DB {
	t.Helper()
	startOnce(t)
	db, err := createDB(t.Context(), newName(), "")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// Migrated returns a new database copied from a template that migrate has
// already run on, which is cheaper than migrating every database. The first
// call in the process builds the template, so every caller must pass the same
// migration.
func Migrated(t testing.TB, migrate func(context.Context, *pgx.Conn) error) DB {
	t.Helper()
	startOnce(t)
	// Errors are stored, not fatal: a Goexit inside Do would mark it done with no template.
	tplOnce.Do(func() { tplName, tplErr = buildTemplate(context.Background(), migrate) }) //nolint:usetesting // the template is process-wide and outlives this test
	if tplErr != nil {
		t.Fatalf("migrate template: %v", tplErr)
	}
	db, err := createDB(t.Context(), newName(), tplName)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func startOnce(t testing.TB) {
	t.Helper()
	pgOnce.Do(func() { pgHost, pgErr = startPostgres(context.Background()) }) //nolint:usetesting // the container is process-wide and outlives this test
	if pgErr != nil {
		t.Fatalf("start postgres: %v", pgErr)
	}
}

// buildTemplate migrates one database and closes its connection, because
// Postgres refuses to copy a template that has any open connection.
func buildTemplate(ctx context.Context, migrate func(context.Context, *pgx.Conn) error) (string, error) {
	name := newName()
	db, err := createDB(ctx, name, "")
	if err != nil {
		return "", err
	}
	c, err := pgx.Connect(ctx, db.Owner)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close(ctx) }()
	if err := migrate(ctx, c); err != nil {
		return "", err
	}
	return name, nil
}

func newName() string { return fmt.Sprintf("t%d_%d", time.Now().UnixNano(), pgSeq.Add(1)) }

// createDB makes a database owned by OwnerRole, optionally copied from a
// template, that only the app role may connect to besides its owner.
func createDB(ctx context.Context, name, template string) (DB, error) {
	su, err := pgx.Connect(ctx, dsn("postgres", "postgres", "postgres"))
	if err != nil {
		return DB{}, err
	}
	defer func() { _ = su.Close(ctx) }()
	create := "CREATE DATABASE " + name + " OWNER " + OwnerRole
	if template != "" {
		create += " TEMPLATE " + template
	}
	for _, q := range []string{
		create,
		"REVOKE ALL ON DATABASE " + name + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + name + " TO " + AppRole,
	} {
		if _, err := su.Exec(ctx, q); err != nil {
			return DB{}, err
		}
	}
	return DB{Owner: dsn(OwnerRole, "owner", name), App: dsn(AppRole, "app", name)}, nil
}

func dsn(user, password, db string) string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", user, password, pgHost, db)
}

func startPostgres(ctx context.Context) (string, error) {
	c, err := testcontainers.Run(ctx, PostgresImage,
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithEnv(map[string]string{"POSTGRES_PASSWORD": "postgres"}),
		// Test data is thrown away, so flushing it to disk only slows tests and
		// competes with the host's other writers.
		testcontainers.WithCmd("postgres", "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"),
		// The image starts a temporary server for init scripts first, so
		// the ready line appears twice.
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(time.Minute)),
	)
	if err != nil {
		return "", err
	}
	host, err := hostOf(ctx, c)
	if err != nil {
		return "", err
	}
	p, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return "", err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(p.Num())))
	su, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:postgres@%s/postgres?sslmode=disable", addr))
	if err != nil {
		return "", err
	}
	defer func() { _ = su.Close(ctx) }()
	for _, q := range []string{
		"CREATE ROLE " + OwnerRole + " LOGIN PASSWORD 'owner'",
		"CREATE ROLE " + AppRole + " LOGIN PASSWORD 'app'",
	} {
		if _, err := su.Exec(ctx, q); err != nil {
			return "", err
		}
	}
	return addr, nil
}
