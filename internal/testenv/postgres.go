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
const PostgresImage = "postgres:18.6"

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
)

// DB is a fresh, empty database: DSNs for its owner and app roles.
type DB struct{ Owner, App string }

// Postgres returns a new database in the process-wide Postgres container,
// so tests never share tables.
func Postgres(t testing.TB) DB {
	t.Helper()
	pgOnce.Do(func() { pgHost, pgErr = startPostgres(context.Background()) }) //nolint:usetesting // the container is process-wide and outlives this test
	if pgErr != nil {
		t.Fatalf("start postgres: %v", pgErr)
	}
	name := fmt.Sprintf("t%d_%d", time.Now().UnixNano(), pgSeq.Add(1))
	ctx := t.Context()
	su, err := pgx.Connect(ctx, dsn("postgres", "postgres", "postgres"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = su.Close(ctx) }()
	for _, q := range []string{
		"CREATE DATABASE " + name + " OWNER " + OwnerRole,
		"REVOKE ALL ON DATABASE " + name + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + name + " TO " + AppRole,
	} {
		if _, err := su.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return DB{Owner: dsn(OwnerRole, "owner", name), App: dsn(AppRole, "app", name)}
}

func dsn(user, password, db string) string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", user, password, pgHost, db)
}

func startPostgres(ctx context.Context) (string, error) {
	c, err := testcontainers.Run(ctx, PostgresImage,
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithEnv(map[string]string{"POSTGRES_PASSWORD": "postgres"}),
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
