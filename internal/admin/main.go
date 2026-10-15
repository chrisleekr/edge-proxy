package admin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
)

// Main runs one admin command and returns the process exit code.
func Main(ctx context.Context, ui fs.FS, args []string, getenv func(string) string, stdin io.Reader, out io.Writer) int {
	log := slog.New(slog.NewJSONHandler(out, nil))
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "migrate":
		err = migrate(ctx, getenv)
	case "serve":
		err = serve(ctx, ui, getenv, log)
	case "create-user":
		err = createUser(ctx, args, getenv, stdin, out)
	default:
		err = fmt.Errorf("unknown command %q; use serve, migrate or create-user", cmd)
	}
	if err != nil {
		log.Error("admin failed", "command", cmd, "error", err.Error())
		return 1
	}
	return 0
}

// migrate runs as the owner role (MIGRATION_DATABASE_URL) and grants
// DB_RUNTIME_ROLE its limited access.
func migrate(ctx context.Context, getenv func(string) string) error {
	url, role := getenv("MIGRATION_DATABASE_URL"), getenv("DB_RUNTIME_ROLE")
	if url == "" || role == "" {
		return errors.New("MIGRATION_DATABASE_URL and DB_RUNTIME_ROLE are required")
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connect: %w", noURL(err))
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	return admindb.Migrate(ctx, conn, role)
}

// noURL replaces pgx's parse errors, which quote the connection string;
// pgx redacts the password only on a best-effort basis.
func noURL(err error) error {
	if _, ok := errors.AsType[*pgconn.ParseConfigError](err); ok {
		return errors.New("invalid connection string")
	}
	return err
}

func serve(ctx context.Context, ui fs.FS, getenv func(string) string, log *slog.Logger) error {
	cfg, err := LoadConfig(getenv)
	if err != nil {
		return err
	}
	cfg.UI = ui
	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database: %w", noURL(err))
	}
	defer db.Close()
	l, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	log.Info("admin listening", "addr", l.Addr().String())
	return NewServer(cfg, db, log).Serve(ctx, l)
}

// createUser bootstraps a user, typically the first admin; the password is
// read from the first line of stdin so it never appears in shell history.
func createUser(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, out io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: admin create-user <username> <role> [role ...]")
	}
	cfg, err := LoadConfig(getenv)
	if err != nil {
		return err
	}
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database: %w", noURL(err))
	}
	defer db.Close()
	id, err := CreateUser(ctx, db, cfg, "cli", args[0], "", strings.TrimRight(line, "\r\n"), args[1:])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "created user %s (%s)\n", args[0], id)
	return err
}
