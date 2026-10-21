package admin

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

// bootstrapActor names automated first-start changes in the audit log.
const bootstrapActor = "bootstrap"

// bootstrap does the first-start steps the deployment asked for. Each step
// checks and acts under the lock that guards it, so replicas starting
// together do it once, and it never touches data that already exists.
func bootstrap(ctx context.Context, db *pgxpool.Pool, s *Server, log *slog.Logger) error {
	if s.cfg.BootstrapUser != "" {
		created := false
		err := dbProblem(pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", userAdminLock); err != nil {
				return err
			}
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users)").Scan(&exists); err != nil || exists {
				return err
			}
			created = true
			_, err := insertUser(ctx, tx, s.cfg, s.now, bootstrapActor, s.cfg.BootstrapUser, "", s.cfg.BootstrapPassword, []string{"admin"})
			return err
		}))
		if err != nil {
			return err
		}
		if created {
			log.Info("bootstrap created the first admin", "username", s.cfg.BootstrapUser)
		}
	}
	if s.cfg.BootstrapPublish {
		var v int64
		err := dbProblem(pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", publishLock); err != nil {
				return err
			}
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM config_versions)").Scan(&exists); err != nil || exists {
				return err
			}
			var err error
			v, err = s.publishTx(ctx, tx, &principal{actor: bootstrapActor}, publishReq{config: snapshot.Starter(), tests: []ConfigTest{},
				message: "Starter policy, published at first start", source: "manual"})
			return err
		}))
		if err != nil {
			return err
		}
		if v != 0 {
			log.Info("bootstrap published the starter policy", "version", v)
		}
	}
	return nil
}
