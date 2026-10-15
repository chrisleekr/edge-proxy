package admindb

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

var testKeys = AuditKeys{Current: "k1", Keys: map[string][]byte{"k1": []byte("0123456789abcdef0123456789abcdef")}, Order: []string{"k1"}}

func audit(t *testing.T, c *pgx.Conn, e Event) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), c, func(tx pgx.Tx) error { return Audit(t.Context(), tx, testKeys, e) }); err != nil {
		t.Fatal(err)
	}
}

func verify(t *testing.T, c *pgx.Conn) (int64, error) {
	t.Helper()
	seq, _, err := VerifyAudit(t.Context(), c, testKeys, 0, nil)
	return seq, err
}

// Rows verify after a round trip through Postgres, whatever the details hold.
func TestAuditChainVerifies(t *testing.T) {
	_, app := migrated(t)
	audit(t, app, Event{Actor: "user:alice", Action: "config.save", Target: "draft", Details: map[string]any{"z": 1, "a": []any{"x", 2.50, nil}, "n": 1e21, "html": "<b>&"}})
	audit(t, app, Event{Actor: "system:guard", Action: "guard.decision", Details: nil})
	audit(t, app, Event{Actor: "user:bob", Action: "login.failure", Details: struct {
		IP string `json:"ip"`
	}{"203.0.113.9"}})
	if seq, err := verify(t, app); err != nil || seq != 3 {
		t.Fatalf("verify = %d, %v", seq, err)
	}
	// Verification continues where the last run stopped.
	seq, mac, _ := VerifyAudit(t.Context(), app, testKeys, 0, nil)
	audit(t, app, Event{Actor: "user:bob", Action: "logout"})
	if seq, _, err := VerifyAudit(t.Context(), app, testKeys, seq, mac); err != nil || seq != 4 {
		t.Fatalf("incremental verify = %d, %v", seq, err)
	}
}

// A rolled-back change leaves no audit row: they share the transaction.
func TestAuditRollsBackWithTheChange(t *testing.T) {
	_, app := migrated(t)
	ctx := t.Context()
	err := pgx.BeginFunc(ctx, app, func(tx pgx.Tx) error {
		if err := Audit(ctx, tx, testKeys, Event{Actor: "user:alice", Action: "settings.save"}); err != nil {
			return err
		}
		return errors.New("the change failed")
	})
	var n int
	_ = app.QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&n)
	if err == nil || n != 0 {
		t.Fatalf("rows after rollback = %d", n)
	}
}

// Concurrent changes still form one gapless chain.
func TestAuditConcurrentInserts(t *testing.T) {
	db := testenv.Postgres(t)
	owner := connect(t, db.Owner)
	if err := Migrate(t.Context(), owner, testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(t.Context(), db.App)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
				return Audit(t.Context(), tx, testKeys, Event{Actor: "user:x", Action: "config.save"})
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if seq, _, err := VerifyAudit(t.Context(), pool, testKeys, 0, nil); err != nil || seq != 20 {
		t.Fatalf("verify = %d, %v", seq, err)
	}
}

// Someone with owner or superuser access edits rows directly; the chain
// shows where.
func TestAuditTamperingIsDetected(t *testing.T) {
	cases := []struct {
		name   string
		tamper string
		seq    int64
		reason string
	}{
		{"edited action", "UPDATE audit_events SET action = 'config.read' WHERE seq = 2", 2, "hmac mismatch"},
		{"edited details", `UPDATE audit_events SET details = '{"limit":1000}' WHERE seq = 2`, 2, "hmac mismatch"},
		{"deleted middle row", "DELETE FROM audit_events WHERE seq = 2", 2, "row missing"},
		{"row re-signed with a key not in deployment secrets", "UPDATE audit_events SET key_id = 'k0' WHERE seq = 3", 3, "unknown key id"},
		{"forged row appended", `INSERT INTO audit_events (seq, occurred_at, actor, action, key_id, hmac)
			VALUES (4, now(), 'user:mallory', 'config.publish', 'k1', decode(repeat('00', 32), 'hex'))`, 4, "hmac mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			owner, app := migrated(t)
			for _, a := range []string{"config.save", "config.publish", "logout"} {
				audit(t, app, Event{Actor: "user:alice", Action: a, Details: map[string]any{"limit": 10}})
			}
			ctx := t.Context()
			// The owner can disable its own table's triggers.
			for _, q := range []string{"ALTER TABLE audit_events DISABLE TRIGGER USER", tc.tamper} {
				if _, err := owner.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			_, err := verify(t, app)
			var b *ChainBreak
			if !errors.As(err, &b) || b.Seq != tc.seq || b.Reason[:len(tc.reason)] != tc.reason {
				t.Fatalf("err = %v, want break at %d: %s", err, tc.seq, tc.reason)
			}
		})
	}
}

// Rotating the key keeps older rows verifiable with the old key.
func TestAuditKeyRotation(t *testing.T) {
	_, app := migrated(t)
	audit(t, app, Event{Actor: "user:alice", Action: "a"})
	rotated := AuditKeys{Current: "k2", Keys: map[string][]byte{"k1": testKeys.Keys["k1"], "k2": []byte("another 32-byte key for the chain")}, Order: []string{"k1", "k2"}}
	if err := pgx.BeginFunc(t.Context(), app, func(tx pgx.Tx) error {
		return Audit(t.Context(), tx, rotated, Event{Actor: "user:alice", Action: "b"})
	}); err != nil {
		t.Fatal(err)
	}
	if seq, _, err := VerifyAudit(t.Context(), app, rotated, 0, nil); err != nil || seq != 2 {
		t.Fatalf("verify = %d, %v", seq, err)
	}
}

func TestAuditDetailsMustBeJSON(t *testing.T) {
	_, app := migrated(t)
	err := pgx.BeginFunc(t.Context(), app, func(tx pgx.Tx) error {
		return Audit(t.Context(), tx, testKeys, Event{Actor: "user:alice", Action: "a", Details: func() {}})
	})
	if err == nil {
		t.Fatal("unencodable details accepted")
	}
}

// Review findings: each is a way to alter the chain without detection.
func TestAuditIntegrityGaps(t *testing.T) {
	ctx := t.Context()
	tamper := func(t *testing.T, owner *pgx.Conn, sql string) {
		t.Helper()
		for _, q := range []string{"ALTER TABLE audit_events DISABLE TRIGGER USER", sql} {
			if _, err := owner.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("a large number changed to one with the same float64", func(t *testing.T) {
		owner, app := migrated(t)
		audit(t, app, Event{Actor: "user:alice", Action: "a", Details: map[string]any{"n": json.Number("9007199254740993")}})
		tamper(t, owner, `UPDATE audit_events SET details = '{"n": 9007199254740992}'`)
		if _, err := verify(t, app); err == nil {
			t.Fatal("edit not detected")
		}
	})
	t.Run("rows already verified are later deleted", func(t *testing.T) {
		owner, app := migrated(t)
		for range 3 {
			audit(t, app, Event{Actor: "user:alice", Action: "a"})
		}
		seq, mac, err := VerifyAudit(ctx, app, testKeys, 0, nil)
		if err != nil || seq != 3 {
			t.Fatal(seq, err)
		}
		tamper(t, owner, "DELETE FROM audit_events WHERE seq >= 2")
		var b *ChainBreak
		if _, _, err := VerifyAudit(ctx, app, testKeys, seq, mac); !errors.As(err, &b) || b.Seq != 3 {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a new row signed with a retired key", func(t *testing.T) {
		_, app := migrated(t)
		rotated := AuditKeys{Current: "k2", Keys: map[string][]byte{"k1": testKeys.Keys["k1"], "k2": []byte("another 32-byte key for the chain")}, Order: []string{"k1", "k2"}}
		for _, k := range []AuditKeys{rotated, testKeys} { // k2 row, then a forged k1 row
			if err := pgx.BeginFunc(ctx, app, func(tx pgx.Tx) error { return Audit(ctx, tx, k, Event{Actor: "user:x", Action: "a"}) }); err != nil {
				t.Fatal(err)
			}
		}
		var b *ChainBreak
		if _, _, err := VerifyAudit(ctx, app, rotated, 0, nil); !errors.As(err, &b) || b.Seq != 2 {
			t.Fatalf("err = %v", err)
		}
	})
}
