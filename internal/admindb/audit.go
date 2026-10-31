package admindb

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// auditLock serializes chain inserts; volume is low.
const auditLock = 0x61756474 // "audt"

// AuditKeys signs and verifies the chain. The keys live in deployment
// secrets, never in Postgres. Older keys stay for verifying older rows.
type AuditKeys struct {
	Current string
	Keys    map[string][]byte
	// Order lists key IDs oldest first, ending with Current. A row may not
	// use a key older than the row before it, so a leaked retired key can't
	// sign new rows.
	Order []string
}

func (k AuditKeys) rank(id string) int { return slices.Index(k.Order, id) }

// Event is one audit row's content. Details must never hold secrets, only
// their IDs.
type Event struct {
	Actor   string
	Action  string
	Target  string
	Details any
}

// Querier reads rows; *pgx.Conn, pgx.Tx and pools satisfy it.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// LockAudit takes the lock Audit takes, for a transaction that must hold
// it before the row locks it takes next. It is released at commit.
func LockAudit(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditLock)
	return err
}

// Audit appends e in tx, the transaction of the change it records, so no
// change commits without its row. now is the caller's clock (admin's, which
// tests freeze); it is read under the lock, so times follow seq.
// The advisory lock is released at commit.
func Audit(ctx context.Context, tx pgx.Tx, k AuditKeys, now func() time.Time, e Event) error {
	details, err := json.Marshal(e.Details)
	if err != nil {
		return fmt.Errorf("audit details: %w", err)
	}
	if e.Details == nil {
		details = []byte("{}")
	}
	if err := LockAudit(ctx, tx); err != nil {
		return err
	}
	var seq int64
	prev := make([]byte, sha256.Size)
	err = tx.QueryRow(ctx, "SELECT seq, hmac FROM audit_events ORDER BY seq DESC LIMIT 1").Scan(&seq, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	r := auditRow{Seq: seq + 1, OccurredAt: now().UTC().Truncate(time.Microsecond), Actor: e.Actor, Action: e.Action, Target: e.Target, Details: details, KeyID: k.Current}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events (seq, occurred_at, actor, action, target, details, key_id, hmac)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		r.Seq, r.OccurredAt, r.Actor, r.Action, r.Target, string(details), r.KeyID, r.sign(k.Keys[k.Current], prev))
	return err
}

// auditRow is what the HMAC covers: every column but the HMAC itself.
type auditRow struct {
	Seq        int64     `json:"seq"`
	OccurredAt time.Time `json:"occurred_at"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Target     string    `json:"target"`
	KeyID      string    `json:"key_id"`
	// Details are signed as stored, byte for byte: the json column keeps
	// the exact text, and re-encoding would hide edits that encode alike.
	Details []byte `json:"-"`
}

// sign is HMAC-SHA256(key, prev ‖ row JSON ‖ 0x00 ‖ details). The row JSON
// can't contain a NUL byte, so the split is unambiguous.
func (r *auditRow) sign(key, prev []byte) []byte {
	b, _ := json.Marshal(r) // fixed struct of marshalable fields
	m := hmac.New(sha256.New, key)
	m.Write(prev)
	m.Write(b)
	m.Write([]byte{0})
	m.Write(r.Details)
	return m.Sum(nil)
}

// ChainBreak is where verification found the chain altered.
type ChainBreak struct {
	Seq    int64
	Reason string
}

func (b *ChainBreak) Error() string {
	return fmt.Sprintf("audit chain broken at seq %d: %s", b.Seq, b.Reason)
}

// VerifyAudit checks rows after seq `from`, whose HMAC is prev (nil and 0 to
// start at the beginning). It returns the last verified seq and HMAC, so
// the next run continues from there, or a *ChainBreak.
func VerifyAudit(ctx context.Context, q Querier, k AuditKeys, from int64, prev []byte) (int64, []byte, error) {
	if prev == nil {
		prev = make([]byte, sha256.Size)
	}
	rank := 0
	if from > 0 {
		// The last verified row must still be there, unchanged: otherwise
		// deleting the newest rows would go unnoticed.
		var mac []byte
		var keyID string
		err := q.QueryRow(ctx, "SELECT hmac, key_id FROM audit_events WHERE seq = $1", from).Scan(&mac, &keyID)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !bytes.Equal(mac, prev) {
			return from, prev, &ChainBreak{Seq: from, Reason: "verified row missing or changed"}
		}
		if err != nil {
			return from, prev, err
		}
		rank = k.rank(keyID)
	}
	rows, err := q.Query(ctx, `SELECT seq, occurred_at, actor, action, target, details::text, key_id, hmac
		FROM audit_events WHERE seq > $1 ORDER BY seq`, from)
	if err != nil {
		return from, prev, err
	}
	defer rows.Close()
	last := from
	for rows.Next() {
		var r auditRow
		var details string
		var mac []byte
		if err := rows.Scan(&r.Seq, &r.OccurredAt, &r.Actor, &r.Action, &r.Target, &details, &r.KeyID, &mac); err != nil {
			return last, prev, err
		}
		r.OccurredAt = r.OccurredAt.UTC()
		r.Details = []byte(details)
		if r.Seq != last+1 {
			return last, prev, &ChainBreak{Seq: last + 1, Reason: "row missing"}
		}
		key, ok := k.Keys[r.KeyID]
		if !ok {
			return last, prev, &ChainBreak{Seq: r.Seq, Reason: fmt.Sprintf("unknown key id %q", r.KeyID)}
		}
		if k.rank(r.KeyID) < rank {
			return last, prev, &ChainBreak{Seq: r.Seq, Reason: fmt.Sprintf("key %q was retired before this row", r.KeyID)}
		}
		if !hmac.Equal(r.sign(key, prev), mac) {
			return last, prev, &ChainBreak{Seq: r.Seq, Reason: "hmac mismatch"}
		}
		last, prev, rank = r.Seq, mac, k.rank(r.KeyID)
	}
	return last, prev, rows.Err()
}
