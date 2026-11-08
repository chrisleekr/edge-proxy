package admin

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/chrisleekr/edge-proxy/internal/admindb"
	"github.com/chrisleekr/edge-proxy/internal/expr"
)

// maxAcks bounds the table: the dashboard has far fewer items at once, and
// the UI deletes an ack when its condition clears.
const maxAcks = 500

// errNoAudit ends a change that has nothing to record; the transaction
// rolls back and the caller treats it as done.
var errNoAudit = errors.New("nothing changed")

var ackKey = regexp.MustCompile(`^[a-z_]+(:[A-Za-z0-9._-]+)*$`)

// attentionAck is one acknowledged dashboard item. Acking changes nothing
// about traffic or notifications.
type attentionAck struct {
	Key     string    `json:"key"`
	Summary string    `json:"summary"`
	Actor   string    `json:"actor"`
	AckedAt time.Time `json:"acked_at"`
}

func (s *Server) attentionRoutes() {
	s.handle("GET /api/attention/acks", "stats.read", s.listAcks)
	s.handle("POST /api/attention/acks", "attention.ack", s.addAck)
	s.handle("DELETE /api/attention/acks", "attention.ack", s.removeAck)
}

func (s *Server) listAcks(w http.ResponseWriter, r *http.Request, _ *principal) error {
	rows, err := s.db.Query(r.Context(), "SELECT key, summary, actor, acked_at FROM attention_acks ORDER BY acked_at DESC, key")
	if err != nil {
		return err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[attentionAck])
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, orEmpty(list))
}

// addAck is idempotent on key: a second ack returns the first and writes
// no audit row.
func (s *Server) addAck(w http.ResponseWriter, r *http.Request, p *principal) error {
	var in struct {
		Key     string `json:"key"`
		Summary string `json:"summary"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return err
	}
	var errs []expr.Issue
	if !ackKey.MatchString(in.Key) || len(in.Key) > 200 {
		errs = append(errs, expr.Issue{Path: "key", Msg: "is required, at most 200 characters: a lowercase kind, optionally followed by :parts"})
	}
	if n := utf8.RuneCountInString(in.Summary); n == 0 || n > 500 {
		errs = append(errs, expr.Issue{Path: "summary", Msg: "is required, at most 500 characters"})
	}
	if errs != nil {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid acknowledgement", Errors: errs}
	}
	ctx := r.Context()
	var out attentionAck
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		// Serializes acks, so the cap and the existing-key check cannot race.
		if _, err := tx.Exec(ctx, "LOCK TABLE attention_acks IN SHARE ROW EXCLUSIVE MODE"); err != nil {
			return admindb.Event{}, err
		}
		err := tx.QueryRow(ctx, "SELECT key, summary, actor, acked_at FROM attention_acks WHERE key = $1", in.Key).
			Scan(&out.Key, &out.Summary, &out.Actor, &out.AckedAt)
		if err == nil {
			return admindb.Event{}, errNoAudit
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return admindb.Event{}, err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM attention_acks").Scan(&n); err != nil {
			return admindb.Event{}, err
		}
		if n >= maxAcks {
			return admindb.Event{}, fail(http.StatusConflict, fmt.Sprintf("%d items are acknowledged already; undo some first", maxAcks))
		}
		out = attentionAck{Key: in.Key, Summary: in.Summary, Actor: p.actor, AckedAt: s.now()}
		_, err = tx.Exec(ctx, "INSERT INTO attention_acks (key, summary, actor, acked_at) VALUES ($1, $2, $3, $4)", out.Key, out.Summary, out.Actor, out.AckedAt)
		return admindb.Event{Action: "attention.ack", Target: out.Summary, Details: map[string]any{"key": out.Key, "summary": out.Summary}}, err
	})
	if err != nil && !errors.Is(err, errNoAudit) {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// removeAck deletes an ack: undone by a person, or cleared because its
// condition ended. Two dashboards can clear the same ack, so a missing key
// is not an error and writes nothing.
func (s *Server) removeAck(w http.ResponseWriter, r *http.Request, p *principal) error {
	key, reason := r.URL.Query().Get("key"), r.URL.Query().Get("reason")
	if !ackKey.MatchString(key) || len(key) > 200 || (reason != "undo" && reason != "cleared") {
		return &problem{Status: http.StatusUnprocessableEntity, Title: "Invalid acknowledgement", Errors: []expr.Issue{{Path: "key", Msg: "needs a key and a reason of undo or cleared"}}}
	}
	ctx := r.Context()
	err := s.change(ctx, p.actor, func(tx pgx.Tx) (admindb.Event, error) {
		var summary string
		err := tx.QueryRow(ctx, "DELETE FROM attention_acks WHERE key = $1 RETURNING summary", key).Scan(&summary)
		if errors.Is(err, pgx.ErrNoRows) {
			return admindb.Event{}, errNoAudit
		}
		return admindb.Event{Action: "attention." + reason, Target: summary, Details: map[string]any{"key": key, "summary": summary}}, err
	})
	if err != nil && !errors.Is(err, errNoAudit) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
