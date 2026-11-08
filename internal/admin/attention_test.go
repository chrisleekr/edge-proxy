package admin

import (
	"strings"
	"testing"
	"time"
)

func auditCount(t *testing.T, h *harness, action string) int {
	t.Helper()
	var n int
	if err := h.db.QueryRow(t.Context(), "SELECT count(*) FROM audit_events WHERE action = $1", action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func ackRows(t *testing.T, c *client) []attentionAck {
	t.Helper()
	return decode[[]attentionAck](t, c.do("GET", "/api/attention/acks", nil))
}

// An ack hides a dashboard item for the whole team; it is audited, and
// clearing it is audited once however many dashboards report it.
func TestAttentionAcks(t *testing.T) {
	setup := func(t *testing.T) (*harness, *client, *client) {
		t.Helper()
		h := newHarness(t)
		h.user("ed", "editor")
		h.user("vera", "viewer")
		return h, h.signedIn("ed"), h.signedIn("vera")
	}
	ack := map[string]any{"key": "shadow:login", "summary": "Rule login is over its limit"}

	t.Run("an editor acks and a viewer sees who and when", func(t *testing.T) {
		h, ed, vera := setup(t)
		status(t, ed.do("POST", "/api/attention/acks", ack), 200)
		got := ackRows(t, vera)
		if len(got) != 1 || got[0].Key != "shadow:login" || got[0].Actor != "user:ed" || got[0].Summary != ack["summary"] || !got[0].AckedAt.Equal(h.now()) {
			t.Fatalf("acks %+v", got)
		}
		if n := auditCount(t, h, "attention.ack"); n != 1 {
			t.Fatalf("%d ack audit rows", n)
		}
	})
	t.Run("the audit row names the item and is written with the change", func(t *testing.T) {
		h, ed, _ := setup(t)
		status(t, ed.do("POST", "/api/attention/acks", ack), 200)
		status(t, ed.do("DELETE", "/api/attention/acks?key=shadow:login&reason=undo", nil), 204)
		var target, details string
		if err := h.db.QueryRow(t.Context(), "SELECT target, details::text FROM audit_events WHERE action = 'attention.undo'").Scan(&target, &details); err != nil ||
			target != ack["summary"] || !strings.Contains(details, "shadow:login") {
			t.Fatalf("undo row %q %q %v", target, details, err)
		}
		if got := ackRows(t, ed); len(got) != 0 {
			t.Fatalf("acks after undo %+v", got)
		}
	})
	t.Run("a viewer cannot ack or undo", func(t *testing.T) {
		h, ed, vera := setup(t)
		status(t, vera.do("POST", "/api/attention/acks", ack), 403)
		status(t, ed.do("POST", "/api/attention/acks", ack), 200)
		status(t, vera.do("DELETE", "/api/attention/acks?key=shadow:login&reason=undo", nil), 403)
		if got := ackRows(t, ed); len(got) != 1 || auditCount(t, h, "attention.undo") != 0 {
			t.Fatalf("acks %+v", got)
		}
	})
	t.Run("a bad key or a long summary is refused and nothing is saved", func(t *testing.T) {
		h, ed, _ := setup(t)
		for name, in := range map[string]map[string]any{
			"empty key":      {"key": "", "summary": "x"},
			"bad characters": {"key": "Shadow login", "summary": "x"},
			"long key":       {"key": "shadow:" + strings.Repeat("a", 200), "summary": "x"},
			"no summary":     {"key": "valkey", "summary": ""},
			"long summary":   {"key": "valkey", "summary": strings.Repeat("가", 501)},
		} {
			if resp := ed.do("POST", "/api/attention/acks", in); resp.StatusCode != 422 {
				t.Errorf("%s: status %d", name, resp.StatusCode)
			}
		}
		if got := ackRows(t, ed); len(got) != 0 || auditCount(t, h, "attention.ack") != 0 {
			t.Fatalf("saved %+v", got)
		}
	})
	t.Run("acking a key again changes nothing", func(t *testing.T) {
		h, ed, _ := setup(t)
		status(t, ed.do("POST", "/api/attention/acks", ack), 200)
		h.advance(time.Minute)
		second := ed.do("POST", "/api/attention/acks", map[string]any{"key": "shadow:login", "summary": "other words"})
		if got := decode[attentionAck](t, second); got.Summary != ack["summary"] {
			t.Fatalf("second ack %+v", got)
		}
		if n := auditCount(t, h, "attention.ack"); n != 1 {
			t.Fatalf("%d ack audit rows", n)
		}
	})
	t.Run("clearing twice writes one audit row", func(t *testing.T) {
		h, ed, _ := setup(t)
		status(t, ed.do("POST", "/api/attention/acks", ack), 200)
		for range 2 {
			status(t, ed.do("DELETE", "/api/attention/acks?key=shadow:login&reason=cleared", nil), 204)
		}
		if n := auditCount(t, h, "attention.cleared"); n != 1 {
			t.Fatalf("%d cleared audit rows", n)
		}
		status(t, ed.do("DELETE", "/api/attention/acks?key=shadow:login&reason=other", nil), 422)
		status(t, ed.do("DELETE", "/api/attention/acks?key=Bad%20Key&reason=undo", nil), 422)
		status(t, ed.do("DELETE", "/api/attention/acks?reason=undo", nil), 422)
	})
	t.Run("the 501st ack is refused", func(t *testing.T) {
		h, ed, _ := setup(t)
		if _, err := h.owner.Exec(t.Context(), "INSERT INTO attention_acks (key, summary, actor) SELECT 'anomaly:' || g, 'x', 'user:ed' FROM generate_series(1, 500) g"); err != nil {
			t.Fatal(err)
		}
		status(t, ed.do("POST", "/api/attention/acks", ack), 409)
		// An ack already held is still returned at the cap.
		status(t, ed.do("POST", "/api/attention/acks", map[string]any{"key": "anomaly:1", "summary": "x"}), 200)
		if n := auditCount(t, h, "attention.ack"); n != 0 {
			t.Fatalf("%d ack audit rows", n)
		}
	})
}
