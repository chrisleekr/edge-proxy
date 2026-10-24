package admindb

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/chrisleekr/edge-proxy/internal/testenv"
)

// tracedPool is the runtime role's pool with the query tracer, recording
// every ended span.
func tracedPool(t *testing.T) (*pgxpool.Pool, *tracetest.SpanRecorder, trace.Tracer) {
	t.Helper()
	db := testenv.Postgres(t)
	if err := Migrate(t.Context(), connect(t, db.Owner), testenv.AppRole); err != nil {
		t.Fatal(err)
	}
	rec := tracetest.NewSpanRecorder()
	tr := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)).Tracer("test")
	c, err := pgxpool.ParseConfig(db.App)
	if err != nil {
		t.Fatal(err)
	}
	c.ConnConfig.Tracer = QueryTracer{Tracer: tr}
	pool, err := pgxpool.NewWithConfig(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, rec, tr
}

// Background jobs query outside any request and start no traces.
func TestQueryOutsideARequestIsNotTraced(t *testing.T) {
	pool, rec, _ := tracedPool(t)
	if _, err := pool.Exec(t.Context(), "SELECT count(*) FROM audit_events"); err != nil {
		t.Fatal(err)
	}
	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("%d spans outside a request", n)
	}
}

// The runtime role can't delete audit rows. The refused query is an error
// span without Postgres's message, which can quote values.
func TestRefusedQuerySpanCarriesNoMessage(t *testing.T) {
	pool, rec, tr := tracedPool(t)
	ctx, req := tr.Start(t.Context(), "request")
	_, err := pool.Exec(ctx, "DELETE FROM audit_events")
	req.End()
	if err == nil {
		t.Fatal("runtime role deleted audit rows")
	}
	for _, s := range rec.Ended() {
		if s.Name() == "DELETE" {
			if s.Status().Code != codes.Error || s.Status().Description != "" || len(s.Events()) != 0 || s.Parent().SpanID() != req.SpanContext().SpanID() {
				t.Fatalf("status %+v, events %v, parent %v", s.Status(), s.Events(), s.Parent())
			}
			return
		}
	}
	t.Fatal("no span for the refused delete")
}
