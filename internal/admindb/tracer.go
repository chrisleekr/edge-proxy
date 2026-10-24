package admindb

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// QueryTracer records one client span per query, but only inside a request
// that is already traced: background jobs would otherwise start a trace per
// query. Statements use placeholders, so recording the text records no
// values; arguments and error messages, which can quote values, are not
// recorded.
type QueryTracer struct{ Tracer trace.Tracer }

// spanKey carries the query's span from start to end, so a query outside
// a trace never ends the request's own span.
type spanKey struct{}

func (q QueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if !trace.SpanFromContext(ctx).IsRecording() {
		return ctx
	}
	ctx, span := q.Tracer.Start(ctx, operation(d.SQL), trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(
		attribute.String("db.system.name", "postgresql"),
		attribute.String("db.query.text", d.SQL),
	))
	return context.WithValue(ctx, spanKey{}, span)
}

func (QueryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	span, ok := ctx.Value(spanKey{}).(trace.Span)
	if !ok {
		return
	}
	if d.Err != nil {
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

// operation names the span by the statement's first keyword, as OTel
// database conventions name spans by operation.
func operation(sql string) string {
	if f := strings.Fields(sql); len(f) > 0 {
		return strings.ToUpper(f[0])
	}
	return "postgresql"
}
