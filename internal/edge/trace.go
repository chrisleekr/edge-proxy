package edge

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// traceProp reads and writes W3C traceparent and tracestate only.
var traceProp = propagation.TraceContext{}

// stdMethods are the methods OTel HTTP semantic conventions name spans by.
// Any other method is client-chosen and would make span names unbounded.
var stdMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true,
	"CONNECT": true, "OPTIONS": true, "TRACE": true, "PATCH": true,
}

// startSpan starts the request's server span once the peer's trust is
// known. Only a trusted, identified peer's trace context is joined (join);
// anyone else's is ignored and the trace restarts here.
func (e *Edge) startSpan(st *reqState, r *http.Request, join bool) {
	if e.tracer == nil {
		return
	}
	ctx := context.Background()
	if join {
		ctx = traceProp.Extract(ctx, propagation.HeaderCarrier(r.Header))
	}
	name := r.Method
	if !stdMethods[name] {
		name = "HTTP"
	}
	st.tctx, st.span = e.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindServer), trace.WithTimestamp(st.start))
}

// endSpan records the request's outcome with the access log's field names.
func endSpan(st *reqState, r *http.Request, decision string) {
	if st.span == nil {
		return
	}
	if st.span.IsRecording() {
		// One SetAttributes call: each call allocates its argument slice.
		var buf [12]attribute.KeyValue
		attrs := buf[:0]
		method := r.Method
		if !stdMethods[method] {
			attrs = append(attrs, attribute.String("http.request.method_original", method))
			method = "_OTHER"
		}
		attrs = append(attrs,
			attribute.String("http.request.method", method),
			attribute.String("server.address", hostOnly(r.Host)),
			attribute.String("url.path", st.fields.path),
			attribute.Int("http.response.status_code", st.sw.status),
			attribute.String("request_id", st.requestID),
			attribute.String("edge.decision", decision),
		)
		if st.client.ip.IsValid() {
			attrs = append(attrs, attribute.String("client.address", st.client.ip.String()))
		}
		if st.ver != nil {
			attrs = append(attrs, attribute.Int64("edge.config_version", st.ver.c.Config.Version), attribute.String("edge.cohort", st.cohort))
		}
		if st.rlRule != "" {
			attrs = append(attrs, attribute.String("edge.rate_limit_rule", st.rlRule))
		}
		if a := authNames[st.auth]; a != "" {
			attrs = append(attrs, attribute.String("edge.auth", a))
		}
		st.span.SetAttributes(attrs...)
		// OTel HTTP server spans are errors on 5xx only; 4xx is the client's.
		if st.sw.status >= 500 {
			st.span.SetStatus(codes.Error, "")
		}
	}
	st.span.End()
}

// injectTrace replaces any incoming trace context with the edge span's,
// so the upstream's spans become its children.
func injectTrace(st *reqState, h http.Header) {
	if st.span == nil {
		return
	}
	delete(h, "Traceparent")
	delete(h, "Tracestate")
	traceProp.Inject(st.tctx, propagation.HeaderCarrier(h))
}
