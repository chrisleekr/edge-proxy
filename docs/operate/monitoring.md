# Monitoring

## Edge metrics

Prometheus text at `GET :9090/metrics`, per replica.

| Metric | Meaning |
|---|---|
| `edge_requests_total{class}` | Responses by class (`2xx` … `5xx`; `none` when the client left first) |
| `edge_rejected_total{reason}` | Requests the edge answered itself, by reason: `rate_limited`, `auth`, `backstop`, `overloaded`, `upstream_timeout`, `untrusted_peer`, `path` and others. `upstream_tls` is an https upstream that has no certificate for the request's Host; clients choose the Host, so it is counted without a log line |
| `edge_inflight`, `edge_streams` | Concurrent requests and open WebSocket/SSE streams |
| `edge_ready` | 1 when a policy is loaded and the edge isn't draining |
| `edge_snapshot_version` | Policy version this replica runs |
| `edge_bootstrap_age_seconds` | Non-zero while running from a bootstrap file |
| `edge_snapshot_poll_errors_total`, `edge_snapshot_rejected_total` | Failed polls of admin (unreachable, an error status, or a policy the edge rejected); policies that failed validation on the edge |
| `edge_valkey_errors_total`, `edge_valkey_breaker_open_total` | Valkey call failures; rate-limit calls skipped because a node's breaker was open |
| `edge_auth_total{result}` | `verified`, `cached`, `missing`, `invalid`, `pass_no_keys` |
| `edge_jwks_refresh_total{result}` | JWKS refreshes, `ok` or `error` |
| `edge_ratelimit_rules_capped_total` | Requests matching more rate-limit rules than are evaluated |
| `edge_log_dropped_total`, `edge_stats_dropped_total` | Log lines dropped because the buffer was full; stats reports admin did not accept |
| `edge_background_panics_total` | Recovered panics in background loops |
| `edge_trace_export_errors_total` | Span batches the trace collector did not accept. Spans are dropped, never retried into the request path |
| `edge_trace_capped_total` | Traces not sampled because the replica reached `TRACE_MAX_PER_SECOND` |

`/metrics` has no latency metric. Each edge reports a latency histogram to admin with its stats, which the rollback guard's p99 latency check reads; for SSE and WebSocket it counts the time to response headers. In the admin UI, latency is on **Routes**: p95 and p50 per route, from the access log's `duration_ms`, which for SSE and WebSocket is the stream's whole lifetime. **Stats** shows no latency. You can also measure it at your load balancer.

## Alerts worth having

| Condition | Means | Do |
|---|---|---|
| `edge_ready == 0` on a replica for 2 minutes | No policy loaded | [Edge not ready](runbooks.md#edge-not-ready) |
| `edge_snapshot_version` differs across replicas for 5 minutes | Some edges can't reach admin | [Admin down](runbooks.md#admin-or-postgres-down) |
| `rate(edge_snapshot_poll_errors_total[5m]) > 0` | Admin unreachable; edges keep their policy | [Admin down](runbooks.md#admin-or-postgres-down) |
| `increase(edge_snapshot_rejected_total[10m]) > 0` | An edge refused a policy admin served. Should never happen | Check edge logs, check versions match |
| `rate(edge_valkey_errors_total[5m]) > 0` | Rate limits are on their `fail_mode` | [Valkey down](runbooks.md#valkey-down) |
| `increase(edge_auth_total{result="pass_no_keys"}[10m]) > 0` | Tokens pass unchecked: keys were never fetched | [IdP down](runbooks.md#identity-provider-down) |
| `edge_bootstrap_age_seconds > 0` | Running from a bootstrap file | Restore admin; the edge switches over on its next successful poll |
| `rate(edge_rejected_total{reason=~"overloaded\|streams_overloaded"}[5m]) > 0` | Capacity limits hit | Scale edges or raise `MAX_*` |
| `rate(edge_trace_export_errors_total[5m]) > 0` | Spans are being dropped; traffic is unaffected | Check the collector and the edge's `opentelemetry error` log line, written at most once a minute |
| `increase(edge_background_panics_total[10m]) > 0` or `edge_rejected_total{reason="panic"}` rising | A bug | Collect logs and report it |

## Logs

Both binaries write JSON lines to stdout.

**Edge access log** (`msg: access`): method, host (`server.address`), normalized path, query key names (`edge.query_keys`, and `edge.query_keys_dropped` counting keys not logged because they looked like secrets or were past the first 32), status, `request_id`, `edge.decision` (`allow` or the rejection reason), `duration_ms`, client IP, config version and cohort (`edge.cohort`: `candidate` when the request's client is in the [canary](../use/publishing.md#canary), otherwise `active`), the config rules that matched (`edge.config_rules`), the rate-limit rule that answered 429 (`edge.rate_limit_rule`) and the JWT result (`edge.auth`: `verified`, `cached`, `missing`, `invalid` or `pass_no_keys`). Query values, `Authorization` and `Cookie` are never logged. Rejections and 5xx are always logged; other requests follow `LOG_SAMPLE_RATE`, and when it is below 1 their lines carry it as `edge.sample_rate`. With [tracing](#traces) on, every line except shed requests (`overloaded`, `streams_overloaded`) carries `trace_id` and `span_id`, sampled or not, and the upstream receives the same trace ID in `traceparent`.

**Admin messages to alert on:**

| Message | Means |
|---|---|
| `guard tripped` | The guard rolled back a version, aborted a canary or raised an alert |
| `audit chain broken` | Audit verification failed: rows were altered or the key is wrong |
| `background job failed` | A leader job (guard, JWKS, audit, retention) failed |
| `jwks fetch failed; keeping the last good keys` | An issuer's JWKS URL is failing |

## Traces

With `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` set ([Edge settings](../deploy/edge.md#tracing)), each edge exports spans over OTLP/HTTP:

| Span | Kind | Attributes |
|---|---|---|
| The method, such as `GET`; `HTTP` for a non-standard method | Server | Named as in the access log: `http.request.method` (`_OTHER` for a non-standard method, with `http.request.method_original`), `server.address`, `url.path`, `http.response.status_code`, `client.address`, `request_id`, `edge.decision`, `edge.config_version`, `edge.cohort`, `edge.rate_limit_rule`, `edge.auth` |
| `valkey ratelimit` | Client, child of the request span | `db.system.name`, `edge.ratelimit_calls`, `edge.ratelimit_failed` |

- **Joining a trace.** The edge continues the caller's trace from any peer, including a request it rejects for a wrong ingress secret, and keeps the caller's `tracestate`. An invalid `traceparent` starts a new trace and drops `tracestate`, as W3C Trace Context requires.
- **Sampling.** New traces follow `TRACE_SAMPLE_RATE`, and a caller's sampled flag is followed. A client can choose its own trace ID and sampled flag, so each replica samples at most `TRACE_MAX_PER_SECOND` traces it starts and, separately, at most that many joined from callers; forged flags can't use up the budget for the edge's own traces. A trace the cap drops reaches the upstream with the sampled flag off, so the services behind drop it too. A client that sends the flag off keeps its own requests out of traces; they are still in the access log.
- **What is not recorded.** Query values, `Authorization`, `Cookie` and other header values. Attribute values are cut at 512 characters unless `OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT` or `OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT` sets another limit.
- **Personal data.** Spans carry the client IP and path, as access logs do. Give the trace backend the same retention and access rules as your log store.
- **Status.** A request span is an error only for 5xx. A 4xx is the client's error, and `edge.decision` says why the edge answered it.
- **Collector outage.** Spans are queued in memory (2048 by default, `OTEL_BSP_MAX_QUEUE_SIZE`) and dropped when the queue is full. Requests are never slowed, and `/readyz` is unaffected.
- **Streams.** A WebSocket or SSE span lasts as long as the stream, like `duration_ms` in the access log.

### Admin traces

With the same variables set on admin ([Admin settings](../deploy/admin.md#variables)), admin exports:

| Span | Kind | Attributes |
|---|---|---|
| The method and route, such as `POST /api/publish` | Server | OTel HTTP conventions: `http.request.method`, `http.route`, `http.response.status_code`, `url.scheme`, `url.path`, `server.address` and `server.port` (from `Host`), `network.peer.address`, `network.peer.port`, `network.protocol.version`, `user_agent.original`, request and response body sizes, and `client.address` |
| The statement's first keyword, such as `INSERT` | Client, child of the request span | `db.system.name` (`postgresql`) and `db.query.text`, the statement with its placeholders; error status when the query fails |

- **What is traced.** Only `/api/` requests, the ones people make. Edge polls and reports, log shipping (`/v1/`) and the UI's files are not, and neither are admin's background jobs.
- **Client address.** `client.address` is the address audit and login throttling use: the peer, or with `ADMIN_TRUSTED_PROXIES` the rightmost `X-Forwarded-For` entry a trusted proxy didn't add. A client-written `X-Forwarded-For` entry never appears.
- **What is not recorded.** Query arguments, so no written value, password hash or token appears in a trace; Postgres error messages, which can quote values; the URL query; request bodies; and headers other than `User-Agent` and `Host`.
- **Personal data.** `client.address` and `user_agent.original` identify people; keep trace retention in line with the access log's.
- **Joining a trace.** Unlike the edge, admin joins the caller's trace only from a peer in `ADMIN_TRUSTED_PROXIES`. Any other caller's trace context starts a new trace that links to it. Sampling is under the same per-replica cap as the edge.
- **Failure.** Admin has no metrics endpoint, so a failed export shows only as the `opentelemetry error` log line, at most once a minute.

## Admin health

Admin has no health endpoint. Probe `GET /` for liveness: it serves the UI with 200 when the UI is embedded, as in the admin image; a build without the UI answers 404 there. Admin being down never affects traffic.
