# Monitoring

## Edge metrics

Prometheus text at `GET :9090/metrics`, per replica.

| Metric | Meaning |
|---|---|
| `edge_requests_total{class}` | Responses by class (`2xx` … `5xx`; `none` when the client left first). A code above 599, which an upstream can send, counts as `5xx` |
| `edge_responses_total{origin,code}` | Responses by who answered (`edge` or `upstream`) and status code, so the edge's 502 reads apart from the upstream's. Only codes seen have a series, except the edge's 502, 503 and 504, which are always present so an alert sees the first one. Code `0` is a request that got no answer, `600` any code above 599 |
| `edge_upstream_errors_total{cause}` | Requests the edge got no answer from the upstream for, by cause: `dns`, `refused`, `reset`, `tls`, `timeout`, `other`, as on the access line |
| `edge_rejected_total{reason}` | Requests the edge answered itself, by reason: `rate_limited`, `blocked` (a config rule's `block` setting), `auth`, `backstop`, `overloaded`, `upstream_timeout`, `untrusted_peer`, `path`, `body_timeout` (a 400 for a body sent too slowly), `body_invalid` (a 400 for a body that could not be read, such as broken chunk framing) and others. `upstream_tls` is a failed TLS handshake with the upstream: it refused the handshake, or its certificate is not valid for the request's Host, which the client chose, or not trusted; its error is on the request's access line |
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
| `edge_request_duration_seconds` | Histogram of request latency, on the buckets the rollback guard reads (1 ms to 10 s, then `+Inf`). For SSE and WebSocket it measures the time to response headers, not the stream's lifetime. It has `_bucket` and `_count` but no `_sum`, so averages are not available; `histogram_quantile(0.99, sum by (le) (rate(edge_request_duration_seconds_bucket[5m])))` gives the p99. A request is counted when it finishes, so one still open when its version is dropped, such as a long stream across a publish, is not counted |
| `edge_ratelimit_rule_total{rule,outcome}` | Each rate-limit rule's requests by outcome: `evaluated`, `limited`, `would_limit` (a log-only rule, or any rule under the kill switch, over its limit), `failed` (Valkey did not answer and the rule took its `fail_mode`), `capped` (matched, but skipped by the per-request rule cap) and `expired` (matched after the rule's `expires_at`, so skipped). Only rules of the versions this replica serves, or served since its last stats report, have series, so a rule removed by a publish loses its series after the next report. A version has at most 200 rate-limit rules, so an active version and a canary give at most 400 rules of 6 series each, plus rules of versions retired since the last report |

In the admin UI, latency is on **Routes**: p95 and p50 per route, from the access log's `duration_ms`, which for SSE and WebSocket is the stream's whole lifetime. **Stats** shows no latency.

## Admin metrics

Prometheus text at `GET :9091/metrics` (`ADMIN_INTERNAL_ADDR`), per replica, with no authentication. Every series below except the leader gauges is present from the start, at 0.

| Metric | Meaning |
|---|---|
| `admin_leader` | 1 on the replica running background jobs, 0 on the others |
| `admin_publishes_total{source}` | New versions by how they were made: `manual` (including the starter policy at first start), `revert`, `guard_rollback`, `import`, `autopilot` |
| `admin_guard_actions_total{action}` | Guard actions: `rollback`, `canary_abort`, `alert` (counted once when an alert starts) |
| `admin_notifications_total{result}` | Posts to Alertmanager, `sent` or `failed` |
| `admin_edge_reports_total{result}` | Edge stats reports: `accepted`, `invalid` (refused as malformed or too large, or a body that could not be read, such as from an edge that disconnected mid-report or hit admin's 30 s read timeout) or `error` (admin failed after authenticating the report and before ingesting it, such as Postgres unreachable). A report refused before this check, for a missing or wrong edge token or because Postgres was down while checking a token created in admin, is not counted under any label; the edge drops every report admin does not answer with 2xx and counts it in `edge_stats_dropped_total` |
| `admin_log_lines_total{result}` | Shipped access lines `accepted` into **Routes**, or `rejected` (not an access line, or too long) |
| `admin_log_batches_busy_total` | Access-log batches answered 429 because admin was busy; the shipper resends them |
| `admin_background_job_failures_total{job}` | Failed leader jobs: `jwks`, `verified_bots`, `audit`, `audit_full`, `guard`, `notifications`, `retention`, `autopilot`. `jwks` and `verified_bots` count only Postgres errors: a failed JWKS or crawler range fetch keeps the last good set and logs `jwks fetch failed; keeping the last good keys` or `verified bot ranges fetch failed; keeping the last good set` instead. `notifications` also counts a post Alertmanager did not accept (unreachable or not 2xx), which `admin_notifications_total{result="failed"}` counts too. `audit` and `audit_full` also count a broken chain, which `admin_audit_verify_failures_total` counts too |
| `admin_audit_verify_failures_total` | Audit verifications that found the chain broken |
| `admin_trace_export_errors_total` | Span batches the trace collector did not accept |
| `admin_connector_requests_total{connector,result}` | Requests to the autopilot's [connectors](../deploy/admin.md#connectors) (`prometheus`, `grafana`, `datadog`), by result: `ok`, `error` (unreachable, a redirect or not 2xx), `timeout` (over 10 seconds) or `too_large` (an answer over 256 KiB). Exported from zero on every replica, configured or not |
| `admin_autopilot_cases_total{trigger,verdict}` | [Autopilot](../use/autopilot.md) cases closed, by what opened them (`anomaly`, `sweep`, `review`, `investigate`, `ablation`) and verdict (`attack`, `benign`, `unsure`, `failed`, `cancelled`) |
| `admin_autopilot_proposals_total{action,result}` | Proposals by action (`add_sensor`, `enforce`, `retire`) and `accepted` or `rejected` |
| `admin_autopilot_policy_rejections_total{reason}` | Failed checks, by check: each failed check of a refused proposal counts, as do enforce rules rejected after observing (`block_share`, `crawler_subject`, `protected_subject`, `attack_stopped`, `note_expected_pattern`, or, for a proposed rule refused at publish, `compile`, `schema` or `deployment`) and approvals refused as `observed_too_short` |
| `admin_autopilot_note_writes_total{result}` | [Gate](../use/autopilot.md#the-gate) outcomes of `record_learning` calls: `written`, or `refused` for one of its reasons |
| `admin_autopilot_note_refusals_total{reason}` | Refused notes, by [gate](../use/autopilot.md#the-gate) reason |
| `admin_autopilot_note_transitions_total{to}` | Notes moved to `unconfirmed` (contested), `confirmed`, `dormant`, `retracted` or `retired` |
| `admin_autopilot_llm_runs_total{provider,model,status}` | Runs reported, by provider, model and status (`ok`, `error`, `timeout`, `lease_lost`). `model` holds at most 16 models per provider, then `other`; a model with no price reads `unpriced` |
| `admin_autopilot_llm_tokens_total{provider,model,kind}` | Tokens the runs reported: `input`, `output`, `cache_read`, `cache_write` |
| `admin_autopilot_llm_cost_usd_total{provider,model,source}` | Cost in USD: `configured` from the model prices admin holds, `provider` as the runner reported it |
| `admin_autopilot_llm_run_seconds{provider}` | Histogram of run durations |
| `admin_autopilot_agent_connected` | Leader only: 1 while a runner was seen in the last 2 minutes, else 0 |
| `admin_autopilot_cases_open` | Leader only: queued and running cases |
| `admin_autopilot_rules{state}` | Leader only: autopilot rules `observing` and `enforcing` |
| `admin_autopilot_notes{trust}` | Leader only: notes by trust level |
| `admin_autopilot_budget_used_ratio{budget}` | Leader only: the share in use of each budget: `enforcing` (`max_enforcing`), `sensors` (`max_sensors`), `cases_hour` (`cases_per_hour`) |
| `admin_edges_live` | Leader only: edges that reported in the last minute |
| `admin_anomalies_firing{signal}` | Leader only: firing [notifications](notifications.md), by signal |

The leader gauges come from the leader's notification check, so they appear up to one minute after a replica takes the lead and disappear when it steps down. They also disappear while that check fails, rather than show stale values. Use `max` across replicas for them.

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
| `rate(edge_stats_dropped_total[5m]) > 0` | Edges can't report stats to admin, so [notifications](notifications.md) can't see them | [Admin down](runbooks.md#admin-or-postgres-down) |
| `rate(edge_trace_export_errors_total[5m]) > 0` | Spans are being dropped; traffic is unaffected | Check the collector and the edge's `opentelemetry error` log line, written at most once a minute |
| `increase(edge_background_panics_total[10m]) > 0` or `edge_rejected_total{reason="panic"}` rising | A bug | Collect logs and report it |
| `(max(admin_leader) or vector(0)) == 0` for 5 minutes, which also fires when no admin replica is scraped | No admin replica runs the guard, notifications, JWKS refresh or audit checks; traffic is unaffected | Check admin logs for `leader loop`, and Postgres |
| `sum(changes(admin_leader[30m])) > 4` | Leadership keeps moving, so background jobs keep restarting | Check the leader's connection to Postgres (`leader connection lost; stopping jobs`) |
| `increase(admin_audit_verify_failures_total[1h]) > 0` | Audit rows were altered, or the audit key is wrong | Check the `audit chain broken` log line |
| `increase(admin_background_job_failures_total[30m]) > 0` | A leader job failed: usually Postgres, but also Alertmanager unreachable or not answering 2xx (`notifications`) or a broken audit chain (`audit`, `audit_full`). An unreachable IdP or crawler range source does not count here | Check the `background job failed` log line for its error |
| `sum by (connector) (rate(admin_connector_requests_total{result=~"error\|timeout"}[15m])) > 0` for 15 minutes | A connector is unreachable, slow or refusing requests, so autopilot runs get tool errors from it. A query the model wrote that the connector refuses counts too, so look at the statuses before acting. Traffic and the rest of the autopilot are unaffected | [A connector fails](runbooks.md#a-connector-fails) |

## Logs

Both binaries write JSON lines to stdout.

**Edge access log** (`msg: access`): method, host (`server.address`), normalized path, query key names (`edge.query_keys`, and `edge.query_keys_dropped` counting keys not logged because they looked like secrets or were past the first 32), status, `request_id`, `edge.decision` (`allow`, `would_block` when a config rule set to log only would have blocked it, or the rejection reason, such as `blocked`), whether the upstream answered (`edge.upstream_answered`: `false` when the edge wrote the response, such as a CORS preflight, which is still `allow`, or the 502 for a protocol switch the edge refused because the upstream's `Upgrade` didn't match the request's), `duration_ms`, client IP (`client.address`), `user_agent.original`, the viewer AS number (`client.as.number`), country (`client.geo.country_iso_code`) and JA4 (`tls.client.ja4`) when the deployment has their sources, the request's [client signals](../reference/expressions.md#client-signals) (`client.signals`, when any; computed for every logged request that reached the config phase, whether or not a rule reads them), config version and cohort (`edge.cohort`: `candidate` when the request's client is in the [canary](../use/publishing.md#canary), otherwise `active`), the config rules that matched (`edge.config_rules`), the rate-limit rule that answered 429 (`edge.rate_limit_rule`) and the JWT result (`edge.auth`: `verified`, `cached`, `missing`, `invalid` or `pass_no_keys`). When the edge got no answer from the upstream, the line carries the error (`edge.upstream_error`, at most 512 bytes; quoted values, which can be a header line or an `Upgrade` value, are replaced with `"…"` unless the error is a DNS, certificate or socket error) and its cause (`edge.upstream_error_kind`): `dns` when the upstream's name did not resolve, `refused` when nothing accepted the connection, `reset` when the upstream dropped it, `tls` when the TLS handshake with the upstream failed: it refused the handshake, or its certificate is not valid for the request's Host or not trusted (decision `upstream_tls`), `timeout` when the upstream did not connect, finish the TLS handshake or send response headers in time (decision `upstream_timeout`, a 504), or `other`. **Stats** and `edge_upstream_errors_total` count the same causes exactly. There is no separate log line per failure: during an outage every failing request would take the log handler's lock on the request path. Admin keeps counts, not lines: keep these lines in your log store, and set `LOG_SEARCH_URL` ([admin settings](../deploy/admin.md)) so admin links its counts to them. Query values, `Authorization` and `Cookie` are never logged. Rejections, `would_block` and 5xx are always logged; other requests follow `LOG_SAMPLE_RATE`, and when it is below 1 their lines carry it as `edge.sample_rate`. With [tracing](#traces) on, every line except shed requests (`overloaded`, `streams_overloaded`) carries `trace_id` and `span_id`, sampled or not, and the upstream receives the same trace ID in `traceparent`.

**Admin messages to alert on:**

| Message | Means |
|---|---|
| `guard tripped` | The guard rolled back a version, aborted a canary or raised an alert |
| `anomaly firing`, `anomaly resolved` | A [notification](notifications.md) started or ended; it is also sent to Alertmanager when `ALERTMANAGER_URL` is set |
| `audit chain broken` | Audit verification failed: rows were altered or the key is wrong |
| `background job failed` | A leader job (guard, notifications, JWKS, verified crawler ranges, audit, retention) failed |
| `jwks fetch failed; keeping the last good keys` | An issuer's JWKS URL is failing |
| `verified bot ranges fetch failed; keeping the last good set` | A `VERIFIED_BOT_SOURCES` URL is failing |

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
- **Failure.** A failed export is counted in `admin_trace_export_errors_total` and logged as `opentelemetry error`, at most once a minute.

## Admin health

Admin has no health endpoint. Probe `GET /` for liveness: it serves the UI with 200 when the UI is embedded, as in the admin image; a build without the UI answers 404 there. Admin being down never affects traffic.
