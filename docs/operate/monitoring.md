# Monitoring

## Edge metrics

Prometheus text at `GET :9090/metrics`, per replica.

| Metric | Meaning |
|---|---|
| `edge_requests_total{class}` | Responses by class (`2xx` … `5xx`; `none` when the client left first) |
| `edge_rejected_total{reason}` | Requests the edge answered itself, by reason: `rate_limited`, `auth`, `backstop`, `overloaded`, `upstream_timeout`, `untrusted_peer`, `path` and others |
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
| `increase(edge_background_panics_total[10m]) > 0` or `edge_rejected_total{reason="panic"}` rising | A bug | Collect logs and report it |

## Logs

Both binaries write JSON lines to stdout.

**Edge access log** (`msg: access`): method, host (`server.address`), normalized path, query key names (`edge.query_keys`, and `edge.query_keys_dropped` counting keys not logged because they looked like secrets or were past the first 32), status, `request_id`, `edge.decision` (`allow` or the rejection reason), `duration_ms`, client IP, config version and cohort (`edge.cohort`: `candidate` when the request's client is in the [canary](../use/publishing.md#canary), otherwise `active`), the config rules that matched (`edge.config_rules`), the rate-limit rule that answered 429 (`edge.rate_limit_rule`) and the JWT result (`edge.auth`: `verified`, `cached`, `missing`, `invalid` or `pass_no_keys`). Query values, `Authorization` and `Cookie` are never logged. Rejections and 5xx are always logged; other requests follow `LOG_SAMPLE_RATE`, and when it is below 1 their lines carry it as `edge.sample_rate`.

**Admin messages to alert on:**

| Message | Means |
|---|---|
| `guard tripped` | The guard rolled back a version, aborted a canary or raised an alert |
| `audit chain broken` | Audit verification failed: rows were altered or the key is wrong |
| `background job failed` | A leader job (guard, JWKS, audit, retention) failed |
| `jwks fetch failed; keeping the last good keys` | An issuer's JWKS URL is failing |

## Admin health

Admin has no health endpoint. Probe `GET /` for liveness: it serves the UI with 200 when the UI is embedded, as in the admin image; a build without the UI answers 404 there. Admin being down never affects traffic.
