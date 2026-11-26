# Monitoring

## Edge metrics

Prometheus text at `GET :9090/metrics`, per replica.

| Metric | Meaning |
|---|---|
| `edge_requests_total{class}` | Responses by class (`2xx` … `5xx`; `none` when the client left first). A code above 599, which an upstream can send, counts as `5xx` |
| `edge_responses_total{origin,code}` | Responses by who answered (`origin`: `edge` or `upstream`) and status `code`, so the edge's 502 reads apart from the upstream's. [Label values](#edge-metric-label-values) |
| `edge_upstream_errors_total{cause}` | Requests the edge got no answer from the upstream for, by cause: `dns`, `refused`, `reset`, `tls`, `timeout`, `other`, as on the access line |
| `edge_rejected_total{reason}` | Requests the edge answered itself, by `reason`: `rate_limited`, `blocked`, `banned`, `auth`, `backstop`, `overloaded`, `upstream_timeout`, `untrusted_peer`, `path`, `body_timeout`, `body_invalid`, `upstream_tls` and others. [Label values](#edge-metric-label-values) |
| `edge_inflight`, `edge_streams` | Concurrent requests and open WebSocket/SSE streams |
| `edge_ready` | 1 when a policy is loaded and the edge isn't draining |
| `edge_snapshot_version` | Policy version this replica runs |
| `edge_bootstrap_age_seconds` | Non-zero while running from a bootstrap file |
| `edge_snapshot_poll_errors_total`, `edge_snapshot_rejected_total` | Failed polls of admin (unreachable, an error status, or a policy the edge rejected); policies that failed validation on the edge |
| `edge_valkey_errors_total`, `edge_valkey_breaker_open_total` | Valkey call failures; rate-limit calls skipped because a node's breaker was open |
| `edge_auth_total{result}` | `verified`, `cached`, `missing`, `invalid`, `pass_no_keys` |
| `edge_jwks_refresh_total{result}` | JWKS refreshes, `ok` or `error` |
| `edge_ban_hits_total` | Requests refused as `banned` |
| `edge_ban_dropped_total` | Bans not stored because the ban shard for the address was full (64 shards of 1,563 bans each, so drops can start well below 100,000 per edge); those clients are not banned |
| `edge_ban_reports_dropped_total` | Bans not sent to admin because the 200-ban report queue was full |
| `edge_ip_list_entries` | Prefixes in this edge's IP list set, counted across lists; 0 while no list is on |
| `edge_ip_list_fetch_failures_total` | IP list fetches that failed or were refused (admin unreachable, an error status, an unreadable body, a bad or repeated list name, more than 128 lists, a bad or 4-in-6 prefix, a bad lift IP, more than 500,000 prefixes, or lists that split into more than 1,048,576 names across combinations); the edge keeps its last set |
| `edge_bans` | Entries in this edge's ban table, including ones that ended and are not yet swept |
| `edge_allowlisted_total` | Requests from a client on the trusted client allowlist, including ones a retained check later rejected |
| `edge_ratelimit_rules_capped_total` | Requests matching more rate-limit rules than are evaluated |
| `edge_snapshot_loads_total` | Policy snapshots this replica activated, from admin, its cache or the bootstrap file |
| `edge_backstop_untracked_total` | Requests from a new IP that passed the local backstop untracked because its table was full; the shared limits still apply to them |
| `edge_ratelimit_local_untracked_total` | Requests a rule counted in this replica's memory (a count rule, or `fail_mode: local` while Valkey can't answer) whose new subject wasn't stored because the local store was full, so the rule let it through |
| `edge_ratelimit_penalty_cache_hits_total` | Rate-limit checks answered from this replica's penalty cache, with no Valkey call |
| `edge_ratelimit_penalty_cache_dropped_total` | Penalties not stored because the penalty cache was full. A count rule then doesn't refuse that subject (fail open) |
| `edge_cors_preflight_total{result}` | CORS preflights the edge answered, `allowed` or `denied` (answered with no `Access-Control-*` headers) |
| `edge_log_dropped_total`, `edge_stats_dropped_total` | Log lines dropped because the buffer was full; stats reports admin did not accept |
| `edge_background_panics_total` | Recovered panics in background loops |
| `edge_trace_export_errors_total` | Span batches the trace collector did not accept. Spans are dropped, never retried into the request path |
| `edge_trace_capped_total` | Traces not sampled because the replica reached `TRACE_MAX_PER_SECOND` |
| `edge_request_duration_seconds` | Histogram of request latency, on the buckets the rollback guard reads (1 ms to 10 s, then `+Inf`). [Notes](#edge-metric-label-values) |
| `edge_client_signal_total{signal}` | Requests that showed each client signal (one request can show several), counted exactly. [Notes](#edge-metric-label-values) |
| `edge_ratelimit_rule_total{rule,outcome}` | Each rate-limit rule's requests by `outcome`: `evaluated`, `limited`, `logged`, `failed`, `capped` or `expired`. [Label values](#edge-metric-label-values) |

### Edge metric label values

- `edge_responses_total`: only codes seen have a series, except the edge's 502, 503 and 504, which are always present so an alert sees the first one. Code `0` is a request that got no answer, `600` any code above 599.
- `edge_rejected_total{reason}`:
    - `blocked` is an access rule's `block` setting.
    - `banned` is a client IP an access rule's `ban` setting banned earlier on this edge.
    - `body_timeout` is a 400 for a body sent too slowly.
    - `body_invalid` is a 400 for a body that could not be read, such as broken chunk framing.
    - `upstream_tls` is a failed TLS handshake with the upstream: it refused the handshake, or its certificate is not valid for the request's Host, which the client chose, or not trusted. Its error is on the request's access line.
- `edge_request_duration_seconds`:
    - For SSE and WebSocket it measures the time to response headers, not the stream's lifetime.
    - It has `_bucket` and `_count` but no `_sum`, so averages are not available. `histogram_quantile(0.99, sum by (le) (rate(edge_request_duration_seconds_bucket[5m])))` gives the p99.
    - A request is counted when it finishes, so one still open when its version is dropped, such as a long stream across a publish, is not counted.
- `edge_client_signal_total`: every signal always has a series. Requests shed before the config step, such as an ambiguous path, count none.
- `edge_ratelimit_rule_total{outcome}`:
    - `logged` is a log-only rule, or any rule under the kill switch, over its limit.
    - `failed` is Valkey not answering, so the rule took its `fail_mode`.
    - `capped` is matched but skipped by the per-request rule cap.
    - `expired` is matched after the rule's `expires_at`, so skipped.
- `edge_ratelimit_rule_total{rule}`: only rules of the versions this replica serves, or served since its last stats report, have series, so a rule removed by a publish loses its series after the next report. A version has at most 200 rate-limit rules, so an active version and a canary give at most 400 rules of 6 series each, plus rules of versions retired since the last report.

In the admin UI, latency is on **Routes**: p95 and p50 per route, from the access log's `duration_ms`, which for SSE and WebSocket is the stream's whole lifetime. **Stats** shows no latency.

## Admin metrics

Prometheus text at `GET :9091/metrics` (`ADMIN_INTERNAL_ADDR`), per replica, with no authentication. Every series below except the leader gauges and the model-labelled `admin_autopilot_llm_runs_total`, `admin_autopilot_llm_tokens_total` and `admin_autopilot_llm_cost_usd_total` is present from the start, at 0. Those three appear with a model's first run, so `rate()` and `increase()` miss that run.

| Metric | Meaning |
|---|---|
| `admin_leader` | 1 on the replica running background jobs, 0 on the others |
| `admin_publishes_total{source}` | New versions by how they were made: `manual` (including the starter policy at first start), `revert`, `guard_rollback`, `import`, `autopilot` |
| `admin_guard_actions_total{action}` | Guard actions: `rollback`, `canary_abort`, `alert` (counted once when an alert starts) |
| `admin_notifications_total{result}` | Posts to Alertmanager, `sent` or `failed` |
| `admin_edge_reports_total{result}` | Edge stats reports: `accepted`, `invalid` or `error`. Details follow the table |
| `admin_log_lines_total{result}` | Shipped access lines `accepted` into **Routes**, or `rejected` (not an access line, or too long) |
| `admin_log_batches_busy_total` | Access-log batches answered 429 because admin was busy; the shipper resends them |
| `admin_background_job_failures_total{job}` | Failed leader jobs, by `job`: `jwks`, `verified_bots`, `audit`, `audit_full`, `guard`, `notifications`, `retention`, `autopilot`, `ip_lists`. Details follow the table |
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

Notes on the labels above:

- `admin_edge_reports_total`:
    - `invalid` is a report refused as malformed or too large, or a body that could not be read, such as from an edge that disconnected mid-report or hit admin's 30 s read timeout.
    - `error` is admin failing after authenticating the report and before ingesting it, such as Postgres unreachable.
    - A report refused before this check, for a missing or wrong edge token or because Postgres was down while checking a token created in admin, is not counted under any label. The edge drops every report admin does not answer with 2xx and counts it in `edge_stats_dropped_total`.
- `admin_background_job_failures_total`:
    - `jwks` counts only Postgres errors: a failed JWKS fetch keeps the last good keys and logs `jwks fetch failed; keeping the last good keys` instead.
    - `verified_bots` counts a Postgres error storing a source's ranges or status, returned after every source is processed. A failed crawler range fetch or a list that does not parse does not count: it keeps the last good set, logs `verified bot ranges fetch failed; keeping the last good set`, shows on **Fleet** and raises `verified_bots_stale` after repeated failures.
    - `ip_lists` counts a Postgres error storing a list or its status, returned after every source is processed. A failed download or a list with no usable line does not count: it keeps the last good list, logs `ip list fetch failed; keeping the last good set` and shows on **IP lists**.
    - `notifications` also counts a post Alertmanager did not accept (unreachable or not 2xx), which `admin_notifications_total{result="failed"}` counts too.
    - `audit` and `audit_full` also count a broken chain, which `admin_audit_verify_failures_total` counts too.

The leader gauges come from the leader's notification check, so they appear up to one minute after a replica takes the lead and disappear when it steps down. They also disappear while that check fails, rather than show stale values. Use `max` across replicas for them.

## Alerts worth having

| Condition | Means | Do |
|---|---|---|
| `edge_ready == 0` on a replica for 2 minutes | No policy loaded | [Edge not ready](runbooks.md#edge-not-ready) |
| `edge_snapshot_version` differs across replicas for 5 minutes | Some edges can't reach admin | [Admin down](runbooks.md#admin-or-postgres-down) |
| `increase(edge_snapshot_poll_errors_total[5m]) >= 3` on a replica | Admin unreachable for 3 or more polls in 5 minutes; edges keep their policy. A single failed poll, such as one during an admin restart, doesn't fire it | [Admin down](runbooks.md#admin-or-postgres-down) |
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
| `increase(admin_background_job_failures_total[30m]) > 0` | A leader job failed: usually Postgres, but also Alertmanager unreachable or not answering 2xx (`notifications`) or a broken audit chain (`audit`, `audit_full`). An unreachable IdP or crawler range source does not count here; a crawler range source that keeps failing raises the `verified_bots_stale` [notification](notifications.md#signals) | Check the `background job failed` log line for its error |
| `sum by (connector) (rate(admin_connector_requests_total{result=~"error\|timeout"}[15m])) > 0` for 15 minutes | A connector is unreachable, slow or refusing requests, so autopilot runs get tool errors from it. A query the model wrote that the connector refuses counts too, so look at the statuses before acting. Traffic and the rest of the autopilot are unaffected | [A connector fails](runbooks.md#a-connector-fails) |

## Logs

Both binaries write JSON lines to stdout.

**Edge access log** (`msg: access`): one JSON line per logged request, written off the request path. Field names follow OpenTelemetry HTTP conventions where one exists. Fields marked "when present" are left out of the line otherwise.

| Field | Meaning | When present |
|---|---|---|
| `http.request.method`, `url.path`, `http.response.status_code`, `request_id` | Method, normalized path, status and request ID | Always |
| `server.address` | The host | Always |
| `edge.action` | `allow`, or the reason the edge refused the request, such as `blocked` or `rate_limited`. A log-only rule's match is not a refusal, so the line stays `allow` | Always |
| `edge.upstream_answered` | Whether the upstream answered. `false` when the edge wrote the response, such as a CORS preflight, which is still `allow`, or the 502 for a protocol switch the edge refused because the upstream's `Upgrade` didn't match the request's | Always |
| `duration_ms` | Request duration | Always |
| `edge.query_keys` | Query key names, never values | The request has a query |
| `edge.query_keys_dropped` | Count of keys not logged because they looked like secrets or were past the first 32 | Any key was dropped |
| `client.address` | Client IP | The edge has a client IP |
| `user_agent.original` | The `User-Agent` | The request sent one |
| `client.as.number`, `client.geo.country_iso_code`, `tls.client.ja4` | Viewer AS number, country and JA4 | The deployment has their sources |
| `tls.client.ja3`, `client.geo.continent_code` | JA3 fingerprint and continent | The deployment has their sources |
| `client.signals` | The request's [client signals](../reference/expressions.md#client-signals). Computed for every logged request that reached the config phase, whether or not a rule reads them | Any signal showed |
| `client.ip_lists` | Names of the [IP lists](../use/ip-lists.md) that hold the client IP | The IP is on a list, so absent while no list is on |
| `edge.config_version`, `edge.cohort` | Config version and cohort: `candidate` when the request's client is in the [canary](../use/publishing.md#canary), otherwise `active` | The request got a config version |
| `edge.allowlist` | The trusted client allowlist entry the client matched, as written in the policy | The client matched an entry, on lines that are written, so it follows `LOG_SAMPLE_RATE` like any other |
| `edge.decided_by` | The rule that decided the request: the access rule whose `block` setting refused it, the rule behind a ban for `banned`, the rate-limit rule for `rate_limited`, `rate_limit_key` and `rate_limit_unavailable`, or the [always-allow](../use/policy.md#always-allow) rule that let it through | A rule decided it |
| `edge.matched_rules` | Every access, rate-limit and request-header rule the request matched, in evaluation order. See [Matched rules](#matched-rules) | A rule matched |
| `edge.logged_rules` | The IDs of the `edge.matched_rules` entries whose `result` is `logged`, the rules that only logged | Any rule only logged |
| `edge.ban.until` | When the ban ends, RFC 3339 UTC | The request set a ban |
| `edge.ban.dropped: true` | The ban table was full and nothing was stored | Instead of `edge.ban.until`, when the table was full |
| `edge.ban.rule`, `edge.ban.since`, `edge.ban.host`, `edge.ban.path` | The rule that set the ban, when the client last tripped it, and the host and path of the request that tripped it, at most 255 and 128 bytes, never the query | `edge.action` is `banned` |
| `edge.auth` | JWT result: `verified`, `cached`, `missing`, `invalid` or `pass_no_keys` | A token check ran |
| `edge.auth_sub` | The JWT `sub` claim, at most 256 bytes. No other claim is logged | `edge.auth` is `verified` or `cached` |
| `network.protocol.version`, `url.scheme` | Viewer HTTP version (`1.0`, `1.1`, `2` or `3`) and scheme (`https` or `http`), from the trusted viewer headers | The deployment has a source for them |
| `http.request.body.size` | The declared request body length | The length is known, so absent for a chunked body |
| `http.response.body.size` | The bytes the edge wrote as the response body, including the edge's own templates | Not on a WebSocket or other hijacked connection, whose traffic does not pass through the edge's writer |
| `edge.locale` | The locale the edge detected | The request's locale setting is on and a rule or the upstream request read it |
| `http.request.header.sec-ch-ua`, `.sec-ch-ua-mobile`, `.sec-ch-ua-platform`, `.sec-fetch-site`, `.sec-fetch-mode`, `.sec-fetch-dest`, `.sec-fetch-user`, `.accept`, `.accept-language`, `.accept-encoding` | The request header, the first value, at most 256 bytes | The request sent it |
| `http.request.header.<lower-case name>` | Every header in [`CDN_HEADERS`](../deploy/edge.md#cdn-headers), raw as received, for example `.cf-ipcity` or `.cloudfront-viewer-tls`, so each preset adds its CDN's headers to every line | The request sent it |
| `http.request.header.referer` | The Referer's scheme, host and path only, at most 512 bytes | The Referer is an absolute URL |
| `edge.upstream_error` | The error when the edge got no answer from the upstream, at most 512 bytes. Quoted values, which can be a header line or an `Upgrade` value, are replaced with `"…"` unless the error is a DNS, certificate or socket error | The upstream did not answer |
| `edge.upstream_error_kind` | The cause, listed below | The upstream did not answer |
| `edge.sample_rate` | The value of `LOG_SAMPLE_RATE` | It is below 1 and the line is a sampled allowed request |
| `trace_id`, `span_id` | The request's trace, which the upstream also receives as `traceparent` | [Tracing](#traces) is on, sampled or not, except for shed requests (`overloaded`, `streams_overloaded`) |

Causes in `edge.upstream_error_kind`, which **Stats** and `edge_upstream_errors_total` count exactly:

- `dns`: the upstream's name did not resolve.
- `refused`: nothing accepted the connection.
- `reset`: the upstream dropped the connection.
- `tls`: the TLS handshake with the upstream failed. It refused the handshake, or its certificate is not valid for the request's Host or not trusted (action `upstream_tls`).
- `timeout`: the upstream did not connect, finish the TLS handshake or send response headers in time (action `upstream_timeout`, a 504).
- `other`: any other failure.

Rules for what is logged:

- **Never logged:** query values, `Authorization` and `Cookie`.
- **Always logged:** rejections, 5xx, lines of a request an always-allow rule or the allowlist let through past a block, and lines with an `edge.logged_rules` entry. Other allowed requests follow `LOG_SAMPLE_RATE`.
- **No line per failure:** an upstream failure has no separate log line, because during an outage every failing request would take the log handler's lock on the request path. Admin keeps counts, not lines: keep these lines in your log store, and set `LOG_SEARCH_URL` ([admin settings](../deploy/admin.md)) so admin links its counts to them.

**Admin messages to alert on:**

| Message | Means |
|---|---|
| `guard tripped` | The guard rolled back a version, aborted a canary or raised an alert |
| `anomaly firing`, `anomaly resolved` | A [notification](notifications.md) started or ended; it is also sent to Alertmanager when `ALERTMANAGER_URL` is set |
| `audit chain broken` | Audit verification failed: rows were altered or the key is wrong |
| `background job failed` | A leader job (guard, notifications, JWKS, verified crawler ranges, audit, retention) failed. For a crawler source's ranges or status it names the source Postgres could not store |
| `jwks fetch failed; keeping the last good keys` | An issuer's JWKS URL is failing |
| `verified bot ranges fetch failed; keeping the last good set` | A `VERIFIED_BOT_SOURCES` URL is failing; its failures in a row show on **Fleet** |

### Matched rules

`edge.matched_rules` is a list of objects, one per rule that matched the request, in the order the edge ran them: access rules, then rate-limit rules, then request-header rules. A rate-limit rule skipped for a missing key part, an expired rule or one past the per-request cap is not listed. Each entry has:

- `rule`: the rule ID.
- `type`: `access`, `rate_limit` or `headers`.
- `result`: what the rule did.
- `left`: a rate-limit rule's remaining quota after this request, absent when the rule has no count (`error`, `not_counted`).
- `retry_after`: seconds until the client may retry, on a rate-limit entry the request was over the limit for and that refused or logged it.
- `blocked_until`: RFC 3339 UTC time a penalty on this key ends, when one is set.

| `result` | Type | Means |
|---|---|---|
| `blocked` | access | Its `block` setting won the merge and the edge refused the request |
| `allowed` | access | An always-allow rule |
| `logged` | access | Its `block` setting won and was `log` (or the kill switch made it `log`), so the request went on |
| `overridden` | access | It sets `block`, but another rule's setting won or an allow lifted it |
| `matched` | access, headers | It matched and refuses nothing |
| `under` | rate_limit | The request was within the limit |
| `logged` | rate_limit | Over the limit, but the rule is log-only or the kill switch is on, so the request went on |
| `blocked` | rate_limit | Over the limit and refused |
| `over` | rate_limit | A count rule counted this response's status over the limit; the response was already sent, so the penalty applies to the next requests |
| `not_counted` | rate_limit | A count rule counts after the response, and this response was not counted |
| `error` | rate_limit | Valkey did not answer and the rule's `fail_mode` is `open` or `closed`, so there is no count. With `local` the edge counts on its own share and the entry shows `under`, `over` or `blocked` |

Most log stores can't match two fields of one entry in a list of objects: Elasticsearch maps it by default so that `edge.matched_rules.rule: x` and `edge.matched_rules.result: logged` can match different entries ([Elasticsearch](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/nested)), and Loki's `json` parser skips arrays ([Loki](https://grafana.com/docs/loki/latest/query/log_queries/)). To find the requests a log-only rule would have refused, search `edge.logged_rules` for the rule ID. Use `edge.matched_rules` to read one line in full.

## Traces

With `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` set ([Edge settings](../deploy/edge.md#tracing)), each edge exports spans over OTLP/HTTP:

| Span | Kind | Attributes |
|---|---|---|
| The method, such as `GET`; `HTTP` for a non-standard method | Server | Named as in the access log: `http.request.method` (`_OTHER` for a non-standard method, with `http.request.method_original`), `server.address`, `url.path`, `http.response.status_code`, `client.address`, `request_id`, `edge.action`, `edge.config_version`, `edge.cohort`, `edge.decided_by`, `edge.auth` |
| `valkey ratelimit` | Client, child of the request span | `db.system.name`, `edge.ratelimit_calls`, `edge.ratelimit_failed` |

- **Joining a trace.** The edge continues the caller's trace from any peer, including a request it rejects for a wrong ingress secret, and keeps the caller's `tracestate`. An invalid `traceparent` starts a new trace and drops `tracestate`, as W3C Trace Context requires.
- **Sampling.** New traces follow `TRACE_SAMPLE_RATE`, and a caller's sampled flag is followed. A client can choose its own trace ID and sampled flag, so each replica samples at most `TRACE_MAX_PER_SECOND` traces it starts and, separately, at most that many joined from callers; forged flags can't use up the budget for the edge's own traces. A trace the cap drops reaches the upstream with the sampled flag off, so the services behind drop it too. A client that sends the flag off keeps its own requests out of traces; they are still in the access log.
- **What is not recorded.** Query values, `Authorization`, `Cookie` and other header values. Attribute values are cut at 512 characters unless `OTEL_SPAN_ATTRIBUTE_VALUE_LENGTH_LIMIT` or `OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT` sets another limit.
- **Personal data.** Spans carry the client IP and path, as access logs do. Give the trace backend the same retention and access rules as your log store.
- **Status.** A request span is an error only for 5xx. A 4xx is the client's error, and `edge.action` says why the edge answered it.
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
