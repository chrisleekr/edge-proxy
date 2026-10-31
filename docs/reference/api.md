# Admin API

Everything the UI does goes through this JSON API, so it can be automated. Authenticate with `Authorization: Bearer <token>` (a user token from **Users**) or the UI's session cookie. Cross-origin browser writes are refused. Errors are `application/problem+json` with the failing field and reason.

Draft writes and publish use optimistic concurrency: send the `ETag` from the last read as `If-Match`. A stale value gets `412`, and a missing one `428`.

## Endpoints

| Method and path | Permission | Does |
|---|---|---|
| `POST /api/auth/login` | public | Session sign-in |
| `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/password` | signed in | Sign out, current user (with `log_search_url`, the deployment's `LOG_SEARCH_URL`, when it is set), change password |
| `GET /api/roles` | signed in | Roles and their permissions |
| `GET /api/draft` | `config.read` | Read the draft: `{config, tests}`, people's rules only, plus `overlay`, the active version's [autopilot rules](../use/publishing.md#autopilot-rules) that have not expired, and `adopted`, the ones adopted since the last publish |
| `PUT /api/draft` | `config.write` | Replace the draft; a save validates everything |
| `POST /api/draft/check` | `config.read` | Validate a `{config}` as a save would, without saving: returns `{errors, warnings}`, each with its path |
| `POST /api/draft/adopt` | `config.write` | Copy autopilot rule `id` into the draft without its `ap-` prefix and expiry. `404` when the overlay has no such rule, `409` when the draft already has a rule with that id in any phase, since rule ids are unique across phases |
| `GET /api/draft/rebase` | `config.read` | Preview a rebase onto the active version |
| `POST /api/draft/rebase` | `config.write` | Apply it |
| `GET /api/expr/schema`, `POST /api/expr/parse`, `POST /api/expr/render`, `POST /api/expr/validate` | `config.read` | Fields and operators, and the values rule settings and config sections take (such as algorithms, content types, JWT algorithms and HTTP methods); convert between text and tree; validate |
| `POST /api/tests/run`, `POST /api/simulate` | `config.test` | Run the draft's tests; simulate one request. A mistyped client IP is a 422 with an error at `request.ip` |
| `POST /api/publish` | `config.publish` (plus `canary.manage` with `canary_percent`) | Publish the draft. Body: `message`, optional `canary_percent`, `override_reason`, `guard_override` with `guard_override_reason` |
| `GET /api/versions`, `GET /api/versions/{v}` | `config.read` | List and read versions |
| `GET /api/diff/{a}/{b}`, `GET /api/rules/{id}/history` | `config.read` | Compare versions; one rule's history |
| `POST /api/versions/{v}/revert` | `config.rollback` | Publish version `v`'s own rules, with the current autopilot rules, as a new version. Body: `reason` (required), optional `override_reason`, `canary_percent` (needs `canary.manage`), `guard_override` with `guard_override_reason` |
| `POST /api/versions/{v}/copy-to-draft` | `config.write` | Start the draft from version `v` |
| `GET /api/canary` | `config.read` | Canary state |
| `POST /api/canary/step`, `POST /api/canary/promote`, `POST /api/canary/abort` | `canary.manage` | Step (`percent`), promote, abort (`reason`) |
| `GET /api/export` | `config.read` | Export the active version, autopilot rules included, as `{envelope, tests}` (`envelope` is an edge bootstrap file) |
| `POST /api/import` | `config.publish` | Publish `{config, tests, message, override_reason}` as a new version. `ap-` rate-limit rules in `config` are ignored and this admin's autopilot rules are kept, less those expired. `422` when a config rule or request header rule has an `ap-` id |
| `GET /api/settings/guard` | `config.read` | Default guard settings |
| `PUT /api/settings/guard` | `settings.manage` | Change them |
| `GET /api/settings/notifications` | `config.read` | [Notification](../operate/notifications.md) settings: defaults per signal and per-rule settings |
| `PUT /api/settings/notifications` | `settings.manage` | Change them |
| `GET /api/anomalies` | `stats.read` | Open anomalies and those resolved in the last 7 days, newest first, with whether `ALERTMANAGER_URL` is set |
| `GET /api/fleet`, `GET /api/stats` | `stats.read` | Edges and their versions; per-minute stats for the last `minutes`, one row per minute and version summed across replicas. With `step`, a number of minutes that divides a day (such as 5 or 60), each row is a bucket of `step` minutes from UTC midnight, `minute` is its start, the range starts at the start of the bucket `minutes` falls in, so the first bucket is whole, and `top_limited` keeps, for each rule, the 20 clients with the most `limited` plus `would_limit`, summed by rule and key. Rows have `status_codes`, requests by status code apart by who answered (`{"edge": {"502": 3}, "upstream": {"200": 980}}`; code `0` is a request that got no answer and `600` any code above 599), and `upstream_errors`, the edge's upstream failures by cause (`{"refused": 3}`). Both are empty for minutes reported by edges older than this admin |
| `GET /api/observed-routes`, `GET /api/observed-routes/{id}` | `stats.read` | Routes built from access logs, with traffic, status mix, latency and grouping suggestions (`hours` sets the range; `limit` keeps the busiest routes and `more` counts the rest); one route with its hourly series, `status_codes` (its answers by code) and `upstream_errors` (the edge's upstream failures by cause) |
| `GET /api/observed-routes/{id}/flow`, `GET /api/observed-routes/{id}/condition` | `config.read` | What a version does to a request like this route's (`version`: a number or `draft`; the live version when omitted); an expression that matches the route, to start a new rule |
| `DELETE /api/observed-routes`, `DELETE /api/observed-routes/{id}` | `routes.manage` | Delete every route, or one. Routes are collected again from new access logs |
| `GET /api/route-patterns` | `stats.read` | Patterns that group similar paths into one route |
| `POST /api/route-patterns`, `DELETE /api/route-patterns/{id}` | `routes.manage` | Add a pattern (existing routes it covers are merged into it), or remove one |
| `GET /api/audit` | `audit.read` | Read the audit log, newest first, 100 rows per page. `actor`, `action` and `target` match exactly, and `action` also takes a comma-separated list of up to 50; `mentions` matches part of the target or details; `since` takes an RFC 3339 time and leaves out earlier events; `before` takes a `seq` to page. A publish, import, revert or guard rollback that changes the kill switch from the live version's has the new switch in `details.kill_switch`. A revert or a guard rollback of a person's version that published the restored rules without the autopilot rules, because together they were refused, has `details.overlay_dropped: true` |
| `POST /api/audit/verify`, `POST /api/audit/export` | `audit.read` | Verify the chain, or export every row with its HMAC as a streamed JSON array. Both are POST because each writes its own audit row |
| `GET /api/users`, `POST /api/users`, `PUT /api/users/{id}/roles`, `POST /api/users/{id}/disable` | `users.manage` | Manage users |
| `GET /api/tokens`, `POST /api/tokens`, `DELETE /api/tokens/{id}` | `tokens.manage` | Manage tokens. `name` and `kind` (`edge` or `user`) are required. User tokens need `expires_in` (for example `"720h"`, at most `8760h`); their `scopes` must be permissions you hold |
| `GET /v1/snapshot`, `POST /v1/edge/report` | edge token | The edge polls its policy (with `If-None-Match`) and reports its stats |
| `POST /v1/logs/access` | `logs.ingest` | The log shipper posts edge access lines as newline-delimited JSON. Only the token in admin's `LOG_INGEST_TOKEN_FILE` holds this permission; a `429` means admin is busy and the batch should be sent again |
| `GET /api/autopilot` | `autopilot.read` | [Autopilot](../use/autopilot.md) state: `mode`, `agent_connected`, the runners seen in the last day, `credentials` (whether a connected runner holds a credential for `claude` and for `openai`; never the credential itself), `warnings` (such as a model whose provider no connected runner can run), `budgets` with what they use, `cases_open`, the live autopilot `rules` (each with the `host` and `path_prefix` its conditions fix), the active `exclusions`, `spend`, `spend_days` and `precision`. `spend` has `last_24h` and `last_7d`, each with `runs` (finished runs started in the window), `unpriced_runs` (those whose model had no price), `configured_usd_micros` and `provider_usd_micros`. `spend_days` has a row per UTC day, `provider` and `model` for the finished runs started in the last 14 UTC days, today included, newest day first: `day` (`YYYY-MM-DD`), `runs`, `cases` (distinct cases, so a retried case counts once), `unpriced_runs`, `configured_usd_micros` and `provider_usd_micros`. `precision` has a row per `model` and `prompt_sha256` with `correct` (expired after enforcing, or adopted) and `wrong` (rolled back, or retired as a false positive) for enforce rules that ended in the last 7 days |
| `GET /api/autopilot/contract` | `autopilot.read` | What a claim gives the runner, less the case: `prompt`, `prompt_sha256`, `tools` (each `name`, `permission`, `description`, `input_schema` and `evidence`, true for a `stats.read` or connector tool, whose successful runner call answers an `evidence_id`; only this deployment's tools), `tools_sha256` (the hash of the tools without `evidence`) and `output_schema`. Replay reads it |
| `GET /api/settings/autopilot` | `autopilot.read` | Autopilot settings |
| `PUT /api/settings/autopilot` | `settings.manage` | Change them. An optional `reason`, at most 500 characters, goes into the audit row only. `422` when `default_ttl` or `max_ttl` is under 4 times (30 seconds plus `min_publish_interval`), the shortest TTL a rule can be renewed within; when `default_ttl` is not over `observe_for` plus `min_publish_interval` and 30 seconds; or when the protected networks and the active exclusions don't fit in half of an expression. Setting `mode` to `off` is the kill switch: in one transaction it retires every autopilot rule, cancels open cases and publishes the active version without autopilot rules. `409` while a canary runs |
| `GET /api/autopilot/cases`, `GET /api/autopilot/cases/{id}` | `autopilot.read` | The latest 100 cases (`rule` filters by rule); one case with its `runs` (with `prompt_sha256`, `tools_sha256`, token counts, costs and `error_category`), `proposals` (with `rule`, `ttl_seconds`, `evidence` and `checks`), rule `transitions`, `tool_calls` (every MCP call its runs made, by run and `seq`, each with `at` and `payload`; a call's `result` needs both `stats.read` and `config.read`, and a [connector](#mcp-tools) call's also `autopilot.manage`; without them `result` is left out, `hidden` is `true` and `hidden_reason` names the permissions needed, and a hidden connector call also leaves out its `arguments` and `refusal`, since its query is part of what it read) and the `rules` it made, each with its state, outcome and expression as text |
| `POST /api/autopilot/cases` | `autopilot.manage` | Investigate: open a case on at most one of `rule`, `route_id` or `anomaly_id`, with an optional `question`, or on a `question` alone. `422` when it names more than one target, names none and asks nothing, or has a `rule` over 200 characters or a `question` over 2,000. `409` while autopilot is off, when no runner was seen in the last 2 minutes, when a case on the same target (or the same question) is open, or when 100 cases are open |
| `POST /api/autopilot/rules/{id}/enforce` | `autopilot.manage` | Approve an observing enforce rule in `observe` mode; the next tick makes it block. `409` with `observed_too_short` before `observe_for` has passed |
| `POST /api/autopilot/rules/{id}/retire` | `autopilot.manage` | End an autopilot rule. Body: `reason` (required), `false_positive`. A false positive is not proposed again for `max_lifetime` |
| `GET /api/autopilot/exclusions` | `autopilot.read` | The [exclusions](../use/autopilot.md#exclusions) active now, and those revoked or expired in the last 30 days, newest first, at most 200 |
| `POST /api/autopilot/exclusions` | `autopilot.manage` | Exclude a client: `subject` (an IP, or a CIDR of at least /24 for IPv4 or /48 for IPv6), `host`, `path_prefix` (optional, starting with `/`), `reason` (1 to 500 characters), `ttl` (1h to 8760h; left out, it never expires) and `rule_id` (optional: a proposed or observing sensor, whose host and path prefix fill those left empty, and which is retired). `201` with the exclusion; `422` with the field at fault, or when the exclusions and protected networks would take over half of an expression |
| `POST /api/autopilot/exclusions/{id}/revoke` | `autopilot.manage` | Revoke an exclusion. Body: `reason`, 1 to 500 characters. `204`; `409` when there is no such exclusion or it is revoked already |
| `GET /api/autopilot/notes` | `autopilot.read` | The newest 500 autopilot [notes](../use/autopilot.md#memory); `trust` and `scope_key` filter exactly |
| `GET /api/autopilot/notes/{id}` | `autopilot.read` | One note with its `revisions`, its last 200 `uses`, its cited reads as `evidence` (each with its run event's `payload`, which needs both `stats.read` and `config.read`, and for a connector read also `autopilot.manage`; without them it is left out, `hidden` is `true` and `hidden_reason` names the permissions needed) and `blast_radius`: the `cases` served it, the `proposals` that cited it and the `enforcing_rules` of those proposals |
| `POST /api/autopilot/notes/{id}/retract` | `autopilot.manage` | Retract a note. Body: `reason`, 1 to 500 characters. `204`; `409` when it is retracted or retired already, naming its trust as read in the retraction's transaction |
| `POST /api/autopilot/notes/{id}/reevaluate` | `autopilot.manage` | Open an investigate case on each rule still enforcing that cites the note; answers the `cases` opened. `409` while autopilot is off or no runner was seen in the last 2 minutes, as for `POST /api/autopilot/cases`, and when no enforcing rule cites it |
| `GET /api/autopilot/prices` | `autopilot.read` | Model prices, in USD per million tokens, newest first |
| `POST /api/autopilot/prices` | `settings.manage` | Add a price: `provider` (`claude` or `openai`), `model`, `input_usd_per_mtok`, `output_usd_per_mtok`, `cache_read_usd_per_mtok`, `cache_write_usd_per_mtok` (0 to 1000 each) and `effective_from`. A run is priced at the row in effect when it started |
| `POST /v1/autopilot/claim` | `autopilot.agent` | The runner long-polls for a case, up to `wait` (default and most `30s`), sending `runner`, `version`, `sdk_version` and `providers`, the providers it holds a credential for. Answers the case, its run, the lease, the model and its provider, the system prompt with `prompt_sha256`, `tools_sha256` and the output schema; `204` with no case, while autopilot is off or when `cases_per_hour` is spent. It takes the oldest queued case whose model's provider it holds. `409` when cases are queued and it holds the provider of none of them |
| `POST /v1/autopilot/cases/{id}/heartbeat` | `autopilot.agent` | Extend the 10 minute lease of `run_id`, and update `providers`. `409` once the lease lapsed |
| `POST /v1/autopilot/cases/{id}/result` | `autopilot.agent` | The run's verdict (`attack`, `benign` or `unsure`), `summary`, `proposals`, `status`, `usage`, `provider_cost_usd`, the transcript's size and hash and `last_seq`. A result after the lease lapsed is kept as `lease_lost` and answers `409` |
| `POST /v1/autopilot/runs/{id}/events` | `autopilot.agent` | Runner events of a run (`seq`, `kind`, `at`, `payload`), at most 1 MiB a batch. An event over 64 KiB is kept as its size and hash; a run keeps at most 1,000 events and 4 MiB, past which a batch gets `409` |
| `POST /v1/mcp` | signed in, with a bearer token only; each [tool](#mcp-tools) checks its own permission | The [MCP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) server the runner and Claude Code call. A session cookie gets `401` |

## MCP tools

`POST /v1/mcp` is a stateless MCP server: every request is one JSON-RPC call answered as JSON. A user token reaches the tools its scopes allow; the runner's `AUTOPILOT_TOKEN_FILE` token reaches every tool, and its calls must send `X-Autopilot-Run` naming a run in progress. `tools/list` shows only the tools the token can call, and a connector's tools only where the deployment sets that [connector](../deploy/admin.md#connectors). Each token has at most 4 calls in progress; each call has 5 seconds (a connector call 10), a result of at most 64 KiB and a window of at most 20160 minutes (14 days). Values clients wrote, such as paths and hosts, sit inside fields named `untrusted`. Every call the runner makes is kept as an admin event of its run. A successful call of a `stats.read` or connector tool by the runner, kept whole, also answers its `evidence_id`, the event's `seq`, as a second text content `{"evidence_id":N}` and as a field of the structured result; a note cites it as evidence.

The six connector tools (`prom_query`, `prom_query_range`, `grafana_annotations`, `grafana_dashboards`, `dd_query_metrics`, `dd_search_logs`) read the deployment's own Prometheus, Grafana and Datadog, set in [Admin settings](../deploy/admin.md#connectors). Only the runner's token calls them, since a connector reaches whatever its credentials do. Each answer names its `connector`, has every string, keys included, scrubbed of what looks like a credential, and is cut to at most 48 KiB by leaving out trailing items, which `more` counts. A failed connector request is a tool error.

| Tool | Permission | Returns |
|---|---|---|
| `get_autopilot_state` | `autopilot.read` | What `GET /api/autopilot` returns, with each rule's expression inside an `untrusted` field |
| `list_cases` | `autopilot.read` | Past cases and verdicts, on one `rule` when set. An ablation run's list leaves out ablation cases and the cases its withheld notes were served to |
| `list_rules` | `config.read` | The active version's rate-limit and config rules (not request-header rules), people's and the autopilot's, with expressions as text inside `untrusted` fields |
| `describe_fields` | `config.read` | Expression fields, rate-limit key kinds and algorithms |
| `get_stats` | `stats.read` | `GET /api/stats` for `minutes`, in hourly steps past 360 minutes |
| `get_rule_stats` | `stats.read` | One rate-limit rule's counts per minute (hourly past 360 minutes) and its 50 most-limited subjects |
| `list_anomalies` | `stats.read` | What `GET /api/anomalies` returns |
| `list_routes` | `stats.read` | What `GET /api/observed-routes` returns for `hours` (default 24), busiest first, at most `limit` (1 to 200, default 50) |
| `get_route` | `stats.read` | What `GET /api/observed-routes/{id}` returns |
| `check_subject` | `stats.read` | Whether an `ip` is in a verified crawler range or a protected subject |
| `list_versions` | `config.read` | Recent versions with source, author and change summary |
| `get_case` | `autopilot.agent` | The run's case: trigger, evidence and prior cases on the same rule |
| `validate_rule` | `autopilot.agent` | The policy checks and the compile of a rule with the live rules, and the `notes` it cites, without proposing it. Its `rule`, as in `simulate_rule` and `propose`, takes `expression` (text), `algorithm`, `limit`, `period`, `key` and `on_missing_key`, and optionally `burst`, `penalty`, `distinct_of`, `count_statuses` (upstream statuses or classes from 1xx to 4xx to count instead of requests, as in [Counting responses](../use/rate-limiting.md#counting-responses)) and `fail_mode` |
| `simulate_rule` | `autopilot.agent` | Which rules, the candidate included, match up to 20 test requests |
| `propose` | `autopilot.agent` | Propose `add_sensor`, `enforce` or `retire` (of a proposed or observing sensor only), with up to 5 `notes` that `search_notes` served the run; refused in an ablation run; answers `proposal_id`, `accepted`, the new `rule_id`, and `reasons` with each check |
| `record_learning` | `autopilot.agent` | Record a [note](../use/autopilot.md#memory) through the gate; answers `note_id`, `trust`, `anchor` and the `stats` admin computed, or the reason it refused |
| `search_notes` | `autopilot.read` | Notes, newest first, at most 20, by `scope` and `kind`. For a run it checks the 20 newest unconfirmed and confirmed notes, less those an ablation withholds, and serves those whose claim matches now and hypotheses, each check recorded; notes past the answer's 56 KiB cap are neither served nor recorded, and a narrower `scope` or `kind` reaches them; a person's token gets every note not retracted or retired, with `matches_now`, and records nothing |
| `prom_query` | `autopilot.agent` | A PromQL instant `query` (1 to 2,000 characters) on `PROMETHEUS_URL`: `result_type`, up to 50 `series` of `{labels, value}` with the labels inside `untrusted`, `more` (series left out) and `link` from `METRICS_LINK_URL`, or `null`. A scalar or string result answers `value` instead of `series` |
| `prom_query_range` | `autopilot.agent` | A PromQL `query` over the last `minutes` (default 60), at a step of 60 seconds or `minutes` seconds, whichever is larger: `from`, `to`, `step_seconds`, up to 10 `series` of `{labels, points}` with at most 60 points each, `more` and `link` |
| `grafana_annotations` | `autopilot.agent` | Annotations on `GRAFANA_URL` over the last `minutes` (default 1,440), with every one of up to 5 `tags`, at most `limit` (1 to 100, default 100): `id`, `time`, `time_end`, `text` and `tags` inside `untrusted`, `dashboard_uid` and a `link` to its dashboard |
| `grafana_dashboards` | `autopilot.agent` | Dashboards whose title matches `query` (up to 200 characters), at most `limit` (1 to 20, default 20): `uid`, `title` inside `untrusted`, `url` on `GRAFANA_URL` and `tags` |
| `dd_query_metrics` | `autopilot.agent` | A Datadog metrics `query` (1 to 2,000 characters) over the last `minutes` (default 60): `from`, `to`, up to 10 `series` of `{metric, scope, points}`, the scope inside `untrusted`, every k-th point so at most 60 remain, and `more`. `link` is `null`: Datadog documents no URL form for a query |
| `dd_search_logs` | `autopilot.agent` | Datadog logs matching `query` over the last `minutes` (default 15), newest first, at most `limit` (1 to 50, default 50): `lines` inside `untrusted`, each `timestamp`, `service`, `host`, `status` and `message` cut to 500 characters, and `more` when there were more. `link` is `null` |

## Example: publish from CI

```bash
API=https://admin.internal
AUTH="Authorization: Bearer $EDGE_POLICY_TOKEN"   # a user token scoped to config.read, config.write and config.publish

etag=$(curl -sfI -H "$AUTH" $API/api/draft | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')
curl -sf -X PUT -H "$AUTH" -H 'Content-Type: application/json' -H "If-Match: $etag" --data @policy.json $API/api/draft

etag=$(curl -sfI -H "$AUTH" $API/api/draft | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')
curl -sf -X POST -H "$AUTH" -H 'Content-Type: application/json' -H "If-Match: $etag" \
  -d '{"message":"deploy 1234"}' $API/api/publish
```

`policy.json` holds `{"config": ..., "tests": [...]}`, as returned by `GET /api/draft`.
