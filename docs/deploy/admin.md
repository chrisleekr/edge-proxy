# Admin settings

Environment variables only. The image's commands:

| Command | Does |
|---|---|
| `serve` (default) | Runs the API and UI on `LISTEN_ADDR`, and `/metrics` on `ADMIN_INTERNAL_ADDR` |
| `migrate` | Applies database migrations and grants the runtime role. Needs `MIGRATION_DATABASE_URL` and `DB_RUNTIME_ROLE` |
| `create-user <name> <role> [role ...]` | Creates a user; the password is the first line of stdin. Needs every `serve` variable |

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | required | Postgres URL for the runtime role |
| `AUDIT_HMAC_KEY_ID` | required | Name of the current audit key, recorded on every audit row |
| `AUDIT_HMAC_KEY` | required | Base64, at least 32 bytes. Keep it in a secret store, never in Postgres |
| `AUDIT_HMAC_PREVIOUS_KEYS` | none | `id=base64,...` of retired keys, so older rows still verify |
| `LISTEN_ADDR` | `:8081` | |
| `ADMIN_INTERNAL_ADDR` | `:9091` | Serves only `GET /metrics` ([Admin metrics](../operate/monitoring.md#admin-metrics)), with no authentication. Never expose it publicly; let only your metrics scraper reach it. Admin exits at start if it can't listen here |
| `SESSION_IDLE_TIMEOUT` | `30m` | Sign-out after inactivity |
| `SESSION_MAX_AGE` | `12h` | Sign-out regardless of activity |
| `PASSWORD_BLOCKLIST_PATH` | none | File of refused passwords, one per line, matched case-insensitively |
| `JWKS_ALLOWED_HOSTS` | none | Same as the edge's: JWKS hosts allowed to resolve to private addresses |
| `VERIFIED_BOT_SOURCES` | none | Comma-separated `https` URLs, at most 16, of crawler IP range lists in the JSON format Google publishes. For Google use only `https://developers.google.com/static/crawling/ipranges/common-crawlers.json` and `https://developers.google.com/static/crawling/ipranges/special-crawlers.json` (see [verifying Googlebot](https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot)). Never add the user-triggered fetcher lists: they cover fetches other people control, such as Google Cloud customers' fetchers, so they must not exempt anyone. No query, credentials or fragment. The leader fetches each every 10 minutes through the same SSRF guard as JWKS, so `JWKS_ALLOWED_HOSTS` applies; a list may be 512 KiB with 1 to 2,000 prefixes. A changed list is stored and audited as `verified_bots.changed`; a failed fetch keeps the last good list; a URL removed from the variable is dropped and audited as `verified_bots.removed`. Without this variable, validation refuses any rule that reads `client.verified_bot`; with it, the field is false until the first fetch succeeds. Edges get the ranges only while the active or canary version reads `client.verified_bot` |
| `ADMIN_TRUSTED_PROXIES` | none | CIDRs or IPs of admin's own HTTPS proxy. Login throttling and audit then use the rightmost `X-Forwarded-For` address it didn't add; without it every user shares the proxy's login budget |
| `INSTANCE` | hostname | Replica name |
| `LOG_SEARCH_URL` | none | Your log store's search, as an http or https URL template with no credentials, such as `https://logs.example.com/search?q=status:{status}%20host:{host}&from={from}&to={to}`. **Stats**, **Dashboard**, a route and an anomaly then link their counts to the matching access lines there; admin stores counts only. Placeholders: `{from}` and `{to}` (RFC 3339), `{from_ms}` and `{to_ms}` (Unix milliseconds), `{status}` and `{host}`, each URL-encoded. A link is shown only where every placeholder the template uses has a value: an anomaly has a time range but no status or host. It is returned to every user with `stats.read`, so no token or key may appear anywhere in it; links rely on the user's own sign-in to the log store |
| `ALERTMANAGER_URL` | none | Alertmanager's base URL, such as `http://alertmanager.monitoring.svc:9093`. Admin posts [anomaly notifications](../operate/notifications.md) to its `/api/v2/alerts`. Without it, anomalies are only shown in admin |
| `CLIENT_IP_SOURCE`, `VIEWER_HEADERS`, `ALLOW_REGEX`, `INGRESS_SECRET_HEADER` | as the edge | Must match the edges, so admin validates policy against the real deployment (for example, that a rule's viewer field has a trusted source). Publishing returns 409 while a live edge reports different values. Admin doesn't need `UPSTREAM_URL` |
| `LOG_INGEST_TOKEN_FILE` | none | File holding the log shipper's token, at least 32 characters. It may only post edge access lines to `/v1/logs/access`, from which admin builds **Routes**. It must differ from the `EDGE_SERVICE_TOKEN_FILE` token; admin refuses to start otherwise |
| `AUTOPILOT_TOKEN_FILE` | none | File holding the [autopilot](../use/autopilot.md) runner's token, at least 32 characters. It holds only `autopilot.agent`: claim cases, report results and call the MCP tools, as actor `deployment:autopilot`. It must differ from the `EDGE_SERVICE_TOKEN_FILE` and `LOG_INGEST_TOKEN_FILE` tokens; admin refuses to start otherwise. Give the autopilot runner the same token. Unset, no runner can connect |
| `PROMETHEUS_URL` | none | Prometheus's base URL, such as `http://prometheus:9090`, for the autopilot's `prom_query` and `prom_query_range` [tools](../reference/api.md#mcp-tools). http or https with a host, and no credentials, query or fragment; a path is allowed, such as Grafana Cloud's `/api/prom`. Unset, the tools are not listed. See [Connectors](#connectors) |
| `PROMETHEUS_TOKEN_FILE` | none | File holding a bearer token for `PROMETHEUS_URL`. Set it only with `PROMETHEUS_URL` |
| `GRAFANA_URL`, `GRAFANA_TOKEN_FILE` | none | Grafana's base URL, with the same rules as `PROMETHEUS_URL`, and a file holding a service account token, for the `grafana_annotations` and `grafana_dashboards` tools. Set both or neither |
| `DATADOG_SITE` | none | Your Datadog [site](https://docs.datadoghq.com/getting_started/site/), for the `dd_query_metrics` and `dd_search_logs` tools: `datadoghq.com`, `us3.datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`, `ap1.datadoghq.com`, `ap2.datadoghq.com`, `uk1.datadoghq.com`, `ddog-gov.com` or `us2.ddog-gov.com`. Admin calls `https://api.<site>` |
| `DATADOG_API_KEY_FILE`, `DATADOG_APP_KEY_FILE` | none | Files holding a Datadog API key and application key. Both are required with `DATADOG_SITE`, and refused without it |
| `METRICS_LINK_URL` | none | A link template for a Prometheus query a person can open, such as Prometheus's own `https://prometheus.example.com/query?g0.expr={query}&g0.tab=graph&g0.range_input=1h`: http or https, no credentials, and it must contain `{query}`. `{query}`, `{from_ms}` and `{to_ms}` (Unix milliseconds) are URL-encoded. Prometheus's own UI takes no Unix milliseconds, so its link shows the range ending when it is opened, not the window the tool queried. The Prometheus tools answer it as `link`; unset, `link` is `null`. Needs `PROMETHEUS_URL` |
| `EDGE_SERVICE_TOKEN_FILE` | none | File holding an edge token defined by the deployment, at least 32 characters: give the edges the same file and they need no token created in the UI. It is accepted alongside tokens created in admin, cannot be revoked there, and rotates by changing the file and restarting admin and the edges |
| `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD_FILE` | none | Set both to create this user with the `admin` role at start when no user exists yet. The password is the file's first line and must pass the password rules. Once any user exists, nothing changes |
| `BOOTSTRAP_PUBLISH_DEFAULT` | `false` | `true` publishes the starter policy at start when no version has ever been published, so edges on a fresh install load a policy and become ready. It has no rules, so every request goes to `UPSTREAM_URL`, with a per-IP backstop of 100 requests a second (burst 200) |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS`, `TRACE_SAMPLE_RATE`, `TRACE_MAX_PER_SECOND`, `TRACE_SHUTDOWN_TIMEOUT` | as the edge | [Tracing](edge.md#tracing), off unless an endpoint is set. Admin traces `/api/` requests, with a span per Postgres query. On admin, `TRACE_SHUTDOWN_TIMEOUT` bounds only the final flush, and a caller's sampled flag is followed only from `ADMIN_TRUSTED_PROXIES`; see [Monitoring](../operate/monitoring.md#admin-traces) |
| `OTEL_SERVICE_NAME` | `edge-proxy-admin` | `service.name` on admin's spans |
| `MIGRATION_DATABASE_URL` | `migrate` only | Postgres URL for the owner role |
| `DB_RUNTIME_ROLE` | `migrate` only | The role `DATABASE_URL` connects as |

## Connectors

The Prometheus, Grafana and Datadog connectors let [autopilot](../use/autopilot.md#external-metrics-and-logs) runs read your own metrics, dashboards and logs. Each is optional, and its tools are listed only when it is set. Admin calls them directly with the deployment's credentials, from the URL you set, so they don't go through the SSRF guard.

The model chooses the queries, so it can read whatever the credentials can, and each answer is kept in the run's record. Give each connector read-only credentials scoped to what the autopilot needs:

- **Prometheus:** a token that can only query, or none where Prometheus is reachable only from admin.
- **Grafana:** a [service account](https://grafana.com/docs/grafana/latest/administration/service-accounts/) with the `Viewer` role.
- **Datadog:** an application key [scoped](https://docs.datadoghq.com/account_management/api-app-keys/#scope-application-keys) to `timeseries_query` and `logs_read_data`, the permissions of the [metrics query](https://docs.datadoghq.com/api/latest/metrics/#query-timeseries-points) and [log search](https://docs.datadoghq.com/api/latest/logs/#search-logs-post) endpoints.

Admin sends the `PROMETHEUS_TOKEN_FILE` and `GRAFANA_TOKEN_FILE` tokens as bearer tokens over whatever scheme `PROMETHEUS_URL` and `GRAFANA_URL` name. Use https, or plain http only on a network path with equivalent protection, such as mesh mTLS: a bearer token is usable by whoever reads it, so [RFC 6750 section 5.3](https://www.rfc-editor.org/rfc/rfc6750#section-5.3) requires TLS or equivalent. Datadog is always called over https.

A token file holds one token of printable ASCII with no spaces; surrounding whitespace is trimmed. Admin refuses to start when a file can't be read, is empty or holds anything else, and its messages never repeat a token.

Each call has 10 seconds and reads at most 256 KiB of the answer. A redirect is an error, so a token is never sent to another host. A non-2xx answer becomes a tool error with its status and the first 200 bytes of the body, with anything that looks like a credential redacted. Every result is counted in [`admin_connector_requests_total`](../operate/monitoring.md#admin-metrics).

## Fixed behaviour

These are not configurable:

| What | Value |
|---|---|
| Sign-in throttle | 10 sign-in attempts per 15 minutes per user and IP; 100 per user; 100 per IP. An IP the user signed in from in the last 30 days (remembered in memory by each admin replica) skips the per-user budget, so attackers can't lock users out |
| User token lifetime | At most 365 days |
| Background jobs | Run on one replica, chosen by a Postgres advisory lock. A second replica takes over within about 10 seconds after the leader's database connection closes |
| JWKS refresh | Every 10 minutes |
| Audit verification | Incremental every 5 minutes, full every 24 hours |
| Anomaly checks | Every minute |
| Retention | 30 days of per-minute stats, **Routes** hours and resolved anomalies. Edges in **Fleet** and routes not seen for 30 days are removed |

Guard settings are changed in the UI (**Settings → Rollback guard**), notification settings on **Notifications**. A change to `evaluate_every` takes effect when leadership next changes, for example on the next admin restart.
