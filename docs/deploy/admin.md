# Admin settings

Environment variables only. The image's commands:

| Command | Does |
|---|---|
| `serve` (default) | Runs the API and UI on `LISTEN_ADDR` |
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
| `SESSION_IDLE_TIMEOUT` | `30m` | Sign-out after inactivity |
| `SESSION_MAX_AGE` | `12h` | Sign-out regardless of activity |
| `PASSWORD_BLOCKLIST_PATH` | none | File of refused passwords, one per line, matched case-insensitively |
| `JWKS_ALLOWED_HOSTS` | none | Same as the edge's: JWKS hosts allowed to resolve to private addresses |
| `ADMIN_TRUSTED_PROXIES` | none | CIDRs or IPs of admin's own HTTPS proxy. Login throttling and audit then use the rightmost `X-Forwarded-For` address it didn't add; without it every user shares the proxy's login budget |
| `INSTANCE` | hostname | Replica name |
| `CLIENT_IP_SOURCE`, `VIEWER_HEADERS`, `ALLOW_REGEX`, `INGRESS_SECRET_HEADER` | as the edge | Must match the edges, so admin validates policy against the real deployment (for example, that a rule's viewer field has a trusted source). Publishing returns 409 while a live edge reports different values. Admin doesn't need `UPSTREAM_URL` |
| `LOG_INGEST_TOKEN_FILE` | none | File holding the log shipper's token, at least 32 characters. It may only post edge access lines to `/v1/logs/access`, from which admin builds **Routes**. It must differ from the `EDGE_SERVICE_TOKEN_FILE` token; admin refuses to start otherwise |
| `EDGE_SERVICE_TOKEN_FILE` | none | File holding an edge token defined by the deployment, at least 32 characters: give the edges the same file and they need no token created in the UI. It is accepted alongside tokens created in admin, cannot be revoked there, and rotates by changing the file and restarting admin and the edges |
| `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD_FILE` | none | Set both to create this user with the `admin` role at start when no user exists yet. The password is the file's first line and must pass the password rules. Once any user exists, nothing changes |
| `BOOTSTRAP_PUBLISH_DEFAULT` | `false` | `true` publishes the starter policy at start when no version has ever been published, so edges on a fresh install load a policy and become ready. It has no rules, so every request goes to `UPSTREAM_URL`, with a per-IP backstop of 100 requests a second (burst 200) |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS`, `TRACE_SAMPLE_RATE`, `TRACE_MAX_PER_SECOND`, `TRACE_SHUTDOWN_TIMEOUT` | as the edge | [Tracing](edge.md#tracing), off unless an endpoint is set. Admin traces `/api/` requests, with a span per Postgres query. On admin, `TRACE_SHUTDOWN_TIMEOUT` bounds only the final flush, and a caller's sampled flag is followed only from `ADMIN_TRUSTED_PROXIES`; see [Monitoring](../operate/monitoring.md#admin-traces) |
| `OTEL_SERVICE_NAME` | `edge-proxy-admin` | `service.name` on admin's spans |
| `MIGRATION_DATABASE_URL` | `migrate` only | Postgres URL for the owner role |
| `DB_RUNTIME_ROLE` | `migrate` only | The role `DATABASE_URL` connects as |

## Fixed behaviour

These are not configurable:

| What | Value |
|---|---|
| Sign-in throttle | 10 sign-in attempts per 15 minutes per user and IP; 100 per user; 100 per IP. An IP the user signed in from in the last 30 days (remembered in memory by each admin replica) skips the per-user budget, so attackers can't lock users out |
| User token lifetime | At most 365 days |
| Background jobs | Run on one replica, chosen by a Postgres advisory lock. A second replica takes over within about 10 seconds after the leader's database connection closes |
| JWKS refresh | Every 10 minutes |
| Audit verification | Incremental every 5 minutes, full every 24 hours |
| Retention | 30 days of per-minute stats and **Routes** hours. Edges in **Fleet** and routes not seen for 30 days are removed |

Guard settings are changed in the UI (**Settings → Rollback guard**). A change to `evaluate_every` takes effect when leadership next changes, for example on the next admin restart.
