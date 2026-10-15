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
| `CLIENT_IP_SOURCE`, `VIEWER_HEADERS`, `UPSTREAMS`, `ALLOW_REGEX`, `INGRESS_SECRET_HEADER` | as the edge | Must match the edges, so admin validates policy against the real deployment (for example, that a rule's upstream exists). Publishing returns 409 while a live edge reports different values |
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
| Stats retention | 30 days |

Guard settings are changed in the UI (**Settings → Rollback guard**). A change to `evaluate_every` takes effect when leadership next changes, for example on the next admin restart.
