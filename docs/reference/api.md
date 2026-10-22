# Admin API

Everything the UI does goes through this JSON API, so it can be automated. Authenticate with `Authorization: Bearer <token>` (a user token from **Users**) or the UI's session cookie. Cross-origin browser writes are refused. Errors are `application/problem+json` with the failing field and reason.

Draft writes and publish use optimistic concurrency: send the `ETag` from the last read as `If-Match`. A stale value gets `412`, and a missing one `428`.

## Endpoints

| Method and path | Permission | Does |
|---|---|---|
| `POST /api/auth/login` | public | Session sign-in |
| `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/password` | signed in | Sign out, current user, change password |
| `GET /api/roles` | signed in | Roles and their permissions |
| `GET /api/draft` | `config.read` | Read the draft (`{config, tests}`) |
| `PUT /api/draft` | `config.write` | Replace the draft; a save validates everything |
| `POST /api/draft/check` | `config.read` | Validate a `{config}` as a save would, without saving: returns `{errors, warnings}`, each with its path |
| `GET /api/draft/rebase` | `config.read` | Preview a rebase onto the active version |
| `POST /api/draft/rebase` | `config.write` | Apply it |
| `GET /api/expr/schema`, `POST /api/expr/parse`, `POST /api/expr/render`, `POST /api/expr/validate` | `config.read` | Fields and operators, and the values rule settings and config sections take (such as algorithms, content types, JWT algorithms and HTTP methods); convert between text and tree; validate |
| `POST /api/tests/run`, `POST /api/simulate` | `config.test` | Run the draft's tests; simulate one request. A mistyped client IP is a 422 with an error at `request.ip` |
| `POST /api/publish` | `config.publish` (plus `canary.manage` with `canary_percent`) | Publish the draft. Body: `message`, optional `canary_percent`, `override_reason`, `guard_override` with `guard_override_reason` |
| `GET /api/versions`, `GET /api/versions/{v}` | `config.read` | List and read versions |
| `GET /api/diff/{a}/{b}`, `GET /api/rules/{id}/history` | `config.read` | Compare versions; one rule's history |
| `POST /api/versions/{v}/revert` | `config.rollback` | Publish version `v`'s config as a new version. Body: `reason` (required), optional `override_reason`, `canary_percent` (needs `canary.manage`), `guard_override` with `guard_override_reason` |
| `POST /api/versions/{v}/copy-to-draft` | `config.write` | Start the draft from version `v` |
| `GET /api/canary` | `config.read` | Canary state |
| `POST /api/canary/step`, `POST /api/canary/promote`, `POST /api/canary/abort` | `canary.manage` | Step (`percent`), promote, abort (`reason`) |
| `GET /api/export` | `config.read` | Export the active version as `{envelope, tests}` (`envelope` is an edge bootstrap file) |
| `POST /api/import` | `config.publish` | Publish `{config, tests, message, override_reason}` as a new version |
| `GET /api/settings/guard` | `config.read` | Default guard settings |
| `PUT /api/settings/guard` | `settings.manage` | Change them |
| `GET /api/fleet`, `GET /api/stats` | `stats.read` | Edges and their versions; per-minute stats for the last `minutes` |
| `GET /api/observed-routes`, `GET /api/observed-routes/{id}` | `stats.read` | Routes built from access logs, with traffic, status mix, latency and grouping suggestions (`hours` sets the range); one route with its hourly series |
| `GET /api/observed-routes/{id}/flow`, `GET /api/observed-routes/{id}/condition` | `config.read` | What a version does to a request like this route's (`version`: a number or `draft`; the live version when omitted); an expression that matches the route, to start a new rule |
| `DELETE /api/observed-routes`, `DELETE /api/observed-routes/{id}` | `routes.manage` | Delete every route, or one. Routes are collected again from new access logs |
| `GET /api/route-patterns` | `stats.read` | Patterns that group similar paths into one route |
| `POST /api/route-patterns`, `DELETE /api/route-patterns/{id}` | `routes.manage` | Add a pattern (existing routes it covers are merged into it), or remove one |
| `GET /api/audit` | `audit.read` | Read the audit log, newest first, 100 rows per page. `actor`, `action` and `target` match exactly; `mentions` matches part of the target or details; `before` takes a `seq` to page |
| `POST /api/audit/verify`, `POST /api/audit/export` | `audit.read` | Verify the chain, or export every row with its HMAC as a streamed JSON array. Both are POST because each writes its own audit row |
| `GET /api/users`, `POST /api/users`, `PUT /api/users/{id}/roles`, `POST /api/users/{id}/disable` | `users.manage` | Manage users |
| `GET /api/tokens`, `POST /api/tokens`, `DELETE /api/tokens/{id}` | `tokens.manage` | Manage tokens. `name` and `kind` (`edge` or `user`) are required. User tokens need `expires_in` (for example `"720h"`, at most `8760h`); their `scopes` must be permissions you hold |
| `GET /v1/snapshot`, `POST /v1/edge/report` | edge token | The edge polls its policy (with `If-None-Match`) and reports its stats |
| `POST /v1/logs/access` | `logs.ingest` | The log shipper posts edge access lines as newline-delimited JSON. Only the token in admin's `LOG_INGEST_TOKEN_FILE` holds this permission; a `429` means admin is busy and the batch should be sent again |

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
