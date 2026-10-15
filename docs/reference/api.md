# Admin API

Everything the UI does goes through this JSON API, so it can be automated. Authenticate with `Authorization: Bearer <token>` (a user token from **Users**) or the UI's session cookie. Cross-origin browser writes are refused. Errors are `application/problem+json` with the failing field and reason.

Draft writes and publish use optimistic concurrency: send the `ETag` from the last read as `If-Match`. A stale value gets `412`.

## Endpoints

| Method and path | Permission | Does |
|---|---|---|
| `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/password` | public / signed in | Session sign-in, sign-out, current user, change password |
| `GET /api/draft`, `PUT /api/draft` | `config.read`, `config.write` | Read or replace the draft (`{config, tests}`); a save validates everything |
| `GET`, `POST /api/draft/rebase` | `config.read`, `config.write` | Preview or apply a rebase onto the active version |
| `GET /api/expr/schema`; `POST /api/expr/parse`, `/render`, `/validate` | `config.read` | Fields and operators; convert between text and tree; validate |
| `POST /api/tests/run`, `POST /api/simulate` | `config.test` | Run the draft's tests; simulate one request |
| `POST /api/publish` | `config.publish` (plus `canary.manage` with `canary_percent`) | Publish the draft. Body: `message`, optional `canary_percent`, `override_reason`, `guard_override` with `guard_override_reason` |
| `GET /api/versions`, `GET /api/versions/{v}` | `config.read` | List and read versions |
| `GET /api/diff/{a}/{b}`, `GET /api/rules/{id}/history` | `config.read` | Compare versions; one rule's history |
| `POST /api/versions/{v}/revert` | `config.rollback` | Publish version `v`'s config as a new version. Body: `reason` (required), optional `override_reason`, `canary_percent` (needs `canary.manage`), `guard_override` with `guard_override_reason` |
| `POST /api/versions/{v}/copy-to-draft` | `config.write` | Start the draft from version `v` |
| `GET /api/canary`; `POST /api/canary/step`, `/promote`, `/abort` | `config.read`; `canary.manage` | Canary state; step (`percent`), promote, abort (`reason`) |
| `GET /api/export`, `POST /api/import` | `config.read`, `config.publish` | Export the active version as `{envelope, tests}` (`envelope` is an edge bootstrap file); import publishes `{config, tests, message, override_reason}` as a new version |
| `GET`, `PUT /api/settings/guard` | `config.read`, `settings.manage` | Default guard settings |
| `GET /api/fleet`, `GET /api/stats?minutes=` | `stats.read` | Edges and their versions; per-minute stats |
| `GET /api/audit` | `audit.read` | Read the audit log, newest first, 100 rows per page |
| `POST /api/audit/verify`, `POST /api/audit/export` | `audit.read` | Verify the chain, or export every row with its HMAC as a streamed JSON array. Both are POST because each writes its own audit row |
| `GET /api/roles` | signed in | Roles and their permissions |
| `GET`, `POST /api/users`; `PUT /api/users/{id}/roles`; `POST /api/users/{id}/disable` | `users.manage` | Manage users |
| `GET`, `POST /api/tokens`; `DELETE /api/tokens/{id}` | `tokens.manage` | Manage tokens. `name` and `kind` (`edge` or `user`) are required. User tokens need `expires_in` (for example `"720h"`, at most `8760h`); their `scopes` must be permissions you hold |

Edges use two more endpoints with their edge token: `GET /v1/snapshot` (with `If-None-Match`) and `POST /v1/edge/report`.

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
