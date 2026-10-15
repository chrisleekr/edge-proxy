# Runbooks

Traffic keeps flowing through every failure below. What changes is how policy is enforced.

| Failure | Traffic | Policy |
|---|---|---|
| Valkey down | Served | Each rate-limit rule follows its `fail_mode`; the local backstop still applies |
| Admin or Postgres down | Served | Edges keep their current policy. Publishing, stats, guard and the UI stop |
| Identity provider down | Served | Edges keep the last good keys |
| One edge down | Served by the others | Unchanged |

## Edge not ready

`/readyz` returns 503 only while no policy is loaded or while draining.

1. Check the edge log for `no snapshot source succeeded; staying not ready`.
2. Make sure admin is reachable from the edge, the edge token is valid (**Users → tokens**) and something has been published.
3. If admin is down, give the edge a cache file or a fresh bootstrap file ([Deploy](../deploy/index.md#where-an-edge-gets-its-policy)).

## Valkey down

1. Confirm with `edge_valkey_errors_total` and `edge_valkey_breaker_open_total`.
2. Rules with `fail_mode: open` allow traffic; `closed` answer 503; `local` enforce limit ÷ fleet size on each edge.
3. Nothing to do on the edges: they reconnect on their own, and each Valkey node has a breaker that retries every second.
4. After recovery, counters restart from what Valkey has; no state needs repair.

## Admin or Postgres down

1. Traffic is unaffected. Don't restart edges: a running edge keeps its policy, but a restarted one needs the cache or a bootstrap file.
2. Restore Postgres, then admin. Edges pick up the active version within about a minute (their poll backs off while admin is down).
3. Stats sent during the outage are lost; nothing else is.

## Identity provider down

1. Edges keep the last good keys and keep verifying tokens.
2. A token signed with a new key can't be verified until the IdP is back, and gets 401.
3. To publish a rule that needs an issuer whose keys were never fetched, use the publish override reason.

## A bad publish

1. **Versions → Revert to previous**, with a reason. It is a new version and reaches every edge within one poll.
2. During a canary, **Publish → Abort** instead.
3. The guard may already have done this; check **Versions** and **Audit**.

## Stop rate limiting or JWT checks now

**Settings → Kill switch**, then save and publish. **Disable rate limiting** makes every rate-limit rule log-only; **Disable JWT checks** stops requiring tokens. The per-IP backstop still applies. Both are audited. Turn them off the same way.

## Audit chain broken

`audit chain broken` means a row no longer matches its HMAC chain.

1. Check that `AUDIT_HMAC_KEY_ID`, `AUDIT_HMAC_KEY` and `AUDIT_HMAC_PREVIOUS_KEYS` are the values used when the rows were written. A missing previous key is the usual cause.
2. If the keys are right, treat it as tampering: export the log (**Audit → Export with HMACs**), compare it with the `audit anchor` lines admin logs, and investigate database access. Rows can't be repaired; the app never edits or deletes them.

## Rotate secrets

| Secret | How |
|---|---|
| Audit HMAC key | Add the current pair to `AUDIT_HMAC_PREVIOUS_KEYS` as `id=key`, set a new `AUDIT_HMAC_KEY_ID` and `AUDIT_HMAC_KEY`, restart admin |
| Edge token | Create a new edge token, roll the edges with it, then revoke the old one in **Users** |
| Ingress secret | Add the new value to `INGRESS_SECRET_VALUES`, roll edges, switch the CDN, then remove the old value |
| A user's password | The user changes it on **Account**. An admin can disable a user in **Users** |

## Upgrade

1. Read the release notes.
2. Run `admin migrate` with the new image.
3. Roll admin, then roll edges.
4. Publish config that uses a new schema only after every edge is upgraded. Admin enforces this: it refuses the publish while any live edge can't read the schema.
