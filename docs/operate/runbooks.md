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
2. Make sure admin is reachable from the edge, the edge token is valid (created on **Users**, or the same `EDGE_SERVICE_TOKEN_FILE` on admin and the edge) and something has been published (or admin has `BOOTSTRAP_PUBLISH_DEFAULT=true`).
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

## A flood

1. Read `edge_rejected_total` by reason. `backstop` and `rate_limited` rising means the edge is rejecting the flood itself; `overloaded` means an edge is at its in-flight cap (`MAX_INFLIGHT`, or lower from **Settings → Requests in progress**).
2. **One IP or a few:** the [local backstop](../use/rate-limiting.md#local-backstop) rejects them in memory, without Valkey or the upstream. Nothing to do unless it also limits real clients.
3. **Many IPs, each under the backstop:** publish a site-wide rule (expression `true`) keyed on `ip`, with `action: block` and a `penalty`. Publish it with a guard override and a reason, or the [rollback guard](../use/publishing.md#rollback-guard) can roll it back as an over-blocking change.
    - With a penalty, an IP's later requests are answered from each edge's penalty cache, without a Valkey call.
    - Without one, every rejected request still costs a Valkey call.
4. Watch `edge_backstop_untracked_total`, `edge_ratelimit_penalty_cache_dropped_total` and `edge_ratelimit_local_untracked_total`. When their tables are full, new IPs pass the backstop untracked, new penalties aren't cached and new subjects aren't counted. The shared Valkey limits still apply; count rules (`count_statuses`) fail open.
5. **Many IPs, each under every limit:** the edge can't tell them from real clients. Block them at the CDN.

## Stop rate limiting, blocking or JWT checks now

**Settings → Kill switch**, then save and publish. **Disable rate limiting** makes every rate-limit rule log-only; **Disable blocking by config rules** makes every config rule's `block` setting log-only; **Disable JWT checks** stops requiring tokens. The per-IP backstop still applies. All three are audited. Turn them off the same way.

## Stop autopilot now

**Autopilot → Turn autopilot off**, with a reason the audit log keeps, or set `mode` to `off` with `PUT /api/settings/autopilot` (`settings.manage`). In one transaction it retires every autopilot rule, cancels open cases and publishes without them; an old edge never holds that publish back. Promote or abort a running canary first. See [Turning it off](../use/autopilot.md#turning-it-off).

## A connector fails

A Prometheus, Grafana or Datadog [connector](../deploy/admin.md#connectors) that fails only affects autopilot runs: the tool call answers an error the model sees, and the case goes on without it.

1. Find which connector and why with `admin_connector_requests_total{connector,result}`: `error`, `timeout` or `too_large`.
2. Read the failed calls on the case's page under **Tool calls** (it needs `stats.read`, `config.read` and `autopilot.manage`). `<connector> could not be reached` means admin can't connect; admin also logs `connector request failed` with the cause. `<connector> answered <status>` gives the status and the start of the body: 401 or 403 means the credentials are wrong or lack a scope, 400 usually a query the model wrote, which needs no action. `<tool> took longer than 10s` and `<connector> answered over 256 KiB` mean the query asked for too much.
3. To fix credentials, put the new token or key in its file and restart admin. A read-only, narrowly scoped credential is enough; see [Connectors](../deploy/admin.md#connectors).
4. To stop using a connector, unset its variables and restart admin. Its tools are then not listed, and runs record the new tool set's hash.

## Bypass the edge

Use this only when the edges themselves can't serve, for example a bad image on every replica. If the edges are up and a policy is wrong, [revert it](#a-bad-publish) or use the [kill switch](#stop-rate-limiting-blocking-or-jwt-checks-now) instead.

1. Point the CDN origin, or the load balancer target, at the load balancer or gateway in `UPSTREAM_URL` instead of the edge. It routes by `Host` and path as before, so services need no change. Where the CDN allows it, move one host at a time.
2. If that load balancer or gateway admits only the edge (a firewall rule, security group or NetworkPolicy), open it to the hop that now sends traffic.
3. When the edges are fixed and `/readyz` returns 200 on each, point the CDN or load balancer back at the edge.

While bypassed, nothing the edge does applies:

- No rate limits, per-IP backstop or penalties.
- No JWT checks: requests without a valid token reach services.
- No CORS answers, header rules, locale detection or templated responses from the edge.
- Client-sent `X-Edge-*` headers are no longer stripped, so a service that trusts `X-Edge-Auth-Sub` or `X-Edge-Client-IP` sees whatever the client sent. Strip them at the gateway first, or make sure no service relies on them.
- The ingress secret header (`INGRESS_SECRET_HEADER`) and the client-IP and viewer source headers are no longer removed, so the gateway and every service receive the secret. Remove it at the gateway, or rotate `INGRESS_SECRET_VALUES` after the bypass if anything behind it logs request headers.
- `X-Forwarded-For` is no longer reset to the client address alone, so a gateway set to trust one proxy hop, such as Istio with `numTrustedProxies: 1`, may read a proxy's address as the client.
- No access logs or stats from that traffic, so **Routes**, **Stats** and the rollback guard don't see it.

## Audit chain broken

`audit chain broken` means a row no longer matches its HMAC chain.

1. Check that `AUDIT_HMAC_KEY_ID`, `AUDIT_HMAC_KEY` and `AUDIT_HMAC_PREVIOUS_KEYS` are the values used when the rows were written. A missing previous key is the usual cause.
2. If the keys are right, treat it as tampering: export the log (**Audit → Export with HMACs**), compare it with the `audit anchor` lines admin logs, and investigate database access. Rows can't be repaired; the app never edits or deletes them.

## Rotate secrets

| Secret | How |
|---|---|
| Audit HMAC key | Add the current pair to `AUDIT_HMAC_PREVIOUS_KEYS` as `id=key`, set a new `AUDIT_HMAC_KEY_ID` and `AUDIT_HMAC_KEY`, restart admin |
| Edge token | Create a new edge token, roll the edges with it, then revoke the old one in **Users** |
| Deployment edge token (`EDGE_SERVICE_TOKEN_FILE`) | Change the file for admin and the edges, then restart admin and the edges |
| Log shipper token (`LOG_INGEST_TOKEN_FILE`) | Put the new token in admin's file and in the shipper's config, then restart admin and the shipper |
| Autopilot runner token (`AUTOPILOT_TOKEN_FILE`) | Put the new token in admin's file and in the runner's config, then restart admin and the runner. A case whose runner can't renew its 10 minute lease in time is queued again once; on its second attempt it fails and raises [`autopilot_needs_person`](notifications.md#signals) |
| Ingress secret | Add the new value to `INGRESS_SECRET_VALUES`, roll edges, switch the CDN, then remove the old value |
| A user's password | The user changes it on **Account**. An admin can disable a user in **Users** |

## Upgrade

1. Read the release notes.
2. Run `admin migrate` with the new image.
3. Roll admin, then roll edges.
4. Publish config that uses a new schema only after every edge is upgraded. Admin enforces this: it refuses the publish while any live edge can't read the schema.
