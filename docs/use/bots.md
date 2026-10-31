# Bot detection

The edge has no bot score. It gives rules the facts a score would be built from, and leaves the decision to policy you can read, test and roll back:

| Fact | Field or setting | From |
|---|---|---|
| Automation hints in the headers | `client.signals` | The request's headers and viewer fields ([signals](../reference/expressions.md#client-signals)) |
| TLS fingerprint | `tls.client.ja4`, `tls.client.ja3` | The CDN, through [`VIEWER_HEADERS`](../deploy/edge.md#client-ip-presets) |
| Crawler whose IP is in its operator's published crawler ranges | `client.verified_bot` | Ranges admin fetches from [`VERIFIED_BOT_SOURCES`](../deploy/admin.md) |
| Many different paths, IDs or IPs | `distinct` rate limits | Valkey ([Distinct](rate-limiting.md#distinct)) |
| Many 404s, 401s or 403s | `count_statuses` rate limits | Each edge's memory ([Counting responses](rate-limiting.md#counting-responses)) |

A config rule's `block` setting answers 403; a rate limit answers 429. Every recipe below starts as `log`: watch **Stats** and the access log's `client.signals` and `tls.client.ja4` until only the clients you mean to stop show up, then switch to `block` and publish through a [canary](publishing.md#canary). The [rollback guard](publishing.md#rollback-guard) judges a rule that logged first against its logged share × `max_vs_shadow` (3×); a new rule with no log run rolls back if it blocks over `max_ratio` (5%) of requests. `kill_switch.block` turns every `block` setting back into `log`.

A signal or fingerprint is a hint, not proof. A careful bot sends a browser's headers and TLS stack, and some real users run privacy tools or old browsers. Keep crawlers you want out of every blocking rule with `not client.verified_bot`.

`client.verified_bot` needs `VERIFIED_BOT_SOURCES`; without it, validation refuses rules that read the field. Until admin's first fetch succeeds, the field is false. For Google, list only `common-crawlers.json` and `special-crawlers.json`. The user-triggered fetcher lists cover fetches other people control, such as Google Cloud customers' fetchers, so never use them for an exemption.

## Refuse tools on pages

A config rule that blocks scripted clients on the site's pages, but not on its API, where tools are expected:

```text
client.signals in {"ua_missing" "ua_tool" "ua_headless"} and not starts_with(http.request.uri.path, "/api/") and not client.verified_bot
```

```json
{ "settings": { "block": "log" } }
```

Browser signals such as `browser_no_sec_fetch` fire for a client that claims a modern browser but leaves out what that browser always sends. They need trusted `ssl`, HTTP version or JA4 sources; validation refuses a rule naming a signal the deployment can't compute.

## JSON answers on API paths

The default `forbidden` template is HTML. Add a template named `forbidden-json` with status 403 and content type `application/problem+json` on **Templates**, then map it for the API in a config rule:

```text
starts_with(http.request.uri.path, "/api/")
```

```json
{ "settings": { "responses": { "forbidden": "forbidden-json" } } }
```

Any blocking rule then answers API requests with it, unless a later matching rule maps `forbidden` to another template.

## Limit by TLS fingerprint and network

A botnet rotating IPs often keeps one TLS stack and a few networks. A rate limit keyed on both catches it where a per-IP limit can't. `ja4` is chosen by the client, so it needs an `ip` or JWT claim partner, or a site-wide rule keyed on `ip`:

```json
[
  { "id": "per-ip", "algorithm": "sliding_window", "limit": 600, "period": "1m", "key": ["ip"],
    "on_missing_key": "fallback_ip", "action": "block", "fail_mode": "open" },
  { "id": "ja4-network", "algorithm": "sliding_window", "limit": 3000, "period": "1m", "key": ["ja4", "asnum"],
    "on_missing_key": "skip", "action": "log", "fail_mode": "open" }
]
```

`per-ip` has the expression `true`; `ja4-network` has `not client.verified_bot`. Many real users share a browser's JA4 and a large ISP's AS number, so set the limit from what Stats shows for the busiest legitimate pair. A request without a JA4, such as plain HTTP, skips the rule.

## 404 sweeps

A scanner probing for files gets 404 after 404:

```json
{ "id": "404-sweep", "algorithm": "fixed_window", "limit": 30, "period": "1m", "key": ["ip"],
  "on_missing_key": "fallback_ip", "action": "log", "penalty": "10m", "fail_mode": "open",
  "count_statuses": ["404"] }
```

## Failed logins

A password guesser gets 401 or 403 from the login endpoint. With the expression `http.request.uri.path eq "/login" and http.request.method eq "POST"`:

```json
{ "id": "login-failures", "algorithm": "fixed_window", "limit": 10, "period": "10m", "key": ["ip"],
  "on_missing_key": "fallback_ip", "action": "log", "penalty": "15m", "fail_mode": "open",
  "count_statuses": ["401", "403"] }
```

## Crawl breadth

A crawler you didn't invite walks many pages slowly, under any request rate. Limit different paths per IP:

```json
{ "id": "crawl-breadth", "algorithm": "distinct", "distinct_of": "path", "limit": 300, "period": "10m",
  "key": ["ip"], "on_missing_key": "fallback_ip", "action": "log", "fail_mode": "open" }
```

With the expression `not client.verified_bot`, verified crawlers are left alone.

## An account used from many IPs

Shared or stolen credentials show up as one account from many addresses. On routes that require a token:

```json
{ "id": "account-ips", "algorithm": "distinct", "distinct_of": "ip", "limit": 20, "period": "1h",
  "key": ["jwt_claim:sub"], "on_missing_key": "skip", "action": "log", "fail_mode": "open" }
```

A phone moving between networks uses a few IPs an hour, so start high.
