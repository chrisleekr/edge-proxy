# Bot detection

The edge has no bot score. It gives rules the facts a score would be built from, and leaves the decision to policy you can read, test and roll back:

| Fact | Field or setting | From |
|---|---|---|
| Automation hints in the headers | `client.signals` | The request's headers and viewer fields ([signals](../reference/expressions.md#client-signals)) |
| CDN verdicts and measurements | `http.request.headers["<name>"]`, and the CDN signals in `client.signals` | The headers in [`CDN_HEADERS`](../deploy/edge.md#cdn-headers), and for the signals only those trusted in **Settings → Trusted CDN headers**, or a listed source header for `cdn_tor` |
| TLS fingerprint | `tls.client.ja4`, `tls.client.ja3` | The CDN, through [`VIEWER_HEADERS`](../deploy/edge.md#client-ip-presets) |
| Crawler whose IP is in its operator's published crawler ranges | `client.verified_bot` | Ranges admin fetches from [`VERIFIED_BOT_SOURCES`](../deploy/admin.md) |
| Many different paths, IDs or IPs | `distinct` rate limits | Valkey ([Distinct](rate-limiting.md#distinct)) |
| Many 404s, 401s or 403s | `count_statuses` rate limits | Each edge's memory ([Counting responses](rate-limiting.md#counting-responses)) |

An access rule's `block` setting answers 403; a rate limit answers 429. Every recipe below starts as `log`: watch **Stats** and the access log's `client.signals` and `tls.client.ja4` until only the clients you mean to stop show up, then switch to `block` and publish through a [canary](publishing.md#canary). The [rollback guard](publishing.md#rollback-guard) judges a rule that logged first against its logged share × `max_vs_shadow` (3×); a new rule with no log run rolls back if it blocks over `max_ratio` (5%) of requests. `kill_switch.block` turns every `block` setting back into `log`.

A signal or fingerprint is a hint, not proof. A careful bot sends a browser's headers and TLS stack, and some real users run privacy tools or old browsers. Keep crawlers you want out of every blocking rule with `not client.verified_bot`.

`client.verified_bot` needs `VERIFIED_BOT_SOURCES`; without it, validation refuses rules that read the field. Until admin's first fetch succeeds, the field is false. When a list keeps failing, edges keep matching its last good ranges; **Fleet** shows each source's state under [Verified crawler ranges](../tour/monitor.md#verified-crawler-ranges), and the `verified_bots_stale` [notification](../operate/notifications.md#signals) trips after 3 failed refreshes in a row by default, then fires per the notification settings. For Google, list only `common-crawlers.json` and `special-crawlers.json`. The user-triggered fetcher lists cover fetches other people control, such as Google Cloud customers' fetchers, so never use them for an exemption.

## Refuse tools on pages

An access rule that blocks scripted clients on the site's pages, but not on its API, where tools are expected:

```text
client.signals in {"ua_missing" "ua_tool" "ua_headless"} and not starts_with(http.request.uri.path, "/api/") and not client.verified_bot
```

```json
{ "settings": { "block": "log" } }
```

Browser signals such as `browser_no_sec_fetch` fire for a client that claims a modern browser but leaves out what that browser always sends. They need trusted `ssl`, HTTP version or JA4 sources; validation refuses a rule naming a signal the deployment can't compute.

## Trap paths

An access rule that bans a client for asking for paths the site never serves, such as WordPress and dotfile probes:

```text
starts_with(http.request.uri.path, "/wp-") or starts_with(http.request.uri.path, "/wp/") or starts_with(http.request.uri.path, "/.env") or starts_with(http.request.uri.path, "/.git/") or starts_with(http.request.uri.path, "/index.php/wp-json") or http.request.uri.path in {"/xmlrpc.php" "/index.php"}
```

```json
{ "settings": { "block": "block", "ban": "24h" } }
```

The first request that matches gets 403, and every later request from that client IP on that edge gets 403 with the action `banned` for 24 hours, on every host. See [Banning a client](policy.md#banning-a-client) for what ends a ban early and what clears it. Bans an edge records show under [Banned IPs](ip-lists.md#banned-ips) on the IP lists page, where a person can lift one.

Anchor the expression on paths your own sites and services never use. `/wp-` also matches a top-level path such as a GitLab group, a user or a MinIO bucket named `wp-something`, and would ban its owner on every host. Start with `"block": "log"` and no `ban`, check the lines whose `edge.logged_rules` contains this rule in the [access log](../operate/monitoring.md#logs) against your real traffic, and only then switch to `block` with `ban`.

## IP lists

Named lists of addresses, typed or downloaded, that rules match with `client.ip_lists`: see [IP lists](ip-lists.md), including the [default lists](ip-lists.md#default-ip-lists) and the **Banned IPs** a trap rule produces.

## CDN headers

The headers your CDN sets are [logged on every access line](../deploy/edge.md#cdn-headers) and readable in rules as `http.request.headers["<name>"]`, with the value as the CDN sent it. On Cloudflare that is, for example, the city, the bot score and whether the bot is verified. Read the log first, then write the rule:

```text
http.request.headers["cf-ipcity"] eq "Sydney"
```

Four [client signals](../reference/expressions.md#client-signals) come from them, each available only when the headers it reads are in `CDN_HEADERS` and trusted in **Settings → Trusted CDN headers** (`global.cdn_trusted_headers`). `cdn_tor` reads a source header, which is trusted whenever it is listed:

| Signal | Evidence | Known false positives |
|---|---|---|
| `cdn_likely_automated` | `Cf-Bot-Score` is 1 to 29 (Cloudflare: 1 automated, 2 to 29 [likely automated](https://developers.cloudflare.com/bots/concepts/bot-score/)) and `Cf-Verified-Bot` is not `true`. Needs `cf-bot-score` and `cf-verified-bot` trusted | Cloudflare's model is wrong sometimes; verified crawlers are left out |
| `crawler_impersonated` | A `User-Agent` naming googlebot, bingbot, applebot, duckduckbot, yandexbot or baiduspider and `Cf-Verified-Bot` is `false`; a request without the header never sets it. Needs `cf-verified-bot` trusted | A real crawler on an address Cloudflare doesn't yet verify |
| `cdn_tor` | `ip.src.country` is `T1`, Cloudflare's code for Tor. Needs `cf-ipcountry` listed and the `ip.src.country` header, as on the `cloudflare` preset (a listed source header is always trusted); `T1` is not an ISO 3166 country code | None: it describes the address, not the client |
| `browser_tls_old` | A modern browser whose `CloudFront-Viewer-TLS` doesn't start with `TLSv1.3:`, never on a request the CDN saw as plain HTTP when `ssl` is mapped. Needs `cloudfront-viewer-tls` trusted | Corporate TLS-inspecting proxies that only speak TLS 1.2. [CloudFront's header](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html) |

Cloudflare sends the bot headers only with Enterprise Bot Management, and a client can send them itself without it, so they are not trusted by default: turn on the feature, then trust them. Without it, `cdn_likely_automated` and `crawler_impersonated` are accepted on a Cloudflare preset but never fire. A config naming any of the four needs schema 8 edges, and admin waits for them. Each signal only narrows what a rule matches; none exempts anyone.

## Stale browsers

A scraper fleet often forges a browser `User-Agent` that is years old, or rewrites a Firefox or Safari one while the rest of the request is Chromium. Two signals separate it from real browsers on the same TLS fingerprint:

- `browser_outdated` fires when the claimed Chrome (or other Chromium) or Firefox major version is below **Settings → Oldest browser version** (`global.browser_floor`, for example `{"chromium": 130, "firefox": 128}`). Safari has no floor, because its version follows the operating system. With no floor set the signal is off, and validation refuses a rule that names it. The floor needs schema 7 edges: admin refuses the publish while a live edge reads an older schema, naming that edge.
- `client_hints_mismatch` also fires for a Firefox or Safari `User-Agent` that sends `Sec-CH-UA`, because only Chromium sends it. Its known false positive is a Chrome user whose User-Agent switcher claims Firefox.

You set the floor by hand and must raise it about once a year, as browsers release. Real users on devices pinned to an old operating system can't update, so start with `log`:

```text
client.signals in {"browser_outdated" "client_hints_mismatch"} and not client.verified_bot
```

```json
{ "settings": { "block": "log" } }
```

`ua_headless` also names `Lightpanda`, whose default `User-Agent` is `Lightpanda/1.0`.

## A fleet on one browser fingerprint

A fleet can spread over thousands of IPs, send a few requests from each, and share one [JA4](../deploy/edge.md#client-ip-presets) with the real browsers it imitates. A per-IP limit never sees enough from any one address. A limit keyed on `ja4` alone sees the fleet, but also counts every real user on that fingerprint and limits them with it.

Scope the shared bucket with a [client signal](#stale-browsers) the fleet carries and real browsers don't. The rule limits only requests with the signal, so a real user without it is never counted or limited, even on the same JA4:

```text
not client.verified_bot and client.signals in {"browser_outdated" "client_hints_mismatch"} and http.request.method eq "GET"
```

```json
{
  "id": "fingerprint-fleet",
  "algorithm": "sliding_window",
  "limit": 300,
  "period": "1m",
  "key": ["ja4"],
  "on_missing_key": "skip",
  "action": "log",
  "fail_mode": "open"
}
```

It needs:

- A JA4 source in [`VIEWER_HEADERS`](../deploy/edge.md#client-ip-presets). A request without a JA4, such as plain HTTP, skips the rule. On Cloudflare that is `tls.client.ja4=cf-ja4`, which needs Enterprise Bot Management.
- A site-wide rule keyed on `ip` that counts in Valkey: the expression `true`, no `count_statuses`, any algorithm but `distinct`. Validation refuses a rule keyed only on client-written values without one.
- `global.browser_floor` set, as in [Stale browsers](#stale-browsers), for `browser_outdated`.
- Optionally, `browser_tls_old` (CloudFront) or `cdn_likely_automated` (Cloudflare with Bot Management) in the signal set, where the deployment has their headers.
- `VERIFIED_BOT_SOURCES`, for `not client.verified_bot`. Leave the clause out without it.

Pick the limit from **Stats → Client signals**, which shows how many requests carried each signal and their share. Set it well above what real users with the signal send in a minute, and below the fleet's rate.

Roll it out as every recipe here does: `log` first, watch **Logged instead of limited** on **Stats** and the lines whose `edge.logged_rules` contains the rule in the [access log](../operate/monitoring.md#logs), which carry the JA4, JA3, User-Agent and browser headers of each request it would have limited, publish `block` through a [canary](publishing.md#canary), then keep it. Give it no `penalty`: the edge checks a penalty before the rule, so on a `ja4` key it would block every client on the fingerprint for its duration.

Trade-offs:

- The signals are client-written. They only narrow what the rule limits and never exempt anyone, so a fleet that forges them escapes the rule, and a client can't push a real user into it.
- A fleet that rotates JA4s splits its bucket across them. Key `["constant"]` gives every flagged request one bucket, at the cost of putting real users on old browsers in it, so use it only while the flagged requests are almost all the fleet.
- `client_hints_mismatch` has a known false positive: a Chrome user whose User-Agent switcher claims Firefox.

The [autopilot](autopilot.md#cases) opens a case when `signal_surge` fires and proposes this shape, a `ja4`-only key with an expression that requires a signal and no penalty, if the deployment has the site-wide `ip` rule. See the [checks](autopilot.md#proposals-and-the-checks) it applies.

## JSON answers on API paths

The starter `forbidden` template already sends problem+json to API clients, `fetch` and curl, and a small HTML page to browsers, chosen by the `Accept` header. Use this recipe for a policy whose `forbidden` template predates those bodies, or to send a different answer on API paths: add a template named `forbidden-json` with status 403 and content type `application/problem+json` on **Templates**, then map it for the API in an access rule:

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
  {
    "id": "per-ip",
    "algorithm": "sliding_window",
    "limit": 600,
    "period": "1m",
    "key": ["ip"],
    "on_missing_key": "fallback_ip",
    "action": "block",
    "fail_mode": "open"
  },
  {
    "id": "ja4-network",
    "algorithm": "sliding_window",
    "limit": 3000,
    "period": "1m",
    "key": ["ja4", "asnum"],
    "on_missing_key": "skip",
    "action": "log",
    "fail_mode": "open"
  }
]
```

`per-ip` has the expression `true`; `ja4-network` has `not client.verified_bot`. Many real users share a browser's JA4 and a large ISP's AS number, so set the limit from what Stats shows for the busiest legitimate pair. A request without a JA4, such as plain HTTP, skips the rule.

## 404 sweeps

A scanner probing for files gets 404 after 404:

```json
{
  "id": "404-sweep",
  "algorithm": "fixed_window",
  "limit": 30,
  "period": "1m",
  "key": ["ip"],
  "on_missing_key": "fallback_ip",
  "action": "log",
  "penalty": "10m",
  "fail_mode": "open",
  "count_statuses": ["404"]
}
```

## Failed logins

A password guesser gets 401 or 403 from the login endpoint. With the expression `http.request.uri.path eq "/login" and http.request.method eq "POST"`:

```json
{
  "id": "login-failures",
  "algorithm": "fixed_window",
  "limit": 10,
  "period": "10m",
  "key": ["ip"],
  "on_missing_key": "fallback_ip",
  "action": "log",
  "penalty": "15m",
  "fail_mode": "open",
  "count_statuses": ["401", "403"]
}
```

## Crawl breadth

A crawler you didn't invite walks many pages slowly, under any request rate. Limit different paths per IP:

```json
{
  "id": "crawl-breadth",
  "algorithm": "distinct",
  "distinct_of": "path",
  "limit": 300,
  "period": "10m",
  "key": ["ip"],
  "on_missing_key": "fallback_ip",
  "action": "log",
  "fail_mode": "open"
}
```

With the expression `not client.verified_bot`, verified crawlers are left alone.

## An account used from many IPs

Shared or stolen credentials show up as one account from many addresses. On routes that require a token:

```json
{
  "id": "account-ips",
  "algorithm": "distinct",
  "distinct_of": "ip",
  "limit": 20,
  "period": "1h",
  "key": ["jwt_claim:sub"],
  "on_missing_key": "skip",
  "action": "log",
  "fail_mode": "open"
}
```

A phone moving between networks uses a few IPs an hour, so start high.
