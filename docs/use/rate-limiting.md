# Rate limiting

Each rule keeps one counter per key in Valkey, shared by every edge, so a limit of 100 means 100 across the fleet. A request makes at most one Valkey round trip, whatever number of rules it matches. This page covers the rules you write; [autopilot](autopilot.md) can add short-lived ones during an attack.

## A rule

```json
{
  "id": "login",
  "algorithm": "sliding_window",
  "limit": 5,
  "period": "1m",
  "key": ["ip"],
  "on_missing_key": "fallback_ip",
  "action": "block",
  "penalty": "5m",
  "fail_mode": "open"
}
```

This is the rule's **Then** block in the UI; its expression (here `http.request.uri.path eq "/login"`) is built above it. The form has no `expires_at` field: set it with **Edit as JSON** under **Then**, or in the rule's JSON through an import or `PUT /api/draft` ([API](../reference/api.md)).

| Field | Values |
|---|---|
| `algorithm` | `fixed_window`, `sliding_window`, `token_bucket`, `leaky_bucket`, `distinct` |
| `limit`, `period` | 1 to 1e9 requests per 1s to 24h (whole seconds). For `distinct`, 1 to 1,000 different values |
| `burst` | `token_bucket` and `leaky_bucket` only, and required for them |
| `distinct_of` | `distinct` only, and required for it: what to count different values of, `path`, `query:<name>`, `ip`, `asnum` or `ja4`. See [Distinct](#distinct) |
| `count_statuses` | Optional: count upstream responses with these statuses, such as `"404"` or `"4xx"`, instead of requests. See [Counting responses](#counting-responses) |
| `key` | 1 to 5 parts: `ip`, `jwt_claim:<name>`, `header:<name>`, `cookie:<name>`, `query:<name>`, `host`, `method`, `country`, `asnum`, `ja4`, `locale`, or `constant` alone (one counter for everyone). IPv6 is keyed per /64. `asnum` and `ja4` need a trusted viewer header |
| `on_missing_key` | `skip` the rule, `fallback_ip`, or `reject` the request |
| `action` | `block`, or `log` to count what would have been limited without blocking (shadow mode) |
| `penalty` | Optional, 1s to 24h: once over the limit, stay blocked this long |
| `fail_mode` | What to do when Valkey can't answer: `open`, `closed` or `local` |
| `expires_at` | Optional, an RFC 3339 time such as `"2026-11-01T00:00:00Z"`: the rule stops running then. See [Rules that expire](#rules-that-expire) |

## Before you block: shadow mode

Start every rule in shadow mode, `"action": "log"`: it counts the requests it would have limited and lets them through. A rule added in the UI starts that way. **Stats** shows its **Over limit, log only** count against real traffic, with the clients it would hit, and **Needs attention** on the dashboard lists log-only rules with requests over their limit. Switch it to `block` once the numbers look right, and publish that change through a [canary](publishing.md#canary) so only part of the traffic sees it first. The [rollback guard](publishing.md#rollback-guard) compares a changed rule with what it found while it only logged.

## How a request is checked

Rate limiting runs after the [local backstop](#local-backstop) (each edge's own per-IP flood limit), CORS and JWT, and before header rules and the proxy. Each rule below is checked on its own; then the request gets one answer.

A site-wide rule has the expression `true`, so it matches every request ([Several rules on one request](#several-rules-on-one-request)). "Limit ÷ fleet size" is the share of the limit each edge enforces on its own when Valkey can't answer a `fail_mode: local` rule ([When Valkey fails](#when-valkey-fails)).

```mermaid
flowchart TD
    Start["Request reaches the<br/>rate-limit phase"] --> Pick["Pick rules: every site-wide rule,<br/>then up to 5 other matching rules,<br/>blocking rules before log rules"]
    Pick --> HasKey{"Every key part<br/>present?"}
    HasKey -->|"yes"| PenCache{"Key in this edge's<br/>penalty cache?"}
    HasKey -->|"no, fallback_ip"| ByIP["Key on the client IP"]
    HasKey -->|"no, skip"| Ignored["Rule ignored"]
    HasKey -->|"no, reject"| Bad["400 bad_request"]
    ByIP --> PenCache
    PenCache -->|"yes"| Over["Over the limit"]
    PenCache -->|"no"| Batch["One pipelined Valkey call<br/>for all remaining rules"]
    Batch --> Answered{"Valkey<br/>answered?"}
    Answered -->|"yes"| Algo{"Algorithm<br/>allows it?"}
    Answered -->|"no"| Mode{"fail_mode"}
    Mode -->|"open"| Pass["Rule passes"]
    Mode -->|"closed"| Unavail["503, Retry-After: 1"]
    Mode -->|"local"| Local["This edge's own counter<br/>at limit ÷ fleet size"]
    Local --> Algo
    Algo -->|"yes"| Pass
    Algo -->|"no"| Over
    Over --> Action{"action"}
    Action -->|"log"| Shadow["Count would_limit,<br/>let it through"]
    Action -->|"block"| Limited["429 with Retry-After"]
```

How the per-rule results combine:

- **Any blocking rule over its limit:** 429. `Retry-After` is the longest wait among those rules.
- **Otherwise, any `fail_mode: closed` rule that Valkey couldn't answer:** 503. A `log` rule never fails closed.
- **Otherwise** the request continues to the header phase and the upstream.

Rules are independent counters. A request blocked by one rule still used quota in every other rule it matched, because checking all of them first would need a second round trip.

## The algorithms

Every algorithm keeps its state in one Valkey key per subject and reads the time from Valkey, so all edges agree on it. The tables below were produced by running the algorithm code on each timeline. Times are from the start of a window.

### Fixed window

Counts requests per calendar window of `period`. The count resets when the next window starts.

```mermaid
flowchart TD
    Req["Request"] --> Same{"Stored window is<br/>the current one?"}
    Same -->|"no"| Reset["Start a new window<br/>with a count of 0"]
    Same -->|"yes"| Check{"count below limit?"}
    Reset --> Check
    Check -->|"yes"| Allow["count + 1, allow"]
    Check -->|"no"| Deny["429, Retry-After =<br/>time to the window end"]
```

**Scenario:** `limit: 5`, `period: 1m`. A client sends 5 requests late in one window and 5 more right after it ends.

| Time | Result | Why |
|---|---|---|
| 0:59.0 to 0:59.4 | 5 allowed | Count goes 1 to 5 |
| 1:00.0 to 1:00.4 | 5 allowed | A new window started; the count went back to 0 |
| 1:00.5 | 429, `Retry-After: 60` | Count is 5 until 2:00 |

10 requests passed in 1.5 seconds. That edge burst is the price of the cheapest algorithm; use it for coarse quotas where it doesn't matter.

### Sliding window

Smooths the edge burst. It keeps the count of the current window and the previous one, and estimates the last `period` as:

estimate = current count + previous count × the share of the previous window still inside the last `period`, rounded up

```mermaid
flowchart TD
    Req["Request"] --> Roll{"Stored window?"}
    Roll -->|"current one"| Est
    Roll -->|"the one before"| Shift["previous = current<br/>current = 0"]
    Roll -->|"older or none"| Zero["previous = 0<br/>current = 0"]
    Shift --> Est["Compute the estimate"]
    Zero --> Est
    Est --> Check{"estimate below limit?"}
    Check -->|"yes"| Allow["current + 1, allow"]
    Check -->|"no"| Deny["429, Retry-After =<br/>time to the window end, or longer"]
```

**Scenario:** the same client and the same `limit: 5`, `period: 1m`.

| Time | Estimate before the request | Result |
|---|---|---|
| 0:59.0 to 0:59.4 | 0, 1, 2, 3, 4 | 5 allowed |
| 1:00.0 | 0 + 5 × 100% = 5 | 429 |
| 1:30.0 | 0 + 5 × 50% = 2.5, rounded up to 3 | Allowed |
| 1:30.1 | 1 + 3 = 4 | Allowed |
| 1:30.2 | 2 + 3 = 5 | 429 |
| 1:45.0 | 2 + 5 × 25% = 1.25, rounded up to 2, so 4 | Allowed |
| 2:00.0 | 0 + 3 × 100% = 3 | Allowed |

The edge burst is gone: at 1:00 the client gets nothing more until the old requests age out. Rounding up means the estimate never lets one extra request through. Good for login and signup limits.

### Token bucket

A bucket holds up to `burst` tokens and starts full. It refills at `limit` tokens per `period`. Each request takes one token.

```mermaid
flowchart TD
    Req["Request"] --> Refill["Add tokens for the time since<br/>the last request, up to burst"]
    Refill --> Check{"At least<br/>one token?"}
    Check -->|"yes"| Allow["Take one token, allow"]
    Check -->|"no"| Deny["429, Retry-After =<br/>time to the next token"]
```

**Scenario:** `limit: 10`, `period: 1m`, `burst: 5`. One token every 6 seconds, at most 5 saved up.

| Time | Result | Why |
|---|---|---|
| 0:00, 5 requests | 5 allowed | The bucket starts full |
| 0:00, 6th request | 429, `Retry-After: 6` | Empty; the next token comes in 6s |
| 0:06, 2 requests | 1 allowed, then 429 | One token refilled |
| 0:30, 6 requests | 4 allowed, then 2 × 429 | 24s refilled 4 tokens |

A client can burst up to `burst` after a quiet spell, and averages `limit` per `period` over time. Good for API limits.

### Leaky bucket

A bucket holds up to `burst` requests and starts empty. Each request adds one; the bucket drains at `limit` per `period`. A request that would overflow it is rejected, never queued. This is the meter form of the leaky bucket, the same as GCRA.

```mermaid
flowchart TD
    Req["Request"] --> Drain["Drain the bucket for the time<br/>since the last request"]
    Drain --> Check{"Level + 1<br/>≤ burst?"}
    Check -->|"yes"| Allow["Level + 1, allow"]
    Check -->|"no"| Deny["429, Retry-After =<br/>time until one request fits"]
```

**Scenario:** the same `limit: 10`, `period: 1m`, `burst: 5`. The results are the same as the token bucket, request for request: with equal settings the two admit the same traffic. Both are offered because operators think of limits in one model or the other. Choose leaky bucket when "at most one request every 6 seconds, with 5 of slack" is the way you describe protecting a fragile upstream.

### Distinct

Counts how many **different** values of `distinct_of` a subject sends per `period`, not how many requests. Over the limit, every request of the subject is refused until the period ends, including values it sent before. It catches what a request rate can't: a client walking many paths slowly, an IP trying many account IDs, or an account used from many IPs.

```mermaid
flowchart TD
    Req["Request"] --> Has{"Request has the<br/>distinct_of value?"}
    Has -->|"no"| Skip["Rule not applied"]
    Has -->|"yes"| Win{"Period since the<br/>subject's first value over?"}
    Win -->|"yes"| Fresh["Start a new period<br/>with no values"]
    Win -->|"no"| Mark
    Fresh --> Mark["Mark the value's bit<br/>in a 1024-bit map"]
    Mark --> Est{"Estimated different<br/>values ≤ limit?"}
    Est -->|"yes"| Allow["Allow"]
    Est -->|"no"| Deny["429, Retry-After =<br/>time to the period end"]
```

- **The count is an estimate.** Each value sets one bit of a 1024-bit map, and the count is estimated from the bits still clear (linear counting). Up to 1000 values it stays within 10% of the exact count (about 4% in tests). The map is 158 bytes per subject in Valkey.
- **A period starts with the subject's first value,** not on the clock.
- **`distinct_of` values:** `path` is the normalized path; `query:<name>` the decoded first value of that argument; `ip` the client IP (per /64 for IPv6); `asnum` and `ja4` need their viewer source. A request without the value isn't counted by the rule and isn't refused by it.
- **`fail_mode: local` is refused,** since one map per subject per edge would outgrow the bounded local store. Use `open` or `closed`.
- **Count by something other than the value.** `"key": ["ip"], "distinct_of": "path"` limits paths per IP; `"key": ["jwt_claim:sub"], "distinct_of": "ip"` limits IPs per account. Changing `distinct_of` starts every subject fresh.

**Scenario:** `distinct`, `distinct_of: path`, `key: ["ip"]`, `limit: 50`, `period: 5m`. A scanner requests 60 different paths in 2 minutes, a few per second.

| Request | Result | Why |
|---|---|---|
| Paths 1 to 50 | Allowed | 50 or fewer different paths |
| Path 51 or so | 429, `Retry-After` up to the period end | The estimate is over 50 |
| Path 1 again | 429 | Over the limit, every request is refused until the period ends |

A browser loading pages and their assets sends tens of paths, so start in `log` and set the limit above what Stats shows for real clients.

### Choosing an algorithm

| Algorithm | Behaviour | Good for |
|---|---|---|
| `fixed_window` | Count per calendar window; allows up to 2 × `limit` across a window edge | Cheap coarse quotas |
| `sliding_window` | Weighted previous window plus the current one | Login and signup limits |
| `token_bucket` | Bursts to `burst`, refills at `limit` per `period` | API rate limits |
| `leaky_bucket` | Same admission as the token bucket, described as a draining bucket | Protecting a fragile upstream |
| `distinct` | Different values per period, estimated | Scanning, enumeration, accounts shared across IPs |

Changing `limit` or `burst` applies on the next request. Changing `algorithm` or `period` starts every subject from zero, because both are part of the Valkey key.

## Counting responses

A rule with `count_statuses` counts the upstream's **answers** instead of requests: a client getting many 404s is probing for files, and one getting many 401s or 403s is guessing passwords.

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

- **Each edge counts in its own memory,** against the full limit, with no Valkey call. Behind a load balancer spreading a client over N edges, it can get up to N × `limit` answers before every edge blocks it. When the edge's local store is full, a new subject isn't counted, which is also fail-open; each counts in `edge_ratelimit_local_untracked_total`.
- **The answer that goes over the limit is already sent.** The edge then blocks the key in its penalty cache until the [penalty](#penalty) ends or, without one, until the period's count resets; later requests matching the rule get 429 without reaching the upstream. When the edge's penalty cache is full, the block isn't stored and an over-limit subject isn't refused: this fails open by design, and each drop counts in `edge_ratelimit_penalty_cache_dropped_total`.
- **Statuses are 100 to 499, or the classes `1xx` to `4xx`.** 5xx is refused: it is usually the upstream's fault, and counting it would lock clients out after an outage.
- **Not with `distinct`.** `fail_mode` has no effect, since Valkey isn't used, and a value other than `open` gets a warning. A count rule isn't a site-wide rule, nor the `ip` partner for attacker-controlled keys.
- **Up to 5 count rules** apply to a request, in their own cap beside the 5 other matching rules. They send no `RateLimit` headers.
- **Edge-generated answers aren't counted,** only the upstream's.

## Penalty

Without a penalty, a client over the limit gets through again as soon as the algorithm allows. With one, the first rejected request blocks the key for the whole `penalty`.

```mermaid
sequenceDiagram
    participant Client
    participant Edge
    participant Valkey
    Client->>Edge: 6th login in a minute
    Edge->>Valkey: run the rule's script
    Valkey-->>Edge: over the limit, blocked until now + 5m
    Edge->>Edge: remember the block in its penalty cache
    Edge-->>Client: 429, Retry-After: 300
    Client->>Edge: retry 65 seconds later
    Edge->>Edge: penalty cache hit, no Valkey call
    Edge-->>Client: 429, Retry-After: 235
```

**Scenario:** the `login` rule above: `sliding_window`, `limit: 5`, `period: 1m`, `penalty: 5m`.

| Time | Result | Why |
|---|---|---|
| 0:00 to 0:04 | 5 allowed | Under the limit |
| 0:05 | 429, `Retry-After: 300` | 6th request: the penalty starts and runs to 5:05 |
| 1:10 | 429, `Retry-After: 235` | Still blocked, although the window has moved on |
| 5:04 | 429, `Retry-After: 1` | Still blocked |
| 5:05 | Allowed | Penalty over; counting starts fresh |

- **Repeat offenders cost almost nothing.** Each edge keeps a local copy of active penalties (up to 100,000 keys) and answers from it without calling Valkey. An edge that hasn't seen the client yet asks Valkey once; Valkey answers "blocked" without counting, and that edge caches it too.
- **Penalties apply only to `action: block` rules.** A `log` rule records that a penalty would have started and never blocks.

## Rules that expire

A rule with `expires_at` stops running at that time, with no second publish. From then on every edge skips it: it takes no slot among the 5 rules a request runs, a client serving its penalty is let through, and `/metrics` counts the request as `expired` for the rule. Config tests judge the expiry at the time they run.

- **Each edge uses its own clock.** Edges whose clocks differ end the rule that much apart; run NTP on every host.
- **It needs schema 5 edges.** Admin holds the publish while a live edge reads an older schema, naming it.
- **An expired rule stays valid.** It is skipped, not rejected, so a bootstrap file exported while it ran still loads. A save or check of the draft warns about a rule of yours whose `expires_at` has passed: the rule will not run.

[Autopilot rules](publishing.md#autopilot-rules) always expire, at most 24 hours after they are published.

## When the key is missing

A key part can be absent: a missing header, cookie or query argument, no verified token for a `jwt_claim`, no country or ASN from the CDN, or no locale. `on_missing_key` decides what happens.

**Scenario:** an API rule keyed on `["jwt_claim:sub"]`, `limit: 1000`, `period: 1h`.

| Request | `fallback_ip` (default) | `skip` | `reject` |
|---|---|---|---|
| Valid token, `sub` = `user-42` | user-42's counter | user-42's counter | user-42's counter |
| No token on a route with `auth: optional` | A counter for the client IP | Rule not applied | 400 `bad_request` |

- **`fallback_ip` is the safe default.** A fallback key can never collide with a value a client chooses, so a header set to someone's IP can't land in that IP's bucket.
- **`skip` lets a client bypass the rule** by leaving the value out. Use it only when another rule covers those requests.
- **A `skip`ped rule takes no slot** in the 5-rule cap.

## Several rules on one request

**Scenario:** a site-wide rule `per-ip` (expression `true`, key `ip`, 300 per minute) and the `login` rule. A client sends its 6th login of the minute.

| Rule | Counter after the request | Result |
|---|---|---|
| `per-ip` | 6 of 300 | Allowed |
| `login` | Over 5 | 429 |

The answer is 429, and `per-ip` still counted the request. Both rules were checked in one Valkey round trip.

Limits per request:

- **Site-wide rules** (expression `true`) always run. At most 2 are allowed.
- **Up to 5 other matching rules** run, blocking rules first, then `log` rules. Requests that matched more are counted in `edge_ratelimit_rules_capped_total`.
- Blocking rules go first because clients choose which rules match through what they send. Otherwise five matching `log` rules could push a login limit out of evaluation.

## When Valkey fails

Each Valkey call has a short deadline. After 5 consecutive failures on one Valkey node, the edge stops calling that node for 1 second, then lets one probe through. Only keys on the failed node are affected. Rate-limit calls are never retried: a call that timed out may already have counted, and a retry could count it twice.

Every rule then follows its `fail_mode`.

**Scenario:** Valkey is unreachable, 4 edges are running, and the `login` rule (`limit: 5`) receives traffic.

| `fail_mode` | Result | Use it when |
|---|---|---|
| `open` (default) | Every request passes this rule | Availability matters more than the limit |
| `closed` | 503 with `Retry-After: 1` | The upstream must never see unlimited traffic |
| `local` | Each edge counts on its own with a limit of 5 ÷ 4, rounded down and at least 1. Across the fleet, about 4 logins per minute pass | You need a rough limit during an outage |

- **The fleet size comes from admin,** which counts the edges that reported stats in the last minute. Until admin has supplied it, `EXPECTED_REPLICAS` from deployment config is used.
- **`local` state is bounded** at 100,000 keys per edge, split evenly between rules, and survives publishes during the outage.
- **Cluster deployments must set `cluster-require-full-coverage no`.** With the default, one failed primary fails every key, not just its own.

## Rules that keep limits honest

- **Attacker-controlled keys need a partner.** A rule whose key includes `header`, `cookie`, `query`, `host`, `method` or `ja4` is rejected unless the key also has `ip` or `jwt_claim`, or a site-wide rule keyed on `ip` exists that counts requests in Valkey (not `distinct`). Otherwise a client could rotate the value to get a fresh counter.
- **JWT claims count only after the token verified.**
- **Repeated values use the first one,** so a client can't pick a bucket by reordering duplicate headers or arguments.

## Response headers

- **`Retry-After`** is on every 429, in whole seconds, rounded up.
- **`RateLimit-Policy` and `RateLimit`** (IETF draft) are sent when a config rule sets `ratelimit_headers: true`. There is one item per blocking rule, named by its ID, for example `RateLimit-Policy: "login";q=5;w=60` and `RateLimit: "login";r=2;t=41`. `log` rules are left out.

## Local backstop

Before any shared limit, each edge applies a per-IP token bucket in memory (**Settings → Backstop**). It absorbs floods without touching Valkey and works even when Valkey is down. It is per edge, so the effective ceiling is about the number of edges × the setting. Set it well above any real client's rate.

When its table is full, new IPs pass the backstop untracked rather than share one bucket; the shared limits still apply to them.

## Emergency switch

**Settings → Kill switch → Disable rate limiting** turns every rule into `log`. Save and publish it to stop all rate-limit blocking at once; the backstop still applies. **Disable JWT checks** turns JWT verification off entirely: every route behaves as `auth: none`, claims are empty and `X-Edge-Auth-*` headers are not set. **Disable blocking by config rules** turns every config rule's `block` setting into `log`.
