# Policy fields

Every setting in a policy version and in the admin settings, by its JSON path. `<name>` stands for a map key and `[]` for a list entry.

## Policy

| Field | Type | What it is | Read |
|---|---|---|---|
| `schema` | int | The snapshot schema the policy is written for. A build reads the schemas from its minimum to its supported one. | [Policy](../use/policy.md) |
| `version` | int | The policy version number, at least 1. | [Policy](../use/policy.md) |
| `kill_switch.rate_limit` | bool | Turns off rate-limit enforcement without editing rules. | [Settings](../use/settings.md) |
| `kill_switch.auth` | bool | Turns off token enforcement without editing rules. | [Settings](../use/settings.md) |
| `kill_switch.block` | bool | Makes every block setting act as log. Added in schema 4. | [Settings](../use/settings.md) |
| `global.backstop.limit` | int | Tokens the per-replica, per-IP backstop bucket refills each period, 1 to 1,000,000,000. | [Settings](../use/settings.md) |
| `global.backstop.period` | duration | Refill period of the backstop bucket, whole seconds from 1s to 1h. | [Settings](../use/settings.md) |
| `global.backstop.burst` | int | Bucket size of the backstop, 1 to 1,000,000,000. | [Settings](../use/settings.md) |
| `global.backstop.max_entries` | int | Most client IPs one replica tracks for the backstop, 1 to 10,000,000. | [Settings](../use/settings.md) |
| `global.defaults.locale` | bool | Whether locale detection runs when no config rule sets it. | [Settings](../use/settings.md) |
| `global.defaults.body_limit` | int | Request body limit in bytes when no config rule sets one, at least 1. | [Settings](../use/settings.md) |
| `global.defaults.body_read_timeout` | duration | How long the edge waits to read a request body, from 1s to 1h. | [Settings](../use/settings.md) |
| `global.defaults.upstream_timeout` | duration | How long the edge waits for the upstream when no config rule sets it, from 1s to 1h. | [Settings](../use/settings.md) |
| `global.defaults.responses` | map of strings | Template name for every response kind the edge can send. | [Templates](../use/templates.md) |
| `global.cors_policies.<name>.origins` | list of strings | Allowed origins such as `https://app.example.com`, lowercase, at least one, compared exactly. `*` is refused with credentials. A `*` in a host, a default port, a port not written as a plain number up to 65535, or a non-ASCII host gets a warning, since no browser sends it. | [CORS](../use/cors.md) |
| `global.cors_policies.<name>.methods` | list of strings | Allowed methods, uppercase. | [CORS](../use/cors.md) |
| `global.cors_policies.<name>.request_headers` | list of strings | Request headers a browser may send. `*` is refused with credentials. | [CORS](../use/cors.md) |
| `global.cors_policies.<name>.exposed_headers` | list of strings | Response headers a browser may read. `*` is refused with credentials. | [CORS](../use/cors.md) |
| `global.cors_policies.<name>.credentials` | bool | Whether browsers may send credentials. | [CORS](../use/cors.md) |
| `global.cors_policies.<name>.max_age` | duration | How long browsers cache the preflight answer, whole seconds up to 24h, or 0 for none. | [CORS](../use/cors.md) |
| `global.responses.<name>.status` | int | Status code of the template, 400 to 599. | [Templates](../use/templates.md) |
| `global.responses.<name>.content_type` | string | Content type of the default body. | [Templates](../use/templates.md) |
| `global.responses.<name>.body` | string | Default body of the template. | [Templates](../use/templates.md) |
| `global.responses.<name>.variants[].content_type` | string | Content type of one more body, one of the supported content types and unique within the template. | [Templates](../use/templates.md) |
| `global.responses.<name>.variants[].body` | string | The body the edge sends when the request Accept prefers this content type. | [Templates](../use/templates.md) |
| `global.locale.supported` | list of strings | Locales the edge matches Accept-Language against. At least one when locale is used. | [Policy](../use/policy.md) |
| `global.locale.default` | string | Locale used when none matches, one of the supported locales. | [Policy](../use/policy.md) |
| `global.locale.output_header` | string | Header that carries the detected locale upstream, a name starting with `X-Edge-`. Empty sends `X-Edge-Locale`. | [Policy](../use/policy.md) |
| `global.request_headers.forward.mode` | string | Which client headers reach the upstream: `all`, `allowlist` or `denylist`. | [Settings](../use/settings.md) |
| `global.request_headers.forward.names` | list of strings | Header names the mode applies to. Must be empty when the mode is `all`. | [Settings](../use/settings.md) |
| `global.max_inflight` | int | Lowers every edge's cap on concurrent ordinary requests, 1 to 1,000,000. Left out keeps each edge's own cap; it cannot raise it. | [Settings](../use/settings.md) |
| `global.client_allowlist` | list of strings | IPs and Classless Inter-Domain Routing (CIDR) ranges whose requests skip config blocks and rate limits and need no token. A token sent is still verified. | [Settings](../use/settings.md) |
| `global.browser_floor` | map of ints | Lowest major version of `chromium` and `firefox` a User-Agent may claim before the browser_outdated signal fires, 1 to 999 each. Empty turns the signal off. | [Settings](../use/settings.md) |
| `global.cdn_trusted_headers` | list of strings | The CDN_HEADERS entries whose values the CDN sets on every request. Left out uses the deployment default; an empty list trusts none. | [Settings](../use/settings.md) |
| `global.lists.<name>.field` | string | The one expression field the list is for. IP addresses go in an IP list instead. | [Value lists](../use/value-lists.md) |
| `global.lists.<name>.values` | list of strings | The values, 1 to 10,000, no blanks or repeats. | [Value lists](../use/value-lists.md) |
| `auth.issuers[].id` | string | Identifier rules use to accept this issuer, unique. | [Tokens](../use/tokens.md) |
| `auth.issuers[].issuer` | string | The `iss` value of the issuer, 1 to 256 characters, unique across issuers. | [Tokens](../use/tokens.md) |
| `auth.issuers[].audiences` | list of strings | Accepted `aud` values, at least one. | [Tokens](../use/tokens.md) |
| `auth.issuers[].jwks_url` | string | HTTPS URL of the issuer's keys, with a host and no credentials or fragment. | [Tokens](../use/tokens.md) |
| `auth.issuers[].algorithm` | string | Signing algorithm, one of the asymmetric JSON Web Token (JWT) algorithms the edge verifies. | [Tokens](../use/tokens.md) |
| `auth.default_accepted` | list of strings | Issuer IDs a rule accepts when it lists none of its own. | [Tokens](../use/tokens.md) |
| `config_rules[].id` | string | Rule identifier, unique, 1 to 64 lowercase letters, digits, `-` or `_`. | [Policy](../use/policy.md) |
| `config_rules[].expression` | expression | Condition that selects the requests the rule applies to. | [Policy](../use/policy.md) |
| `config_rules[].settings.auth.mode` | string | Token requirement: `none`, `optional` or `required`. | [Tokens](../use/tokens.md) |
| `config_rules[].settings.auth.accepted` | list of strings | Issuer IDs accepted. Must be empty when the mode is `none`. | [Tokens](../use/tokens.md) |
| `config_rules[].settings.cors_policy` | string | Name of the CORS policy to use; an empty string turns CORS off. | [CORS](../use/cors.md) |
| `config_rules[].settings.locale` | bool | Turns locale detection on or off for matching requests. | [Policy](../use/policy.md) |
| `config_rules[].settings.responses` | map of strings | Template name to send for a response kind. | [Templates](../use/templates.md) |
| `config_rules[].settings.body_limit` | int | Request body limit in bytes, at least 1. | [Policy](../use/policy.md) |
| `config_rules[].settings.upstream_timeout` | duration | Upstream timeout for matching requests. | [Policy](../use/policy.md) |
| `config_rules[].settings.ratelimit_headers` | bool | Whether matching responses carry rate-limit headers. | [Policy](../use/policy.md) |
| `config_rules[].settings.block` | string | `block` answers 403 forbidden; `log` only logs it. | [Policy](../use/policy.md) |
| `config_rules[].settings.ban` | duration | Refuses every later request from the client IP on that edge for this long. Only with block set to `block`. | [Policy](../use/policy.md) |
| `config_rules[].settings.allow` | bool | Lets a matching request through every block, ban, rate limit and token requirement. Needs an expression that requires the client IP, an IP list or a verified crawler, and cannot be set with block. | [Policy](../use/policy.md) |
| `rate_limit_rules[].id` | string | Rule identifier, unique, 1 to 64 lowercase letters, digits, `-` or `_`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].expression` | expression | Condition that selects the requests the rule counts. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].algorithm` | string | One of `fixed_window`, `sliding_window`, `token_bucket`, `leaky_bucket` or `distinct`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].limit` | int | Requests allowed per period, 1 to 1,000,000,000. At most 1000 for `distinct`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].period` | duration | Window length, whole seconds from 1s to 24h. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].burst` | int | Bucket size, only for `token_bucket` and `leaky_bucket`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].key` | list of strings | What counts separately, 1 to 5 characteristics. A key of only client-controlled values needs an `ip` or `jwt_claim` partner. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].on_missing_key` | string | What to do when a key value is missing: `skip`, `fallback_ip` or `reject`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].action` | string | `block` or `log`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].penalty` | duration | How long a client stays blocked after going over, whole seconds up to 24h. 0 for none. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].fail_mode` | string | What happens when Valkey is unavailable: `open`, `closed` or `local`. `local` cannot be used with `distinct`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].count_statuses` | list of strings | Upstream statuses or classes such as `404` or `4xx` to count, in each replica's memory. Not with `distinct`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].distinct_of` | string | What `distinct` counts distinct values of: `path`, `query:<name>`, `ip`, `asnum` or `ja4`. Only for `distinct`. | [Rate limiting](../use/rate-limiting.md) |
| `rate_limit_rules[].expires_at` | timestamp | When the rule stops running, in RFC 3339. Zero means never. | [Rate limiting](../use/rate-limiting.md) |
| `request_header_rules[].id` | string | Rule identifier, unique, 1 to 64 lowercase letters, digits, `-` or `_`. | [Policy](../use/policy.md) |
| `request_header_rules[].expression` | expression | Condition that selects the requests whose headers are edited. | [Policy](../use/policy.md) |
| `request_header_rules[].ops[].op` | string | One of `set`, `append`, `remove`, `copy`, `rename` or `forward`. | [Policy](../use/policy.md) |
| `request_header_rules[].ops[].name` | string | Header to edit, for `set`, `append` and `remove`. | [Policy](../use/policy.md) |
| `request_header_rules[].ops[].value` | string | Value to write, for `set` and `append`. | [Policy](../use/policy.md) |
| `request_header_rules[].ops[].from` | string | Source header, for `copy` and `rename`. | [Policy](../use/policy.md) |
| `request_header_rules[].ops[].to` | string | Target header, for `copy` and `rename`. | [Policy](../use/policy.md) |
| `request_header_rules[].ops[].mode` | string | Forward filter mode, for `forward`: `all`, `allowlist` or `denylist`. | [Policy](../use/policy.md) |
| `request_header_rules[].ops[].names` | list of strings | Header names the forward filter applies to, for `forward`. | [Policy](../use/policy.md) |

## Admin settings

Each prefix is the body of its settings endpoint: `guard`, `notifications` and `autopilot` are `GET` and `PUT /api/settings/<prefix>`, and `traffic_map` is `/api/settings/traffic-map`.

| Field | Type | What it is | Read |
|---|---|---|---|
| `guard.enabled` | bool | Turns the rollback guard on or off. | [Settings](../use/settings.md) |
| `guard.window` | duration | During a canary, how far back the guard compares the candidate with the active version; after a full publish, how long it watches the new version against the window before it. At least 1m. | [Settings](../use/settings.md) |
| `guard.min_requests` | int | Least requests in the window before the guard judges, at least 1. | [Settings](../use/settings.md) |
| `guard.evaluate_every` | duration | How often the guard checks, at least 1s. | [Settings](../use/settings.md) |
| `guard.max_auto_rollbacks_per_publish` | int | Most automatic rollbacks for one publish, not negative. | [Settings](../use/settings.md) |
| `guard.step_min_time` | duration | Least time each canary step runs, not negative. | [Settings](../use/settings.md) |
| `guard.signals.<name>.mode` | string | What a tripped signal does: `rollback`, `alert` or `off`. | [Settings](../use/settings.md) |
| `guard.signals.<name>.factor` | float | Trips when the value is this many times the baseline, at least 1. | [Settings](../use/settings.md) |
| `guard.signals.<name>.floor` | float | Absolute ratio the value must also pass, 0 to 1. | [Settings](../use/settings.md) |
| `guard.signals.<name>.floor_ms` | float | Absolute latency in milliseconds the value must also pass, not negative. | [Settings](../use/settings.md) |
| `guard.signals.<name>.min_ratio` | float | Lowest fleet adoption ratio allowed, above 0 and at most 1. | [Settings](../use/settings.md) |
| `guard.signals.<name>.max_ratio` | float | Highest limited ratio allowed, above 0 and at most 1. | [Settings](../use/settings.md) |
| `guard.signals.<name>.max_vs_shadow` | float | How many times the shadow rate a changed rule may limit, at least 1. | [Settings](../use/settings.md) |
| `guard.signals.<name>.after` | duration | How long after publish the signal starts to judge, not negative. | [Settings](../use/settings.md) |
| `notifications.enabled` | bool | Turns notifications on or off. | [Notifications](../operate/notifications.md) |
| `notifications.window` | duration | The recent span each check measures, whole minutes from 1m to 1h. | [Notifications](../operate/notifications.md) |
| `notifications.baseline` | duration | The span before the window each check compares with, whole minutes, at least the window and at most 24h. | [Notifications](../operate/notifications.md) |
| `notifications.fire_after` | int | Checks in a row that must trip before a notification, 1 to 60. Checks run every minute. | [Notifications](../operate/notifications.md) |
| `notifications.resolve_after` | int | Checks in a row that must pass before it resolves, 1 to 60. | [Notifications](../operate/notifications.md) |
| `notifications.signals.<name>.mode` | string | `notify` or `off`. | [Notifications](../operate/notifications.md) |
| `notifications.signals.<name>.severity` | string | `critical`, `warning` or `info`. | [Notifications](../operate/notifications.md) |
| `notifications.signals.<name>.factor` | float | Trips when the value is this many times the baseline. | [Notifications](../operate/notifications.md) |
| `notifications.signals.<name>.floor` | float | Absolute ratio the value must also pass. | [Notifications](../operate/notifications.md) |
| `notifications.signals.<name>.floor_ms` | float | Absolute latency in milliseconds the value must also pass. | [Notifications](../operate/notifications.md) |
| `notifications.signals.<name>.max_share` | float | Highest share allowed, for signals that bound a share. | [Notifications](../operate/notifications.md) |
| `notifications.signals.<name>.min_requests` | int | Least requests the signal needs before it can trip. | [Notifications](../operate/notifications.md) |
| `notifications.signals.<name>.min_events` | int | Least counted events (5xx, failed token checks) a share signal needs. For verified_bots_stale, the failed refreshes in a row. | [Notifications](../operate/notifications.md) |
| `notifications.rules.<rule>.<signal>.mode` | string | Per-rule override of the signal setting: `notify` or `off`. | [Notifications](../operate/notifications.md) |
| `notifications.rules.<rule>.<signal>.severity` | string | Per-rule override of the signal setting: `critical`, `warning` or `info`. | [Notifications](../operate/notifications.md) |
| `notifications.rules.<rule>.<signal>.factor` | float | Per-rule override of the signal setting: trips when the value is this many times the baseline. | [Notifications](../operate/notifications.md) |
| `notifications.rules.<rule>.<signal>.floor` | float | Per-rule override of the signal setting: absolute ratio the value must also pass. | [Notifications](../operate/notifications.md) |
| `notifications.rules.<rule>.<signal>.floor_ms` | float | Per-rule override of the signal setting: absolute latency in milliseconds the value must also pass. | [Notifications](../operate/notifications.md) |
| `notifications.rules.<rule>.<signal>.max_share` | float | Per-rule override of the signal setting: highest share allowed, for signals that bound a share. | [Notifications](../operate/notifications.md) |
| `notifications.rules.<rule>.<signal>.min_requests` | int | Per-rule override of the signal setting: least requests the signal needs before it can trip. | [Notifications](../operate/notifications.md) |
| `notifications.rules.<rule>.<signal>.min_events` | int | Per-rule override of the signal setting: least counted events a share signal needs. | [Notifications](../operate/notifications.md) |
| `autopilot.mode` | string | `off`, `observe` or `auto`. | [Autopilot](../use/autopilot.md) |
| `autopilot.max_enforcing` | int | Most enforcing autopilot rules at once, 0 to 50. | [Autopilot](../use/autopilot.md) |
| `autopilot.max_sensors` | int | Most log-only autopilot rules at once, 0 to 50. | [Autopilot](../use/autopilot.md) |
| `autopilot.observe_for` | duration | How long a rule only logs before it can enforce, 1m to 1h. | [Autopilot](../use/autopilot.md) |
| `autopilot.default_ttl` | duration | Lifetime of an autopilot rule when the model sets none, from 1m to max_ttl. | [Autopilot](../use/autopilot.md) |
| `autopilot.max_ttl` | duration | Longest an autopilot rule runs before it is renewed, 1m to 24h. | [Autopilot](../use/autopilot.md) |
| `autopilot.max_lifetime` | duration | Longest an autopilot rule lives with renewals, from max_ttl to 720h. | [Autopilot](../use/autopilot.md) |
| `autopilot.max_block_share` | float | Largest share of fleet requests an autopilot rule may block, 0.001 to 0.2. | [Autopilot](../use/autopilot.md) |
| `autopilot.cases_per_hour` | int | Most cases the autopilot opens in an hour, 1 to 200. | [Autopilot](../use/autopilot.md) |
| `autopilot.min_publish_interval` | duration | Least time between autopilot publishes, 30s to 15m. | [Autopilot](../use/autopilot.md) |
| `autopilot.model` | string | Model id for cases, 1 to 100 letters, digits and `._:/@-`. | [Autopilot](../use/autopilot.md) |
| `autopilot.sweep_model` | string | Model id for sweeps, same form as model. | [Autopilot](../use/autopilot.md) |
| `autopilot.sweep_enabled` | bool | Whether the autopilot opens sweep cases on its own. | [Autopilot](../use/autopilot.md) |
| `autopilot.review_enabled` | bool | Whether the autopilot opens review cases on its own. | [Autopilot](../use/autopilot.md) |
| `autopilot.anomaly_investigation_enabled` | bool | Whether the autopilot opens a case for an anomaly on its own. | [Autopilot](../use/autopilot.md) |
| `autopilot.protected_subjects` | list of strings | IPs, Classless Inter-Domain Routing (CIDR) ranges and Autonomous System (AS) numbers such as AS64500 no autopilot rule may block, at most 200. Not an edge exemption. | [Autopilot](../use/autopilot.md) |
| `traffic_map.edge.lat` | float | Latitude of the edges for the war room map, -90 to 90. | [Settings](../use/settings.md) |
| `traffic_map.edge.long` | float | Longitude of the edges, -180 to 180. | [Settings](../use/settings.md) |
| `traffic_map.edge.name` | string | Label for where the edges are, at most 60 characters. | [Settings](../use/settings.md) |
