# Edge settings

Environment variables only; there are no flags. An empty value means the default. Lists are comma-separated. Durations use Go syntax (`500ms`, `30s`, `168h`). If any value is invalid, the edge logs every problem and exits with code 2.

## Trust

These decide whom the edge believes. They come only from the deployment, never from admin.

| Variable | Default | Meaning |
|---|---|---|
| `CLIENT_IP_SOURCE` | required | `cloudfront` (`CloudFront-Viewer-Address`), `cloudflare` (`CF-Connecting-IP`), `header:<Name>:ip` or `header:<Name>:ip_port`, `xff` (rightmost untrusted `X-Forwarded-For` entry), or `remote_addr` (no proxy in front) |
| `TRUSTED_PROXIES` | required unless `remote_addr` | IPs or CIDRs of your CDN or LB. A request from any other peer is rejected; the edge never falls back to the peer address |
| `VIEWER_HEADERS` | from the preset | `field=Header,...` for country, continent, ASN, scheme, HTTP version and client-certificate verification. A rule can use a viewer field only if a trusted source is configured |
| `INGRESS_SECRET_HEADER`, `INGRESS_SECRET_VALUES` | off | A header your CDN adds with a secret value. Requests without a matching value are rejected, and the header is removed before forwarding. Several values allow rotation |
| `ALLOW_REGEX` | `false` | Allows the `matches` operator in rules |

## Upstreams

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAMS` | required | `name=http(s)://host[:port][/path],...`. Rules refer to upstreams by name, never by URL |
| `UPSTREAM_HOSTS` | none | `host=name,...`: the default upstream for each `Host`. A request for an unknown host gets `421` unless a rule sets an upstream |
| `UPSTREAM_DIAL_TIMEOUT` | `5s` | Connect and TLS handshake timeout |
| `UPSTREAM_MAX_IDLE_PER_HOST` | `256` | Idle connection pool per upstream |

## Policy source

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_URL` | none | Admin base URL. At least one of `ADMIN_URL`, `SNAPSHOT_CACHE_PATH` or `BOOTSTRAP_PATH` is required |
| `EDGE_SERVICE_TOKEN` or `EDGE_SERVICE_TOKEN_FILE` | required with `ADMIN_URL` | The edge token from admin. Prefer the file form, mounted from a secret |
| `POLL_INTERVAL` | `5s` | How often to poll admin. Backs off to about a minute while admin fails |
| `SNAPSHOT_CACHE_PATH` | none | Where to keep the last good policy, so a restart works without admin |
| `BOOTSTRAP_PATH` | none | A policy file exported from admin, used when admin and the cache both fail |
| `BOOTSTRAP_MAX_AGE` | `168h` | A bootstrap file older than this is refused |
| `BOOTSTRAP_ALLOW_STALE` | `false` | Serve an old bootstrap anyway. Logged at error level and shown in **Fleet** |
| `STATS_INTERVAL` | `10s` | How often stats are sent to admin |
| `INSTANCE` | hostname | The name shown in **Fleet** |
| `JWKS_ALLOWED_HOSTS` | none | JWKS hosts allowed to resolve to private addresses. Others are blocked by the SSRF guard |

## Valkey

| Variable | Default | Meaning |
|---|---|---|
| `VALKEY_URL` | none | `redis://`, `rediss://`, `valkey://`, `valkeys://` or `unix://`. For a cluster, list nodes with `?addr=host:port&addr=...`. Without it every rule uses its `fail_mode` |
| `VALKEY_TIMEOUT` | `50ms` | Per-request budget for the rate-limit round trip. On timeout the rule's `fail_mode` applies |
| `EXPECTED_REPLICAS` | `1` | Fleet size for `fail_mode: local` when the policy carries no live fleet count, for example when loaded from cache or bootstrap. Admin normally sends the live count |

## Capacity and timeouts

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Traffic |
| `INTERNAL_ADDR` | `:9090` | `/livez`, `/readyz`, `/metrics` |
| `MAX_INFLIGHT` | `10000` | Concurrent ordinary requests per replica; more get `503 overloaded` |
| `MAX_STREAMS` | `1000` | Concurrent WebSocket and SSE requests per replica |
| `MAX_UPSTREAM_INFLIGHT` | `2000` | Concurrent requests per upstream per replica, open streams included |
| `TOKEN_CACHE_SIZE` | `10000` | Verified tokens kept per replica so repeat requests skip the signature check. When full, new tokens are verified on every request but not stored. Raise it when `edge_auth_total{result="verified"}` stays high next to `cached` |
| `MAX_HEADER_BYTES` | `65536` | |
| `READ_HEADER_TIMEOUT` | `10s` | |
| `IDLE_TIMEOUT` | `75s` | Keep-alive idle timeout, on the public and internal listeners. Set your LB's idle timeout below it |
| `DRAIN_DELAY` | `10s` | After SIGTERM, how long `/readyz` fails before the edge stops accepting |
| `SHUTDOWN_TIMEOUT` | `30s` | How long in-flight requests get to finish |
| `LOG_SAMPLE_RATE` | `1` | Share of allowed, non-5xx requests to log (0 to 1). Rejections and 5xx are always logged |

Per-route body limits and upstream timeouts are policy, not deployment settings; see [Policy](../use/policy.md#settings).
