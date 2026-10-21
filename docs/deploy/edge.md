# Edge settings

Environment variables only; there are no flags. An empty value means the default. Lists are comma-separated. Durations use Go syntax (`500ms`, `30s`, `168h`). If any value is invalid, the edge logs every problem and exits with code 2.

## Trust

These decide whom the edge believes. They come only from the deployment, never from admin.

| Variable | Default | Meaning |
|---|---|---|
| `CLIENT_IP_SOURCE` | required | `cloudfront`, `cloudflare`, `header:<Name>:ip`, `header:<Name>:ip_port`, `xff` or `remote_addr`. See [Client IP presets](#client-ip-presets) |
| `TRUSTED_PROXIES` | required unless `remote_addr` | IPs or CIDRs of the hop directly in front of the edge, usually your LB. A request from any other peer is rejected; the edge never falls back to the peer address. See [which hop to list](#client-ip-presets) |
| `VIEWER_HEADERS` | from the preset | `field=Header,...` for country, continent, ASN, scheme, HTTP version and client-certificate verification. A rule can use a viewer field only if a trusted source is configured |
| `INGRESS_SECRET_HEADER`, `INGRESS_SECRET_VALUES` | off | A header your CDN adds with a secret value. Requests without a matching value are rejected, and the header is removed before forwarding. Several values allow rotation |
| `ALLOW_REGEX` | `false` | Allows the `matches` operator in rules |

### Client IP presets

`CLIENT_IP_SOURCE` names where the client IP comes from. `cloudfront` and `cloudflare` are presets: they also set `VIEWER_HEADERS`, which you can extend or override field by field. The other sources read no viewer headers unless you set `VIEWER_HEADERS`.

| Source | Client IP read from | Viewer headers it sets |
|---|---|---|
| `cloudfront` | `CloudFront-Viewer-Address`, as `ip:port` | `ip.src.country=CloudFront-Viewer-Country`, `ip.src.asnum=CloudFront-Viewer-ASN`, `ssl=CloudFront-Forwarded-Proto`, `http.request.version=CloudFront-Viewer-Http-Version` |
| `cloudflare` | `CF-Connecting-IP`, as `ip` | `ip.src.country=CF-IPCountry`, `ssl=X-Forwarded-Proto` |
| `header:<Name>:ip` or `header:<Name>:ip_port` | The named header, as `ip` or `ip:port` | none |
| `xff` | `X-Forwarded-For`, the rightmost entry not in `TRUSTED_PROXIES`, or the leftmost if every entry is trusted | none |
| `remote_addr` | The TCP peer. Use it only when nothing sits in front of the edge | none; `VIEWER_HEADERS` is refused |

The viewer fields are `ip.src.country`, `ip.src.continent`, `ip.src.asnum`, `ssl`, `http.request.version` and `client_cert.verified`. `ssl` is true when its header is `https`; `client_cert.verified` when its header is `true`.

**Which hop goes in `TRUSTED_PROXIES`:** the edge matches it against its own TCP peer, the hop directly in front of it. With CDN → load balancer → edge that is the load balancer (its subnets or addresses), not the CDN. A request from any other peer gets 400. A request from a trusted peer whose client-IP header is missing or unparseable, or, for the single-header sources, sent more than once, also gets 400: the edge never falls back to the peer address, which would count every client as the load balancer.

With `xff`, the same list also tells the edge which `X-Forwarded-For` entries to skip, so it must include every proxy whose address appears in that header. Behind CDN → load balancer → edge, a load balancer that appends to `X-Forwarded-For` adds the CDN's address, so list the CDN's ranges as well, or the edge reads the CDN as the client.

## Upstream

The edge forwards every request it allows to one upstream: the load balancer or gateway that routes your services. It doesn't route itself, and it has no list of hosts or services.

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM_URL` | required | `http(s)://host[:port][/path]` of your load balancer or gateway, such as an ALB or an Istio gateway Service. `Host` is forwarded unchanged so it can route. Over HTTPS the edge sends the request's host as the TLS server name and checks the certificate against it, so the upstream must present a certificate for each host it serves; the connection still goes to this URL's address. Only the deployment sets it: policy can't, and admin shows it read-only on **Fleet** |
| `UPSTREAM_DIAL_TIMEOUT` | `5s` | Connect and TLS handshake timeout |
| `UPSTREAM_MAX_IDLE` | `256` | Idle connections kept to the upstream, in total. Over HTTPS each host has its own pool within this total |

## Policy source

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_URL` | none | Admin base URL. At least one of `ADMIN_URL`, `SNAPSHOT_CACHE_PATH` or `BOOTSTRAP_PATH` is required |
| `EDGE_SERVICE_TOKEN` or `EDGE_SERVICE_TOKEN_FILE` | required with `ADMIN_URL` | An edge token created in admin, or the deployment's own token when admin reads the same file through its `EDGE_SERVICE_TOKEN_FILE`. Set one, not both. Prefer the file form, mounted from a secret |
| `POLL_INTERVAL` | `5s` | How often to poll admin. Backs off to about a minute while admin fails |
| `SNAPSHOT_CACHE_PATH` | none | Where to keep the last good policy, so a restart works without admin |
| `BOOTSTRAP_PATH` | none | A policy file exported from admin, used when admin and the cache both fail |
| `BOOTSTRAP_MAX_AGE` | `168h` | A bootstrap file older than this is refused |
| `BOOTSTRAP_ALLOW_STALE` | `false` | Serve an old bootstrap anyway. Logged at error level and shown in **Fleet** |
| `STATS_INTERVAL` | `10s` | How often stats are sent to admin. At most `30s`: admin counts an edge toward the fleet size, which divides local fallback limits, for a minute after its last report |
| `INSTANCE` | hostname | The name shown in **Fleet** |
| `JWKS_ALLOWED_HOSTS` | none | JWKS hosts (as in the URL) allowed to resolve to private addresses. JWKS URLs are entered in admin, so every JWKS fetch goes through the SSRF (server-side request forgery) guard: it is HTTPS only, uses no proxy and follows redirects only to the same host. Except for the listed hosts, it is also refused when the address actually dialed is loopback, private, link-local (cloud metadata), shared (`100.64.0.0/10`), multicast, unspecified, or a NAT64 (`64:ff9b::/96`) form of one of those |

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
| `TOKEN_CACHE_SIZE` | `10000` | Verified tokens kept per replica so repeat requests skip the signature check. When full, new tokens are verified on every request but not stored. Raise it when `edge_auth_total{result="verified"}` stays high next to `cached` |
| `MAX_HEADER_BYTES` | `65536` | |
| `READ_HEADER_TIMEOUT` | `10s` | |
| `IDLE_TIMEOUT` | `75s` | Keep-alive idle timeout, on the public and internal listeners. Set your LB's idle timeout below it |
| `DRAIN_DELAY` | `10s` | After SIGTERM, how long `/readyz` fails before the edge stops accepting |
| `SHUTDOWN_TIMEOUT` | `30s` | How long in-flight requests get to finish |
| `LOG_SAMPLE_RATE` | `1` | Share of allowed, non-5xx requests to log (0 to 1). Rejections and 5xx are always logged |

Per-route body limits and upstream timeouts are policy, not deployment settings; see [Policy](../use/policy.md#settings).
