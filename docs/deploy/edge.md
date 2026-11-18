# Edge settings

Environment variables only; there are no flags. An empty value means the default. Lists are comma-separated. Durations use Go syntax (`500ms`, `30s`, `168h`). If any value is invalid, the edge logs every problem and exits with code 2.

## Trust

These decide whom the edge believes. They come only from the deployment, never from admin.

| Variable | Default | Meaning |
|---|---|---|
| `CLIENT_IP_SOURCE` | required | `cloudfront`, `cloudflare`, `gcp`, `header:<Name>:ip`, `header:<Name>:ip_port`, `xff` or `remote_addr`. See [Client IP presets](#client-ip-presets) |
| `TRUSTED_PROXIES` | required unless `remote_addr` | IPs or CIDRs of the hop directly in front of the edge, usually your LB. A request from any other peer is rejected; the edge never falls back to the peer address. See [which hop to list](#client-ip-presets) |
| `VIEWER_HEADERS` | from the preset | `field=Header,...` for country, continent, ASN, scheme, HTTP version, client-certificate verification and the JA4 and JA3 TLS fingerprints. A rule can use a viewer field only if a trusted source is configured |
| `CDN_HEADERS` | from the preset | Comma-separated names of the headers your CDN sets, or `none` (case-insensitive). Each is logged on every access line and offered to rules (except source and edge-managed headers), and admin must have the same value. Which of them rules may trust is [policy](#cdn-headers). The `cloudfront` and `cloudflare` presets list their CDN's documented headers; `gcp` and the other sources list none. A list replaces the preset's. Refused at startup: `Authorization`, `Proxy-Authorization`, `Cookie`, `Referer`, `Cf-Access-Jwt-Assertion`, `Cf-Access-Client-Id`, `Cf-Access-Client-Secret`, `X-Goog-Iap-Jwt-Assertion`, `X-Amzn-Oidc-Accesstoken`, `X-Amzn-Oidc-Data`, `CloudFront-Error-Args`, `CloudFront-Error-Uri`, the `INGRESS_SECRET_HEADER`, a header every access line already logs, more than 48 names and any list with `remote_addr`. See [CDN headers](#cdn-headers) |
| `INGRESS_SECRET_HEADER`, `INGRESS_SECRET_VALUES` | off | A header your CDN adds with a secret value. Requests without a matching value are rejected, and the header is removed before forwarding. Several values allow rotation |
| `ALLOW_REGEX` | `false` | Allows the `matches` operator in rules |

### Client IP presets

`CLIENT_IP_SOURCE` names where the client IP comes from. `cloudfront`, `cloudflare` and `gcp` are presets: they also set `VIEWER_HEADERS`, which you can extend or override field by field. The other sources read no viewer headers unless you set `VIEWER_HEADERS`.

| Source | Client IP read from | Viewer headers it sets |
|---|---|---|
| `cloudfront` | `CloudFront-Viewer-Address`, as `ip:port` | `ip.src.country=CloudFront-Viewer-Country`, `ip.src.asnum=CloudFront-Viewer-ASN`, `ssl=CloudFront-Forwarded-Proto`, `http.request.version=CloudFront-Viewer-Http-Version` |
| `cloudflare` | `CF-Connecting-IP`, as `ip` | `ip.src.country=CF-IPCountry`, `ssl=X-Forwarded-Proto` |
| `gcp` | `X-Gclb-Client-Ip`, as `ip` | `ip.src.country=X-Gclb-Region`, `http.request.version=X-Gclb-Protocol`, `ssl=X-Gclb-Encrypted` |
| `header:<Name>:ip` or `header:<Name>:ip_port` | The named header, as `ip` or `ip:port` | none |
| `xff` | `X-Forwarded-For`, the rightmost entry not in `TRUSTED_PROXIES`, or the leftmost if every entry is trusted | none |
| `remote_addr` | The TCP peer. Use it only when nothing sits in front of the edge | none; `VIEWER_HEADERS` and `CDN_HEADERS` are refused |

The viewer fields are `ip.src.country`, `ip.src.continent`, `ip.src.asnum`, `ssl`, `http.request.version`, `client_cert.verified`, `tls.client.ja4` and `tls.client.ja3`. `ssl` is true when its header is `https` or `true`; `client_cert.verified` when its header is `true`. The HTTP version is read as `1.0`, `1.1`, `2.0` or `3.0` from either CloudFront's form or the `HTTP/2` form, for every source; any other value is absent. A rule comparing it with any other literal gets a validation warning, since it can never match. A fingerprint header that is empty or not a well-formed JA4 or JA3 is absent. With an `ssl` source, a fingerprint on a request that wasn't HTTPS is absent too: TLS fingerprints exist only for TLS, so any such value came from the client. On those requests no `X-Edge-TLS-JA4` is sent and `browser_tls_mismatch` can't fire. Map `ssl` whenever you map a fingerprint.

**`gcp`:** a Google Cloud external Application Load Balancer has no fixed viewer headers, so add these [custom request headers](https://docs.cloud.google.com/load-balancing/docs/https/custom-headers-global) to the backend service: `X-Gclb-Client-Ip: {client_ip_address}`, `X-Gclb-Region: {client_region}`, `X-Gclb-Protocol: {client_protocol}` and `X-Gclb-Encrypted: {client_encrypted}`. The load balancer overwrites only the headers it adds: any other header reaches the edge exactly as the client sent it. So every header the edge reads must be a custom header on the load balancer, including any you add to `VIEWER_HEADERS`. Send `INGRESS_SECRET_HEADER` as a custom header too. It is required when the edge can be reached through an internet NEG, or by any path not limited to your own VPC; see the [production checklist](index.md#production-checklist).

ASN and the TLS fingerprints are opt-in. Add `X-Gclb-Asn: {asn}`, `X-Gclb-Ja4: {tls_ja4_fingerprint}` and `X-Gclb-Ja3: {tls_ja3_fingerprint}` as custom headers first, and only then set `VIEWER_HEADERS=ip.src.asnum=X-Gclb-Asn,tls.client.ja4=X-Gclb-Ja4,tls.client.ja3=X-Gclb-Ja3`. Use only the variables Google documents for your load balancer type: the global external and [classic](https://docs.cloud.google.com/load-balancing/docs/https/custom-headers) Application Load Balancers have all three, and the [regional external Application Load Balancer](https://docs.cloud.google.com/load-balancing/docs/https/custom-headers-regional) has the fingerprints but no `{asn}`.

**Fingerprints on other CDNs** are opt-in through `VIEWER_HEADERS`, so a preset's deployment doesn't change:

| CDN | Add to `VIEWER_HEADERS` | Also needed |
|---|---|---|
| CloudFront | `tls.client.ja4=CloudFront-Viewer-JA4-Fingerprint,tls.client.ja3=CloudFront-Viewer-JA3-Fingerprint` | Add both headers to the cache behavior's [origin request policy](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html#tls-related-versions); a cache policy can't carry them. They are present only for HTTPS requests, and the edge ignores them on a request whose `ssl` is false. The preset's viewer headers need the same policy |
| Cloudflare | `tls.client.ja4=cf-ja4` | [JA4 fingerprints](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/) need Enterprise Bot Management, and the ["Add bot protection headers" Managed Transform](https://developers.cloudflare.com/rules/transform/managed-transforms/reference/) is what sets `CF-JA4`. Turn it on before mapping the header: whether Cloudflare replaces a client-sent copy isn't documented, so without the transform a client's own value could be read as the fingerprint. Name another header here if you have Cloudflare set one from the fingerprint |

A preset can be extended this way, such as `VIEWER_HEADERS=tls.client.ja4=CloudFront-Viewer-JA4-Fingerprint`, which keeps the preset's other headers.

**Which hop goes in `TRUSTED_PROXIES`:** the edge matches it against its own TCP peer, the hop directly in front of it. With CDN → load balancer → edge that is the load balancer (its subnets or addresses), not the CDN. A request from any other peer gets 400. A request from a trusted peer whose client-IP header is missing or unparseable, or, for the single-header sources, sent more than once, also gets 400: the edge never falls back to the peer address, which would count every client as the load balancer.

With `xff`, the same list also tells the edge which `X-Forwarded-For` entries to skip, so it must include every proxy whose address appears in that header. Behind CDN → load balancer → edge, a load balancer that appends to `X-Forwarded-For` adds the CDN's address, so list the CDN's ranges as well, or the edge reads the CDN as the client.

### CDN headers

`CDN_HEADERS` lists the headers the deployment's one CDN may set. Unset, it is the `CLIENT_IP_SOURCE` preset's list; `none` (case-insensitive) turns it off.

- **`cloudfront`:** `CloudFront-Viewer-Asn`, `-Isp`, `-Country`, `-Country-Name`, `-Country-Region`, `-Country-Region-Name`, `-City`, `-Postal-Code`, `-Metro-Code`, `-Time-Zone`, `-Latitude`, `-Longitude`, `-JA3-Fingerprint`, `-JA4-Fingerprint`, `-TLS`, `-TLS-Details`, `-Header-Order`, `-Header-Count` and `-Http-Version`, then `CloudFront-Forwarded-Proto` and `CloudFront-Is-Android-Viewer`, `-Desktop-Viewer`, `-IOS-Viewer`, `-Mobile-Viewer`, `-SmartTV-Viewer` and `-Tablet-Viewer`.
- **`cloudflare`:** `CF-IPCountry`, `CF-IPContinent`, `CF-IPCity`, `CF-Region`, `CF-Region-Code`, `CF-Metro-Code`, `CF-Postal-Code`, `CF-Timezone`, `CF-IPLatitude`, `CF-IPLongitude`, `CF-Ray`, `CF-Visitor`, `True-Client-IP`, `CF-JA4`, `CF-JA3-Hash`, `CF-Bot-Score`, `CF-Verified-Bot`, `CF-Cert-Verified`, `CF-Cert-Presented` and `CF-Cert-Revoked`.
- **`gcp` and the other sources:** none. Name the headers your load balancer adds.

A set of names replaces the preset's list, so a header the CDN adds later needs no release. Names are case-insensitive and de-duplicated. Latitude, longitude and postal code identify where a person is; drop them from the list if you don't want them in your logs.

The edge refuses to start with a name that carries credentials or query values: `Authorization`, `Proxy-Authorization`, `Cookie`, `Referer` (the access log keeps only its origin and path), `Cf-Access-Jwt-Assertion`, `Cf-Access-Client-Id`, `Cf-Access-Client-Secret`, `X-Goog-Iap-Jwt-Assertion`, `X-Amzn-Oidc-Accesstoken`, `X-Amzn-Oidc-Data`, `CloudFront-Error-Args`, `CloudFront-Error-Uri` and the `INGRESS_SECRET_HEADER`. It also refuses a header every access line already logs: `User-Agent`, `Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`, `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User`, `Accept`, `Accept-Language` and `Accept-Encoding`.

What a listed header does:

- **Logged.** Every access line carries it raw as `http.request.header.<lower-case name>`, as received, capped like the other logged headers ([Monitoring](../operate/monitoring.md#logs)). When the CDN doesn't set a header, the logged value is the client's.
- **Readable in rules.** As `http.request.headers["cf-ipcity"]`, with no new field. A condition that excludes traffic on a header the policy trusts gets no [client-controlled warning](../reference/expressions.md#fields), because it is the CDN's value; on an untrusted one it does. Admin suggests the names in the rule builder and lists them on **Fleet** ([Dashboard](../use/dashboard.md#fleet-and-stats)). The exceptions are logged but not readable: a source header (read it through its typed field, such as `ip.src.country`) and an edge-managed name, such as `X-Edge-*`, `X-Forwarded-*`, `Host` and the other [reserved headers](../use/policy.md#header-rules).
- **Forwarded.** Reaches the upstream unchanged, unless it is also a source header (a client-IP, `VIEWER_HEADERS` or ingress secret header, such as `CF-IPCountry` on the `cloudflare` preset), which the edge always removes. The edge also strips a client-sent `X-Edge-*` header and sets the edge-managed headers itself.
- **Signals.** `cdn_likely_automated`, `crawler_impersonated` and `browser_tls_old` read `CF-Bot-Score`, `CF-Verified-Bot` and `CloudFront-Viewer-TLS` when they are listed and trusted, and `cdn_tor` reads `ip.src.country` when `CF-IPCountry` is listed and is the header `ip.src.country` comes from, as on the `cloudflare` preset ([client signals](../reference/expressions.md#client-signals)). A rule naming one of these signals is refused when the deployment or policy doesn't meet that: the error names the header it needs listed in `CDN_HEADERS`, and for a header other than a source header, trusted in `global.cdn_trusted_headers`; for `cdn_tor`, it says when `ip.src.country` isn't read from `CF-IPCountry`. Admin judges every stored minute under the current deployment, so after a change to `CDN_HEADERS` or to the header `ip.src.country` comes from makes one of these signals readable, minutes stored before it count its zeros as normal traffic: until they age out of the baselines, [`signal_surge`](../operate/notifications.md#signals) can fire on it, and a [shared-key autopilot rule](../use/autopilot.md#rule-states) on it reads a low baseline for up to 7 days.

**Trust.** Listing a header only logs it and offers it to rules. Whether rules may treat it as the CDN's value is policy: **Settings → Trusted CDN headers** (`global.cdn_trusted_headers`), set by whoever edits policy, who knows which CDN features are on. Trusting a header declares that the CDN sets it on every request. The edge doesn't check. Cloudflare [passes client request headers through to the origin](https://developers.cloudflare.com/fundamentals/reference/http-headers/), and whether it replaces a client-sent copy of one of its own headers isn't documented, so a client can send a header whose feature is off. Trusting one only silences the client-controlled warning and lets rules name the CDN signals, which only narrow a match; it relaxes no check.

- **Default.** While the setting is unset, the trusted headers are the ones the preset's CDN adds to every proxied request with no optional feature, and only when they are in `CDN_HEADERS`: `CF-Ray` and `CF-Visitor` on `cloudflare`, none on `cloudfront` and `gcp`. Whether Cloudflare replaces a client-sent copy of them isn't documented; trusting them only silences the warning and lets rules name the signals. A list in the policy replaces the default, and an empty list trusts none.
- **Source headers.** A listed header that is also a source header, such as `CF-IPCountry` on the `cloudflare` preset, is always trusted, because the deployment already trusts it as `ip.src.country`. Naming one in the setting is saved with a warning and does nothing.
- **Not in `CDN_HEADERS`.** An entry the deployment doesn't list is saved with a warning and isn't trusted.
- **Refused.** An entry that is an edge-managed header ("is managed by the edge and can't be trusted by policy"), repeats, or makes more than 48 entries. A config that sets the list needs schema 8 edges.

Turn on the feature that sets each header before trusting it:

- **Cloudflare:** the Managed Transforms that add the headers, such as "Add visitor location headers", and, on Enterprise with Bot Management, "Add bot protection headers". Without Bot Management Cloudflare sends no bot headers, so don't trust `CF-Bot-Score` or `CF-Verified-Bot` then: a client could send its own and fire `cdn_likely_automated` or `crawler_impersonated`.
- **CloudFront:** an [origin request policy](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html) that adds the headers.
- **Reach:** `TRUSTED_PROXIES`, or a NetworkPolicy, limited to the CDN's connector, so no client reaches the edge directly.

Edge and admin must have the same `CDN_HEADERS`, because a non-empty list, and a non-empty default trust, are part of the deployment fingerprint: [publishing](../use/publishing.md#publish) is held while a live edge differs. A deployment with no CDN headers keeps the fingerprint it had before `CDN_HEADERS` existed. A `cloudfront` or `cloudflare` deployment gets a new one from its preset list, so on an upgrade from a release without `CDN_HEADERS`, publishing is held until admin and every live edge run the new release; reverts and guard rollbacks still work.

## Upstream

The edge forwards every request it allows to one upstream: the load balancer or gateway that routes your services. It doesn't route itself, and it has no list of hosts or services.

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM_URL` | required | `http(s)://host[:port][/path]` of your load balancer or gateway, such as an ALB or an Istio gateway Service, with no query or fragment. `Host` is forwarded unchanged so it can route. Over HTTPS the edge sends the request's host as the TLS server name and checks the certificate against it, so the upstream must present a certificate for each host it serves; the connection still goes to this URL's address. Only the deployment sets it: policy can't, and admin shows it read-only on **Fleet** |
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
| `MAX_INFLIGHT` | `GOMEMLIMIT` ÷ 256 KiB, at most `10000`; `10000` without `GOMEMLIMIT` | Concurrent ordinary requests per replica; more get `503 overloaded`. Each in-flight proxied request holds memory, about 100 KiB in a load test on Kubernetes, kernel socket buffers included, which `GOMEMLIMIT` doesn't cap. The default keeps that, plus streams and headroom, under `GOMEMLIMIT`, so set `GOMEMLIMIT` to about 90% of the container's memory limit. Past what memory holds, a slow upstream gets the edge OOM-killed instead of answering 503. **Settings → Requests in progress** in admin can lower it for every edge, never raise it |
| `MAX_STREAMS` | `1000` | Concurrent WebSocket and SSE requests per replica |
| `TOKEN_CACHE_SIZE` | `10000` | Verified tokens kept per replica so repeat requests skip the signature check. When full, new tokens are verified on every request but not stored. Raise it when `edge_auth_total{result="verified"}` stays high next to `cached` |
| `MAX_HEADER_BYTES` | `65536` | |
| `READ_HEADER_TIMEOUT` | `10s` | |
| `IDLE_TIMEOUT` | `75s` | Keep-alive idle timeout, on the public and internal listeners. Set your LB's idle timeout below it |
| `DRAIN_DELAY` | `10s` | After SIGTERM, how long `/readyz` fails before the edge stops accepting |
| `SHUTDOWN_TIMEOUT` | `30s` | How long in-flight requests get to finish |
| `LOG_SAMPLE_RATE` | `1` | Share of allowed, non-5xx requests to log (0 to 1). Rejections and 5xx are always logged |

Per-route body limits and upstream timeouts are policy, not deployment settings; see [Policy](../use/policy.md#settings).

## Tracing

Off unless an endpoint is set. When on, the edge joins the caller's trace, records one span per request that isn't shed for overload, and passes its own span to the upstream in `traceparent`. See [Monitoring](../operate/monitoring.md#traces).

| Variable | Default | Meaning |
|---|---|---|
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | unset (off) | Full OTLP/HTTP traces URL, such as `http://collector:4318/v1/traces` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Base OTLP/HTTP URL; `/v1/traces` is appended. Used when the traces endpoint is unset |
| `OTEL_SERVICE_NAME` | `edge-proxy` | `service.name` on every span. `service.instance.id` is `INSTANCE` |
| `TRACE_SAMPLE_RATE` | `0.01` | Share of new traces to sample (0 to 1). A caller's sampling decision is followed |
| `TRACE_MAX_PER_SECOND` | `100` | Most traces one replica starts and samples per second, and separately the most it samples per second from callers' traces. Callers choose their trace IDs and sampled flag, so only this cap bounds the export volume a client can force, and a flood of forged flags can't use up the edge's own budget |
| `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS` | none | Headers for the collector, such as credentials: `key=value` pairs separated by commas, values percent-encoded. A malformed value fails startup without being logged, because the exporter would log it |
| `TRACE_SHUTDOWN_TIMEOUT` | `5s` | At shutdown, after `SHUTDOWN_TIMEOUT`: how long to wait for open streams to record their spans and then flush, together |

The exporter also reads the other standard variables it supports, such as `OTEL_EXPORTER_OTLP_CERTIFICATE` for a private CA and `OTEL_EXPORTER_OTLP_COMPRESSION`, and the batch processor reads `OTEL_BSP_*` ([OpenTelemetry environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/), [OTLP exporter settings](https://opentelemetry.io/docs/specs/otel/protocol/exporter/)). The SDK checks those itself: a malformed value is ignored without a log line and the default is used. A plain `http` endpoint with a certificate set does fail startup.
