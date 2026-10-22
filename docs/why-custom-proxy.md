# Why a custom proxy

Edge Proxy is a small Go proxy built for one job: applying policy to every request before it reaches your services. This page explains why it doesn't build on an existing gateway and how it compares with the common ones. For more on content delivery networks (CDNs) and cloud web application firewalls (WAFs), see [Compared with vendors](vendor-comparison.md).

## What it needed

- One rate limiter in front of every service, so no microservice has to build its own.
- One place to maintain limits. When every service has its own limiter, each one has its own code, keys and settings, and a fix or a new rule has to be made in each of them.
- A rate limit counted once across all replicas, so a limit of 100 means 100.
- A choice of algorithm, including sliding window and leaky bucket, which holds traffic to a steady rate with a small allowed burst.
- Limits per user or tenant, read from a verified JSON Web Token (JWT).
- Rule changes that take effect in seconds, without a deploy or restart.
- A client IP address that clients can't fake.
- Traffic that keeps flowing when Valkey, the database or the admin service is down.

## Why the usual places don't work

Rate limits in a CDN or WAF are counted where the request lands. Cloudflare, for example, keeps a separate counter in each data centre and has no global counter, so the same limit applies once per data centre ([request rate](https://developers.cloudflare.com/waf/rate-limiting-rules/request-rate/)). Which request details you can count by depends on your plan ([parameters](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/)), and limiting by a JWT claim needs Enterprise ([JWT validation](https://developers.cloudflare.com/api-shield/security/jwt-validation/)). Keep the CDN in front for distributed denial-of-service (DDoS) protection, bot rules and HTTPS. Edge Proxy adds one count for all your traffic behind it.

A proxy such as NGINX counts on each server separately, so three servers enforce three limits. Its rules live in a config file, so changing one means a reload or a deploy ([limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)).

Limiters inside each service are written and configured differently by each team, and in-memory ones count per process. Many services have none.

Wherever the limit runs, it can be skipped if it reads the client IP address from the first `X-Forwarded-For` entry, because the client writes that entry ([MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)).

## Why not another gateway

Envoy, APISIX, Kong, Tyk and Traefik can all share a rate limit across replicas. Each one falls short in a way that only replacing its rate limiter would fix:

- The algorithm is fixed. Envoy's reference rate-limit service uses fixed windows, and Traefik uses a token bucket.
- The default limiter counts on each server separately (Tyk).
- Each limit makes its own Redis call (APISIX, Kong).
- A Redis outage blocks traffic and there is no setting to change that (Traefik).
- The free edition can limit by a JWT claim only when the claim names a consumer registered in the gateway ahead of time, so a user or tenant ID can't be the key ([APISIX][apx-jwt], [Kong][kong-jwt]). [Traefik's JWT middleware][tr-jwt] is in Traefik Hub only.

Replacing a gateway's limiter and failure handling is most of what this project is. For APISIX, Kong, Tyk and Traefik it would be a plugin in the gateway's own plugin system. Envoy instead calls a separate rate-limit service over gRPC, which you could write in Go, but then every rate-limited request makes an extra network call to that service before it reaches Valkey, you run and scale Envoy and the service side by side, and Envoy's failure setting covers the whole filter rather than one rule ([global rate limiting][env-rl], [failure mode][env-fail]). Forwarding requests is the easy part, and Go's standard library already does it.

| Mark | Meaning |
|---|---|
| ✓ | Built in, in the free edition |
| ◐ | Partly; the cell says how |
| ✗ | Not available |
| ? | Their docs and source neither confirm nor rule it out |

| | Edge Proxy | Envoy | APISIX | Kong | Tyk | Traefik | HAProxy | NGINX |
|---|---|---|---|---|---|---|---|---|
| Exact limit across replicas | ✓ | [✓][env-rl] | [✓][apx-count] | [✓][kong-policies] | [◐ not the default limiter][tyk-rl] | [✓][tr-rl] | [✗ synced copies][hap-st] | [✗ per server][ngx-req] |
| Algorithms | fixed, sliding, token bucket, leaky bucket | [fixed window][env-window] | [leaky][apx-req], [fixed, sliding][apx-count] | [fixed window][kong-schema] | [token bucket per server (default)][tyk-rl], [sliding log][tyk-session], [fixed][tyk-limiter] | [token bucket][tr-rl] | [sliding, fixed][hap-rl] | [leaky bucket][ngx-req] |
| One Redis call for all limits | ✓ | [✓][env-pipe] | [✗][apx-util] | [✗][kong-handler] | [◐ one per check][tyk-session] | ? | no Redis | no Redis |
| Limit by JWT claim, free edition | ✓ | [✓][env-jwt] | [◐ registered consumers only][apx-count] | [◐ registered consumers only][kong-schema] | [✓][tyk-jwt] | [✗ Hub only][tr-jwt] | [◐ local keys only][hap-jwt] | [✗ Plus only][ngx-jwt] |
| Choice of behaviour when Redis is down | ✓ per rule | [◐ per filter][env-fail] | [✓ per plugin][apx-count] | [✓ per plugin][kong-schema] | [◐ depends on the limiter][tyk-session] | [✗ returns 500][tr-fail] | no Redis | no Redis |
| Log-only mode | ✓ | [✓][env-shadow] | [✗][apx-count] | [✗][kong-schema] | [✗][tyk-rl] | [✗][tr-rl] | ? | [✓][ngx-req] |

## What Edge Proxy does

### Rate limiting

- Each limit is one Valkey key, updated by a Lua script that uses Valkey's clock, so every replica sees the same count and the same time.
- The site-wide limits and up to 5 other limits a request matches go to Valkey in one round trip ([several rules on one request](use/rate-limiting.md#several-rules-on-one-request)). The call is never retried, so a request is never counted twice.
- Four algorithms: fixed window, sliding window, token bucket and leaky bucket. Leaky bucket here works the same way as the Generic Cell Rate Algorithm ([algorithms](use/rate-limiting.md#the-algorithms)).
- A limit can be keyed on up to five parts, such as the client IP address, a verified JWT claim, the country, or a header, cookie or query argument paired with the IP address or a claim ([rules that keep limits honest](use/rate-limiting.md#rules-that-keep-limits-honest)).
- A rule can block a client for a set time after it goes over the limit ([penalty](use/rate-limiting.md#penalty)), or only count what it would have blocked so you can check it against real traffic first ([shadow mode](use/rate-limiting.md#before-you-block-shadow-mode)).
- Each Edge Proxy replica also keeps a per-IP limit in memory that absorbs floods without calling Valkey ([local backstop](use/rate-limiting.md#local-backstop)).
- When Valkey can't answer, each rule lets traffic through, returns `503` or counts on each Edge Proxy replica alone, as you choose ([when Valkey fails](use/rate-limiting.md#when-valkey-fails)).
- One setting turns every rule into log-only at once ([emergency switch](use/rate-limiting.md#emergency-switch)).

### Who the client is

- JWTs are checked per route against your identity providers' keys, and a route can accept several issuers.
- The client IP address is read only from proxies listed in `TRUSTED_PROXIES` ([edge settings](deploy/edge.md)).
- Edge Proxy sends your services the client IP address, the country and the verified user's issuer and subject in `X-Edge-*` headers. It removes any copies a client sent first, so services can trust them as long as they can only be reached through Edge Proxy ([headers your upstream can trust](use/policy.md#headers-your-upstream-can-trust), [bypass the edge](operate/runbooks.md#bypass-the-edge)).

### Headers, CORS, locale and responses

- Header rules can set, append, remove, copy or rename request headers, and choose which headers are forwarded at all. A value can include the client IP address, a verified JWT claim, the country, the locale or the request ID ([header rules](use/policy.md#header-rules)).
- On a route with a cross-origin resource sharing (CORS) policy, Edge Proxy answers preflight requests itself. On other responses it replaces the service's CORS headers with its own, including on its own `401` and `429` responses ([CORS](use/policy.md#cors)).
- It picks a language from `Accept-Language` out of the ones you support and sends it to your services in a header ([locale](use/policy.md#locale)).
- Its own error responses, such as a `401` or a `429`, use templates you write in JSON, problem+json, HTML or text ([settings](use/policy.md#settings)).
- Rules match on the path, host, method, headers, cookies, query arguments, client IP address, country or verified JWT claims ([expressions](reference/expressions.md)). Paths are normalized before matching, and ambiguous encodings are rejected.

### Keeps running

- Edge Proxy loads new rules in the background within about 5 seconds. Nothing is parsed or fetched per request.
- If admin or the database is down, Edge Proxy keeps the rules it has and keeps serving.

On a laptop, with no rate-limit rules, the median request took 0.77 ms through Edge Proxy, 0.68 ms through NGINX and 0.54 ms straight to the service. With the full policy it added 1.4 ms, mostly the Valkey round trip ([capacity planning](deploy/capacity.md)).

## The admin UI

Rules are edited in a web UI. Admin checks each change with the same Go code Edge Proxy runs, runs your config tests against it, and keeps every version. A new version can go to part of the traffic first, and it rolls back on its own if errors rise or a changed rule blocks far more than expected. Every change is recorded in an audit log ([publish and roll back](use/publishing.md)).

The UI also shows what is happening. **Stats** shows how many requests each rule checked and blocked, and **Routes** lists every route Edge Proxy served, with its traffic and what each rule does to it ([dashboard](use/dashboard.md)).

## What Edge Proxy gives up

- You patch it yourself, including Go security releases.
- There is no distributed tracing, only access logs and Prometheus metrics ([monitoring](operate/monitoring.md)).
- HTTP/3, HTTPS to clients, retries and routing are left to the CDN and the load balancer.
- There are no third-party plugins.

## When something else is better

If fixed windows are enough and you already run Envoy, use its rate-limit service. If rough per-IP limits are enough, your CDN or NGINX will do.

[env-rl]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/other_features/global_rate_limiting
[env-window]: https://github.com/envoyproxy/ratelimit/blob/main/src/limiter/cache_key.go
[env-pipe]: https://github.com/envoyproxy/ratelimit/blob/main/src/redis/fixed_cache_impl.go
[env-jwt]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/jwt_authn/v3/config.proto
[env-fail]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ratelimit/v3/rate_limit.proto
[env-shadow]: https://github.com/envoyproxy/ratelimit/blob/main/README.md
[apx-req]: https://github.com/apache/apisix/blob/master/docs/en/latest/plugins/limit-req.md
[apx-count]: https://github.com/apache/apisix/blob/master/docs/en/latest/plugins/limit-count.md
[apx-util]: https://github.com/apache/apisix/blob/master/apisix/plugins/limit-count/util.lua
[apx-jwt]: https://github.com/apache/apisix/blob/master/docs/en/latest/plugins/jwt-auth.md
[kong-schema]: https://github.com/Kong/kong/blob/master/kong/plugins/rate-limiting/schema.lua
[kong-handler]: https://github.com/Kong/kong/blob/master/kong/plugins/rate-limiting/handler.lua
[kong-policies]: https://github.com/Kong/kong/blob/master/kong/plugins/rate-limiting/policies/init.lua
[kong-jwt]: https://github.com/Kong/kong/blob/master/kong/plugins/jwt/schema.lua
[tyk-rl]: https://tyk.io/docs/api-management/rate-limit
[tyk-limiter]: https://github.com/TykTechnologies/tyk/blob/master/internal/rate/limiter.go
[tyk-session]: https://github.com/TykTechnologies/tyk/blob/master/gateway/session_manager.go
[tyk-jwt]: https://github.com/TykTechnologies/tyk/blob/master/gateway/mw_jwt.go
[tr-rl]: https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/
[tr-fail]: https://github.com/traefik/traefik/blob/master/pkg/middlewares/ratelimiter/rate_limiter.go
[tr-jwt]: https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/jwt/
[hap-st]: https://www.haproxy.com/blog/introduction-to-haproxy-stick-tables
[hap-rl]: https://www.haproxy.com/blog/what-to-look-for-in-a-rate-limiting-solution
[hap-jwt]: https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/authentication/oauth-authorization/
[ngx-req]: https://nginx.org/en/docs/http/ngx_http_limit_req_module.html
[ngx-jwt]: https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html
