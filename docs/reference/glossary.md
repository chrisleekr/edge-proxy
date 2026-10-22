# Glossary

Terms used in the admin UI, the logs, the metrics and these docs. Each links to the page that explains it.

| Term | Meaning |
|---|---|
| **Action** | What a rule does to the requests its expression matches: settings in `config`, `block` or `log` in `rate_limit`, header operations in `request_headers`. See [Policy](../use/policy.md#phases) |
| **Admin** | The internal service and UI that manage policy, store it in Postgres and serve it to edges. Never on the request path. See [Admin settings](../deploy/admin.md) |
| **Audit log** | An append-only record of every change, who made it and a diff. Rows are HMAC-chained with a key kept outside Postgres, so a changed or deleted row is detected. See [Publish and roll back](../use/publishing.md#audit) |
| **Bootstrap snapshot** | A snapshot file exported from admin (**Versions → Download bootstrap file**) and set as `BOOTSTRAP_PATH`. An edge uses it at start only when admin and `SNAPSHOT_CACHE_PATH` both fail, and refuses it when older than `BOOTSTRAP_MAX_AGE` unless `BOOTSTRAP_ALLOW_STALE=true`. See [Deploy](../deploy/index.md#where-an-edge-gets-its-policy) |
| **Breaker** | Per Valkey node: after a run of consecutive failures the edge stops calling that node for a short time, then lets one probe through. See [Rate limiting](../use/rate-limiting.md#when-valkey-fails) |
| **Burst** | How many requests above the steady rate a `token_bucket` or `leaky_bucket` rule accepts at once. See [Rate limiting](../use/rate-limiting.md#the-algorithms) |
| **Canary** | Publishing a version to a percentage of clients first. Clients are chosen by a hash of their IP, so each client sees one version. Step it up, promote it or abort it. See [Publish and roll back](../use/publishing.md#canary) |
| **CDN** | Content delivery network, such as CloudFront or Cloudflare. It sits in front of the edge and sets the client-IP header. The edge trusts that header only from a peer in `TRUSTED_PROXIES`, the hop directly in front of it, usually the load balancer, not the CDN. See [Edge settings](../deploy/edge.md#client-ip-presets) |
| **Client IP** | The IP the edge believes, read from `CLIENT_IP_SOURCE` and only from a peer in `TRUSTED_PROXIES`. Requests from other peers are rejected; the edge never falls back to the peer address. See [Edge settings](../deploy/edge.md#trust) |
| **Cohort** | The requests served by one version. During a canary each request is in the `active` or `candidate` cohort (`edge.cohort` in the access log), and the guard compares the two. See [Monitoring](../operate/monitoring.md#logs) |
| **Config test** | A stored synthetic request and the outcome you expect from it, run through the edge's own code. A failing test blocks publish. See [Policy](../use/policy.md#config-tests) |
| **CORS / preflight** | Browser cross-origin rules / the `OPTIONS` request a browser sends before a cross-origin request. The edge answers preflights itself from a named CORS policy. See [Policy](../use/policy.md#cors) |
| **Draft** | The one shared, unpublished copy of the policy that editors change. Every save is validated, and saves are guarded by revision; if the live version moved on, rebase the draft. See [Publish and roll back](../use/publishing.md#draft) |
| **Edge** | The stateless proxy that takes traffic, enforces the policy and forwards to `UPSTREAM_URL`. Run several replicas. See [Edge settings](../deploy/edge.md) |
| **Expression** | A rule's condition, built from fields, operators and values in the rule builder or as text. See [Expressions](expressions.md) |
| **Fail-open / fail-closed** | What a rate-limit rule does when Valkey can't answer, set by its required `fail_mode` (a new rule in the UI starts with `open`): `open` lets the request through, `closed` answers `503` for a blocking rule, `local` counts on each edge alone. A log-only rule never fails closed. See [Rate limiting](../use/rate-limiting.md#when-valkey-fails) |
| **Fixed / sliding window** | Count requests per fixed time slot / estimate the count over the last period from the current and previous slots. See [Rate limiting](../use/rate-limiting.md#the-algorithms) |
| **Fleet / fleet size** | The live edges, shown on **Fleet** with the version each runs / the number of edges recently reporting stats to admin, which divides `fail_mode: local` limits. See [Rate limiting](../use/rate-limiting.md#when-valkey-fails) |
| **Guard (rollback guard)** | Admin process that watches a canary, or a set window after a publish, and compares the new version with the old one. It rolls back or aborts on signals only a config change causes, and only alerts on the rest. See [Publish and roll back](../use/publishing.md#rollback-guard) |
| **IdP** | Identity provider: the service that issues the JWTs the edge verifies |
| **Ingress secret** | A header your CDN adds with a secret value (`INGRESS_SECRET_HEADER`). Requests without a matching value are rejected, and the header is removed before forwarding. See [Edge settings](../deploy/edge.md#trust) |
| **Issuer** | A JWT issuer in settings: its `iss`, audiences, JWKS URL and algorithm. Config rules choose which issuers a route accepts. See [Policy](../use/policy.md#settings) |
| **JWKS / `kid`** | An issuer's public key set / the key ID in a token. Admin and edges fetch it through the SSRF guard, and an edge keeps the newest keys it has when the IdP is down. See [Runbooks](../operate/runbooks.md#identity-provider-down) |
| **JWT** | JSON Web Token. Rules and rate-limit keys use claims only from a token that verified. See [Policy](../use/policy.md#settings) |
| **Kill switch** | Settings that turn every rate-limit rule into `log`, or turn JWT checks off, once published. See [Rate limiting](../use/rate-limiting.md#emergency-switch) |
| **Local backstop** | A per-IP token bucket in each edge's memory, applied before any shared limit. It absorbs floods without Valkey and works while Valkey is down. Per edge, so the fleet ceiling is about the number of edges times the setting. See [Rate limiting](../use/rate-limiting.md#local-backstop) |
| **Locale** | The user's language, such as `en-AU`, detected from `Accept-Language` against the supported list and available to rules as `edge.locale`. See [Policy](../use/policy.md#locale) |
| **Normalized path** | The request path after decoding and resolving, which rules match on. Ambiguous encodings such as `%5C` and `..` segments are rejected with `400`; `%2F` stays encoded. See [Expressions](expressions.md#fields) |
| **Penalty** | On a blocking rate-limit rule, how long a key stays blocked after its first rejected request. Edges cache active penalties and answer them without calling Valkey. See [Rate limiting](../use/rate-limiting.md#penalty) |
| **Phase** | A point in the request path where one kind of rule runs: `config`, `rate_limit` or `request_headers`. See [Policy](../use/policy.md#phases) |
| **Policy** | Everything you edit: rules in phases, plus templates, CORS policies, issuers and settings. You change it as the draft and publish it as a version. See [Policy](../use/policy.md) |
| **POP** | Point of presence: one of a CDN's data centres. Vendors count rate limits per POP, server or region. See [Compared with vendors](../vendor-comparison.md) |
| **Publish** | Turning the saved draft into a new version, after its config tests pass. Edges pick it up within a poll interval (`POLL_INTERVAL`). See [Publish and roll back](../use/publishing.md#publish) |
| **Readiness** | `/readyz` on `INTERNAL_ADDR`. It fails only while no snapshot is loaded or while the edge drains, never because a dependency is down. See [Runbooks](../operate/runbooks.md#edge-not-ready) |
| **Revert** | Publishing an old version's config as a new version. History is never rewritten. See [Publish and roll back](../use/publishing.md#revert) |
| **Role / permission** | A bundle of permissions (viewer, editor, publisher, admin) / one allowed action. Access is checked by permission. See [Dashboard](../use/dashboard.md#roles) |
| **Routes** | Admin's list of every route the edges served, built from their access logs by a log shipper. See [Dashboard](../use/dashboard.md#routes) |
| **Rule** | An expression and an action, in one phase. See [Policy](../use/policy.md) |
| **Shadow mode** | A rate-limit rule with `action: log`: it counts what it would have limited and never blocks. See [Rate limiting](../use/rate-limiting.md#before-you-block-shadow-mode) |
| **Site-wide rule** | A rate-limit rule whose expression is `true`. It runs on every request, doesn't count toward the cap on other matching rules, and has its own cap. See [Rate limiting](../use/rate-limiting.md#several-rules-on-one-request) |
| **Snapshot** | What an edge loads: the active version, plus the canary candidate during a canary, the fleet size and the issuers' latest keys. Admin serves it on `GET /v1/snapshot`; the edge validates it before switching, keeps its current one if that fails, and saves it to `SNAPSHOT_CACHE_PATH`. `edge_snapshot_version` is the active version's number. See [Deploy](../deploy/index.md#where-an-edge-gets-its-policy) |
| **SSRF guard** | The check on every JWKS fetch, by admin or an edge, that allows HTTPS only, uses no proxy, follows redirects only to the same host, and refuses private, loopback, link-local and other non-public addresses, checked on the address actually dialed. `JWKS_ALLOWED_HOSTS` lets named hosts resolve to private addresses; the other checks still apply. See [Edge settings](../deploy/edge.md#policy-source) |
| **Template** | The body the edge sends for one kind of response it answers itself, such as `rate_limited`, in JSON, problem+json, HTML or text. See [Policy](../use/policy.md#settings) |
| **Token / leaky bucket** | Tokens refill at a steady rate and each request takes one / requests fill a bucket that drains at a steady rate. Both allow a burst. See [Rate limiting](../use/rate-limiting.md#the-algorithms) |
| **Upstream** | The one load balancer or gateway the edge forwards every allowed request to, `UPSTREAM_URL`, with `Host` unchanged. The edge does not route. See [Edge settings](../deploy/edge.md#upstream) |
| **Valkey** | The in-memory store that holds rate-limit counters, shared by every edge. It holds no policy or durable data. See [Edge settings](../deploy/edge.md#valkey) |
| **Version** | One published policy: numbered and never changed. A publish, a revert and an automatic rollback each create a new version. See [Publish and roll back](../use/publishing.md) |
| **Viewer field** | A fact about the client's connection to the CDN (country, continent, ASN, scheme, HTTP version, client certificate) read from a trusted CDN header. A rule can use one only if the deployment configures its source. See [Expressions](expressions.md#fields) |
| **WAF** | Web application firewall. It stays in front of the edge, which has no OWASP rules or bot detection |
| **Wildcard / strict wildcard** | An operator where `*` matches any characters across the whole value, ASCII case-insensitive / case-sensitive. See [Expressions](expressions.md#operators) |
