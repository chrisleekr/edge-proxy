# Compared with vendors

For Envoy, APISIX, Kong and other gateways you run yourself, see [Why a custom proxy](why-custom-proxy.md).

**Why run this proxy if you already have Cloudflare, AWS WAF + CloudFront, Azure Front Door, Google Cloud Armor, Fastly or Akamai?**

Don't run it *instead of* a vendor. Run it *behind* one when you need application policy the vendors offer only through custom edge code or Enterprise add-ons:

- exact rate limits shared by every node
- limits keyed on a verified identity
- a header contract with your services
- tested, canaried policy changes owned by the application team

If none of those matter, a vendor alone is simpler.

| Mark | Meaning |
|---|---|
| ✓ | Native |
| ◐ | Partial, or only on a tier or add-on |
| 🛠 | Only by writing edge code (Workers, Lambda@Edge, VCL, EdgeWorkers, Service Extensions) |
| ✗ | Not available |
| ? | The vendor's docs neither confirm nor rule it out |

Vendor marks link to the vendor's documentation. **AFD** is Azure Front Door Standard/Premium with WAF. **GCA** is Google Cloud Armor with Cloud Load Balancing.

## Rate limiting

| Capability | Proxy | Cloudflare | AWS | AFD | GCA | Fastly | Akamai |
|---|---|---|---|---|---|---|---|
| Exact quota across all nodes | ✓ | [✗ per data centre][cf-rate] | [✗ approximate][aw-caveats] | [✗ per server][az-rate] | [✗ per region][gc-rate] | [✗ per POP][fa-rate] | [◐ per node or region][ak-rate] |
| Algorithms | ✓ 4 | [◐ undocumented][cf-rate] | [◐ estimate, 60 to 600s][aw-rate] | [◐ fixed, 1 or 5 min][az-rate] | [✓][gc-rate] | [◐ 1, 10, 60s][fa-rate] | [✓][ak-rate] |
| Key: IP, header, cookie, query | ✓ | [◐ IP; rest Enterprise][cf-rl] | [✓][aw-keys] | [◐ IP, geo][az-rules] | [◐ no query][gc-rate] | [◐ IP, User-Agent][fa-policy] | [✓][ak-rate] |
| Key: ASN, country | ✓ | [◐ Enterprise][cf-rl] | [◐ ASN][aw-keys] | [◐ geo][az-rules] | [✓][gc-rate] | [🛠][fa-policy] | [◐ condition only][ak-rate] |
| Key: verified JWT claim | ✓ | [◐ Enterprise][cf-jwt] | [✗][aw-keys] | [✗][az-rules] | [✗][gc-rate] | [🛠][fa-policy] | [✗][ak-rate] |
| Penalty after exceeding | ✓ | [✓][cf-rl] | [✗][aw-caveats] | [◐ rest of window][az-rate] | [✓][gc-rate] | [✓][fa-policy] | [✓][ak-rate] |
| Log-only mode | ✓ | [◐ Enterprise][cf-actions] | [✓][aw-count] | [✓][az-rules] | [✓][gc-rate] | [✓][fa-policy] | [✓][ak-rate] |
| Chosen behaviour when counting fails | ✓ | ? | [◐ fails open][aw-acl] | ? | ? | [◐ in your code][fa-concepts] | ? |
| Per-IP backstop | ✓ | [◐ DDoS only][cf-ddos] | [◐ paid][aw-ddos] | [◐ Premium][az-ddos-rules] | [◐ Enterprise][gc-enterprise] | [◐ add-on][fa-ddos] | [◐ add-on][ak-slowpost] |
| `Retry-After`, `RateLimit` headers | ✓ | [◐ `Retry-After`][cf-retry] | [◐ static][aw-response] | ? | [✗][gc-rate] | [🛠][fa-policy] | [◐ static][ak-deny] |

## Auth, CORS, headers, responses

| Capability | Proxy | Cloudflare | AWS | AFD | GCA | Fastly | Akamai |
|---|---|---|---|---|---|---|---|
| JWT validation per route | ✓ | [◐ Enterprise][cf-jwt] | [🛠][aw-functions] | [✗][az-actions] | [🛠][gc-extensions] | [🛠][fa-jwt] | [◐ API Gateway][ak-jwt] |
| CORS preflight answered at the edge | ✓ | [🛠][cf-cors] | [◐ headers only][aw-cors] | [◐ headers only][az-cors] | [◐][gc-urlmap] | [🛠][fa-cors] | [◐][ak-cors] |
| CORS `Vary: Origin`, upstream headers replaced | ✓ | [◐][cf-cors] | [◐][aw-cors] | [◐][az-cors] | ? | 🛠 | ? |
| Header set, append, remove | ✓ | [◐ no append][cf-headers] | [🛠][aw-insert] | [✓][az-vars] | [✓][gc-headers] | [✓][fa-headers] | [✓][ak-headers] |
| Header copy, rename | ✓ | [✗][cf-headers] | 🛠 | [◐][az-vars] | [✗][gc-headers] | 🛠 | [◐][ak-headers] |
| Forward only listed headers | ✓ | [✗][cf-headers] | [✓][aw-origin] | [✗][az-vars] | ✗ | 🛠 | ? |
| Client can't spoof edge headers | ✓ | [◐ `cf-*` only][cf-headers] | [◐][aw-insert] | [◐ `x-fd-*` only][az-vars] | [◐][gc-headers] | 🛠 | ? |
| Header values from verified claims | ✓ | [◐ Enterprise][cf-jwt] | 🛠 | ✗ | ✗ | 🛠 | [◐ unverified][ak-headers] |
| CR/LF stripped from values | ✓ | ? | ? | ? | [◐][gc-headers] | ? | ? |
| Locale from `Accept-Language` | ✓ | [◐ no matching][cf-lang] | 🛠 | ✗ | 🛠 | [🛠][fa-lang] | 🛠 |
| Templated error responses | ✓ | [◐ fixed tokens][cf-errors] | [◐ static][aw-response] | [◐ one body][az-response] | [◐ static][gc-errors] | 🛠 | [✓][ak-response] |
| Path normalized before matching | ✓ | [✓][cf-normalize] | [◐][aw-transform] | [◐ decode only][az-rules] | [◐][gc-urlmap-concepts] | [🛠][fa-normalize] | [✓ opt-in][ak-path] |

## Rules and change safety

| Capability | Proxy | Cloudflare | AWS | AFD | GCA | Fastly | Akamai |
|---|---|---|---|---|---|---|---|
| Rule language | ✓ | [✓][cf-lang-ref] | [✓ JSON][aw-rate] | [✓ JSON][az-rules] | [✓ CEL][gc-cel] | [✓ VCL][fa-conditions] | [✓ JSON][ak-behaviors] |
| Validated before activation | ✓ | ? | ? | ? | ? | [◐ VCL][fa-services] | ? |
| Config tests block a bad publish | ✓ | [◐ Trace][cf-trace] | ✗ | ✗ | ✗ | [◐ simulator][fa-simulator] | ? |
| Versions and revert | ✓ | [◐ Enterprise][cf-versions] | ✗ | ✗ | ✗ | [✓][fa-services] | [✓][ak-activation] |
| Canary of rule changes | ✓ | [◐ Enterprise][cf-versions] | [◐ up to 15%][aw-staging] | ✗ | ✗ | [◐ not NGWAF][fa-staging] | [✓][ak-activation] |
| Automatic rollback on errors | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | [◐ during rollout][ak-activation] |
| Audit log | ✓ | [✓][cf-audit] | [✓][aw-cloudtrail] | ? | [✓][gc-audit] | [✓][fa-audit] | ? |
| Vendor neutral | ✓ | [◐ Terraform][cf-terraform] | ◐ | [◐ Terraform][az-terraform] | ◐ | [◐ Terraform][fa-terraform] | [◐ Terraform][ak-terraform] |

## Perimeter

The proxy does none of this by design. Keep a vendor in front.

| Capability | Proxy | Cloudflare | AWS | AFD | GCA | Fastly | Akamai |
|---|---|---|---|---|---|---|---|
| OWASP managed rules | ✗ | [◐ from Pro][cf-managed] | [✓][aw-crs] | [◐ Premium][az-drs] | [✓][gc-waf] | [◐ by tier][fa-ngwaf] | [✓][ak-aap] |
| Bot management | ✗ | [◐ by plan][cf-bots] | [◐ paid][aw-bots] | [◐ Premium][az-drs] | [◐][gc-bots] | [◐ add-on][fa-ngwaf] | [◐ add-on][ak-aap] |
| Volumetric DDoS | ✗ | [✓][cf-ddos] | [✓][aw-ddos] | [✓][az-ddos] | [✓][gc-enterprise] | [◐][fa-ddos] | [✓][ak-aap] |
| Client TLS | ✗ | [✓][cf-tls] | [✓][aw-tls] | [✓][az-tiers] | [✓][gc-tls] | [✓][fa-tls] | [✓][ak-tls] |

**Added latency.** Vendors run their rules in the POP the request already reaches. The proxy adds one network hop, plus one pipelined Valkey round trip when a rate-limit rule matches. Its own in-process work on the allow path is about 5 µs (`BenchmarkAllowPath`, no network). On a shared 2 vCPU machine the load tests measured an added p99 of 1.9 to 3.9 ms at 300 RPS.

## Where each side wins

**Vendors:**

- **The perimeter:** OWASP rules, bots, volumetric DDoS, TLS and anycast at global scale.
- **Nothing extra to run:** no hop, no fleet, no Valkey, no admin service or Postgres.
- **Mature change management on some platforms:** Akamai's staging network and phased rollout, Fastly's versioned services.

**The proxy:**

- **Exact, shared quotas.** Every vendor counts per POP, server or region, and AWS, Cloudflare and Google say not to rely on it for precise limits. "5 logins per minute" means exactly 5 here.
- **Limits on verified identity.** Only Cloudflare Enterprise with API Shield does this natively.
- **Explicit failure behaviour:** open, closed or local, chosen per rule.
- **An upstream header contract** that clients can't spoof, without edge code.
- **One policy model across clouds.** Moving CDN means changing the trust preset, not rewriting rules.
- **Tested changes:** a failing config test blocks publish, and the canary and guard roll back degraded policy.

**Both:** basic IP rate limits with penalties and log-only mode, custom error bodies, static CORS headers, simple header edits and path normalization. If your needs stop there, a vendor alone is simpler and cheaper.

## Decision guide

| Your situation | Use |
|---|---|
| Public site, approximate limits are fine, one vendor | Vendor only |
| Exact per-user or per-tenant quotas, or limits on verified identity | Vendor in front, plus this proxy |
| Several clouds or CDNs, or a planned migration | Vendor in front, plus this proxy as the portable policy layer |
| Application teams own policy and need tests, canaries and audit | This proxy |

## Caveats

- **Proxy marks** are backed by the code; the exact-quota claim by `TestSharedQuotaAcrossEdges` against standalone and cluster Valkey.
- **Akamai's** App & API Protector guides need a login, so its marks come from its public API, Terraform and Property Manager references.
- **Fastly's** JWT, CORS, locale, normalization, versions and TLS marks rest on search summaries rather than a full read of the page.
- **Vendor tiers change often.** Recheck them before a purchase decision.

[cf-rl]: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/
[cf-rate]: https://developers.cloudflare.com/waf/rate-limiting-rules/request-rate/
[cf-jwt]: https://developers.cloudflare.com/api-shield/security/jwt-validation/
[cf-actions]: https://developers.cloudflare.com/ruleset-engine/rules-language/actions/
[cf-ddos]: https://developers.cloudflare.com/ddos-protection/
[cf-retry]: https://developers.cloudflare.com/changelog/post/2026-03-12-retry-after-header-for-1xxx-errors/
[cf-cors]: https://developers.cloudflare.com/rules/snippets/examples/define-cors-headers/
[cf-headers]: https://developers.cloudflare.com/rules/transform/request-header-modification/
[cf-lang]: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.accepted_languages/
[cf-errors]: https://developers.cloudflare.com/rules/custom-errors/error-tokens
[cf-normalize]: https://developers.cloudflare.com/rules/normalization/
[cf-lang-ref]: https://developers.cloudflare.com/ruleset-engine/rules-language/
[cf-trace]: https://developers.cloudflare.com/rules/trace-request/
[cf-versions]: https://developers.cloudflare.com/version-management/
[cf-audit]: https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/
[cf-managed]: https://developers.cloudflare.com/waf/managed-rules/
[cf-bots]: https://developers.cloudflare.com/bots/plans/
[cf-tls]: https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/
[aw-rate]: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-high-level-settings.html
[aw-caveats]: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-caveats.html
[aw-keys]: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-aggregation-options.html
[aw-count]: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based-request-limiting.html
[aw-acl]: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html
[aw-ddos]: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-anti-ddos.html
[aw-response]: https://docs.aws.amazon.com/waf/latest/developerguide/customizing-the-response-for-blocked-requests.html
[aw-functions]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/edge-functions-choosing.html
[aw-cors]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/understanding-response-headers-policies.html
[aw-insert]: https://docs.aws.amazon.com/waf/latest/developerguide/customizing-the-incoming-request.html
[aw-origin]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-request-understand-origin-request-policy.html
[aw-transform]: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-transformation.html
[aw-staging]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/continuous-deployment-quotas-considerations.html
[aw-cloudtrail]: https://docs.aws.amazon.com/waf/latest/developerguide/logging-using-cloudtrail.html
[aw-crs]: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
[aw-bots]: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html
[aw-tls]: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html
[az-rate]: https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-rate-limit
[az-rules]: https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-custom-rules
[az-ddos-rules]: https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/http-ddos-ruleset
[az-actions]: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-rules-engine-actions
[az-cors]: https://learn.microsoft.com/en-us/azure/frontdoor/cross-origin-resource-sharing
[az-vars]: https://learn.microsoft.com/en-us/azure/frontdoor/rule-set-server-variables
[az-response]: https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-configure-custom-response-code
[az-drs]: https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs
[az-tiers]: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-cdn-comparison
[az-ddos]: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-ddos
[gc-rate]: https://docs.cloud.google.com/armor/docs/rate-limiting-overview
[gc-enterprise]: https://docs.cloud.google.com/armor/docs/armor-enterprise-overview
[gc-extensions]: https://docs.cloud.google.com/service-extensions/docs/overview
[gc-urlmap]: https://docs.cloud.google.com/compute/docs/reference/rest/v1/urlMaps
[gc-headers]: https://docs.cloud.google.com/load-balancing/docs/https/custom-headers
[gc-errors]: https://docs.cloud.google.com/load-balancing/docs/https/custom-error-response
[gc-urlmap-concepts]: https://docs.cloud.google.com/load-balancing/docs/url-map-concepts
[gc-cel]: https://docs.cloud.google.com/armor/docs/rules-language-reference
[gc-audit]: https://docs.cloud.google.com/armor/docs/audit-logging
[gc-waf]: https://docs.cloud.google.com/armor/docs/waf-rules
[gc-bots]: https://docs.cloud.google.com/armor/docs/bot-management
[gc-tls]: https://docs.cloud.google.com/load-balancing/docs/ssl-certificates
[fa-rate]: https://www.fastly.com/documentation/guides/security/rate-limiting/about-rate-limiting/
[fa-policy]: https://www.fastly.com/documentation/guides/security/rate-limiting/working-with-rate-limiting-policies/
[fa-concepts]: https://www.fastly.com/documentation/guides/concepts/rate-limiting/
[fa-ddos]: https://docs.fastly.com/products/fastly-ddos-protection
[fa-jwt]: https://www.fastly.com/documentation/solutions/tutorials/jwt-edge-compute/
[fa-cors]: https://www.fastly.com/documentation/solutions/examples/cors-options-preflights-at-the-edge/
[fa-headers]: https://www.fastly.com/documentation/guides/full-site-delivery/headers/adding-or-modifying-headers-on-http-requests-and-responses/
[fa-lang]: https://www.fastly.com/documentation/reference/vcl/functions/content-negotiation/accept-language-lookup/
[fa-normalize]: https://www.fastly.com/documentation/reference/vcl/functions/strings/url-normalize/
[fa-conditions]: https://www.fastly.com/documentation/guides/next-gen-waf/rules/defining-rule-conditions/
[fa-services]: https://docs.fastly.com/en/guides/working-with-cdn-services
[fa-simulator]: https://www.fastly.com/documentation/guides/next-gen-waf/rules/testing-rule-logic-with-the-simulator/
[fa-staging]: https://docs.fastly.com/products/staging
[fa-audit]: https://www.fastly.com/documentation/guides/account-info/user-and-account-management/monitoring-account-activity-with-the-audit-log/
[fa-ngwaf]: https://docs.fastly.com/products/fastly-next-gen-waf
[fa-tls]: https://www.fastly.com/documentation/guides/getting-started/domains/securing-domains/setting-up-tls-with-certificates-fastly-manages/
[ak-rate]: https://techdocs.akamai.com/terraform/docs/rate-policy-options
[ak-slowpost]: https://techdocs.akamai.com/application-security/reference/put-policy-slow-post
[ak-deny]: https://techdocs.akamai.com/application-security/reference/deny-name-values
[ak-jwt]: https://techdocs.akamai.com/api-gateway/docs/json-web-token-jwt-val
[ak-cors]: https://techdocs.akamai.com/property-mgr/docs/cors-protocol-support
[ak-headers]: https://techdocs.akamai.com/property-mgr/reference/ga-modify-outgoing-request-header
[ak-response]: https://techdocs.akamai.com/property-mgr/reference/ga-construct-response
[ak-path]: https://techdocs.akamai.com/terraform/docs/path
[ak-behaviors]: https://techdocs.akamai.com/property-mgr/docs/behs
[ak-activation]: https://techdocs.akamai.com/property-mgr/docs/how-activation-works
[ak-aap]: https://techdocs.akamai.com/cloud-security/docs/app-api-protector
[ak-tls]: https://techdocs.akamai.com/cps/llms.txt
[cf-terraform]: https://developers.cloudflare.com/terraform/
[az-terraform]: https://learn.microsoft.com/en-us/azure/frontdoor/create-front-door-terraform
[fa-terraform]: https://www.fastly.com/documentation/guides/integrations/non-fastly-services/developer-guide-terraform/
[ak-terraform]: https://techdocs.akamai.com/terraform/docs/overview
