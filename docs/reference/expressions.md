# Expressions

An expression decides which requests a rule matches. The UI's rule builder and the text form are two views of the same stored tree; admin converts between them.

## Syntax

```text
starts_with(http.request.uri.path, "/api/") and http.request.method in {"POST" "PUT"}
ip.src in {"10.0.0.0/8" 2001:db8::/32}
ssl and (http.host eq "a.example.com" or http.host eq "b.example.com")
http.request.headers["x-tenant"] eq "acme"
not http.request.jwt.claims["role"] in {"admin" "staff"}
true
```

| Element | Form |
|---|---|
| Combine | `and` binds tighter than `or`; `not`; parentheses |
| Compare | `field operator value` |
| Functions | `starts_with(field, "v")`, `ends_with(field, "v")` |
| Keyed fields | `field["key"]`, key quoted |
| Strings | `"..."`, escapes `\"` and `\\` only. Bare words work for simple values |
| Lists | `{a "b c" d}`, space-separated |
| Value lists | `$name`, a [value list](#value-lists) in place of a value or a list. A quoted `"$name"` is a literal |
| Booleans | `ssl` alone means true; `not ssl` means false |
| Match all | `true` |

## Fields

| Field | Type | Notes |
|---|---|---|
| `http.request.uri.path`, `http.request.uri.query` | string | The path is normalized; ambiguous encodings such as `%5C`, and `..` segments, are rejected with 400 before any rule runs. `%2F` stays encoded inside its segment, so match `group%2Fproject`; `%2F` hiding a `.` or `..` part (`..%2Fadmin`) is rejected. A path always starts with `/`, so `eq "search"` is rejected: use `eq "/search"`. The query is not decoded: match query values on `http.request.uri.args` |
| `http.request.full_uri`, `http.request.uri` | string | Not normalized: the path usually keeps the client's percent-encoding, so `/%61dmin` does not match `"/admin"`. `full_uri` is `https://` when `ssl` is true, otherwise `http://`, then `http.host` (an IPv6 address in square brackets), then `http.request.uri`. A rule using them gets a warning; match on `http.request.uri.path` or `http.request.uri.args` |
| `http.request.uri.args["name"]` | list | Query arguments. Names and values are percent-decoded once, and `+` is a space. The name matches exactly, case included: `args["debug"]` does not match `?DEBUG=1`, which an upstream that ignores name case still reads. Pairs containing `;` or a malformed `%` escape are skipped, and are also dropped from the forwarded query |
| `http.host` | string | Lowercase |
| `http.request.method` | string | Uppercase |
| `http.request.headers["name"]` | list | Header name lowercase. A header in [`CDN_HEADERS`](../deploy/edge.md#cdn-headers) that the policy trusts (`global.cdn_trusted_headers`, or the deployment's default while it is unset) is the CDN's value, so a condition that excludes traffic on it gets no client-controlled warning; on any other a client can send the header itself. A source header can't be read; use its typed field |
| `http.request.cookies["name"]` | list | |
| `http.cookie`, `http.referer`, `http.user_agent`, `http.x_forwarded_for` | string | |
| `ip.src` | ip | The trusted client IP |
| `ip.src.country`, `ip.src.continent` | string | Uppercase. Needs a trusted viewer header |
| `ip.src.asnum` | int | Needs a trusted viewer header |
| `ssl`, `client_cert.verified` | bool | Need a trusted viewer header |
| `http.request.version` | string | `1.0`, `1.1`, `2.0` or `3.0` for every source, whatever form the CDN sends (`HTTP/2` becomes `2.0`); any other value is absent. A literal the edge maps the same way, such as `HTTP/2`, matches as that version with any operator; any other literal, or a pattern such as `HTTP/1` that names `HTTP`, gets a validation warning. Needs a trusted viewer header |
| `tls.client.ja4` | string | The client's [JA4](https://github.com/FoxIO-LLC/ja4) TLS fingerprint, such as `t13d1516h2_8daaf6152771_02713d6af862`. A header value of another shape is absent, and `eq` or `in` with a value of another shape is refused. Matched exactly, letter case included. Needs a trusted viewer header. With an `ssl` source, absent on a request that wasn't HTTPS, since TLS fingerprints exist only for TLS |
| `tls.client.ja3` | string | The client's [JA3](https://github.com/salesforce/ja3) TLS fingerprint, 32 lowercase hex characters, with the same rules as JA4, including absent on a request that wasn't HTTPS. Needs a trusted viewer header |
| `client.signals` | list | Names of the [client signals](#client-signals) the request shows. Only `eq`, `ne`, `in` and `not_in` apply, with signal names as values |
| `client.verified_bot` | bool | True when `ip.src` is in a crawler range admin fetched from `VERIFIED_BOT_SOURCES`. Needs `VERIFIED_BOT_SOURCES` on admin, or validation refuses the rule; false until admin's first fetch succeeds |
| `client.ip_lists` | list | Names of the [IP lists](../use/bots.md#ip-lists) that hold `ip.src`, from the lists admin serves to edges. Only `eq`, `ne`, `in` and `not_in` apply, with list names as values: 1 to 63 lowercase letters, digits and hyphens, not starting with a hyphen. A name is checked for its form only, since which lists exist is admin state, not config, so the editor warns about a name that matches no one. Empty until the edge's first poll after it starts, as `client.verified_bot` is false until admin's first fetch |
| `client.denylisted` | bool | True when any [IP list](../use/bots.md#ip-lists) that is on holds `ip.src`, provider, crawler and monitor lists included. Kept for policies written before `client.ip_lists`; saving warns on a rule that reads it. Use `client.ip_lists` |
| `http.request.jwt.claims["name"]` | list | Verified claims only. Not in the `config` phase |
| `edge.locale` | string | The detected locale. Not in the `config` phase; values must be in the supported list |

A field marked "needs a trusted viewer header" is refused by validation unless the deployment's CDN preset or `VIEWER_HEADERS` provides it.

## Client signals

`client.signals` lists what a request shows of automation, computed by the edge from the request's headers, viewer fields and the CDN headers that are in `CDN_HEADERS` and trusted. A signal is a hint, not proof: match it in a rule set to log only first, and combine it with other conditions. [Bot detection](../use/bots.md) has recipes.

| Signal | When | Needs |
|---|---|---|
| `ua_missing` | No `User-Agent`, or an empty one. Then no `User-Agent` signal is set; `cdn_likely_automated` and `cdn_tor` still can be | |
| `ua_tool` | The `User-Agent` names an HTTP library, a command-line tool or a scanner, such as `curl/`, `python-requests/`, `sqlmap` or `nuclei`. Scanners come from the OWASP Core Rule Set's [scanner list](https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data). Only the first 512 bytes are read | |
| `ua_headless` | The `User-Agent` says `HeadlessChrome`, `PhantomJS` or `Lightpanda` (its default is `Lightpanda/1.0`) | |
| `browser_no_accept_language` | A modern browser without `Accept-Language` | |
| `browser_no_sec_fetch` | A modern browser over HTTPS without `Sec-Fetch-Mode` | `ssl` |
| `chromium_no_client_hints` | Chrome 89 or later over HTTPS without `Sec-CH-UA` | `ssl` |
| `client_hints_mismatch` | A Chromium browser over HTTPS whose `Sec-CH-UA` "Chromium" or "Google Chrome" version differs from its `User-Agent`; or a modern Firefox or Safari `User-Agent` that sends any `Sec-CH-UA`, since only Chromium sends it. The Firefox and Safari case doesn't read `ssl`, but a rule naming the signal still needs an `ssl` source | `ssl` |
| `browser_http1` | A modern browser over HTTPS with HTTP/1.0 or HTTP/1.1, since browsers negotiate HTTP/2 only over TLS. Never on a WebSocket handshake (`Upgrade: websocket`, `Connection: upgrade` and `Sec-WebSocket-Key`). The handshake headers come from the client, so a client that adds them skips these checks; the exemption exists because browsers open WebSockets over HTTP/1.1. | `ssl`, `http.request.version` |
| `browser_tls_mismatch` | A modern browser whose JA4 is not TLS 1.3, or negotiated neither `h2` nor `h3`. On a WebSocket handshake only the TLS version is checked. The handshake headers come from the client, so a client that adds them skips these checks; the exemption exists because browsers open WebSockets over HTTP/1.1. | `tls.client.ja4` |
| `browser_outdated` | A Chrome (or other Chromium) or Firefox `User-Agent` whose major version is below `global.browser_floor` for that browser, including versions too old to count as modern. Safari has no floor. Validation refuses a rule naming it while no floor is set | `global.browser_floor` |
| `cdn_likely_automated` | `Cf-Bot-Score` is 1 to 29 and `Cf-Verified-Bot` is not `true`, whatever the `User-Agent` says. Cloudflare scores 1 as automated and 2 to 29 as [likely automated](https://developers.cloudflare.com/bots/concepts/bot-score/). Cloudflare sends both headers only with Enterprise Bot Management: without it the signal is accepted but never fires | `cf-bot-score` and `cf-verified-bot` trusted |
| `crawler_impersonated` | The `User-Agent` names `googlebot`, `bingbot`, `applebot`, `duckduckbot`, `yandexbot` or `baiduspider` and `Cf-Verified-Bot` is `false`, so Cloudflare did not verify the crawler. A request without `Cf-Verified-Bot` never sets it, so it needs Bot Management to ever fire. Known false positive: a real crawler on an address Cloudflare doesn't yet verify | `cf-verified-bot` trusted |
| `cdn_tor` | `ip.src.country` is `T1`, the code Cloudflare uses for Tor. Set only when `cf-ipcountry` is listed in `CDN_HEADERS` and is the `ip.src.country` header, as on the `cloudflare` preset; a listed source header is always trusted. A fact about the address, not a verdict on the client. `T1` is not an ISO 3166 country code | `cf-ipcountry` listed and the `ip.src.country` header |
| `browser_tls_old` | A modern browser whose `CloudFront-Viewer-TLS` doesn't start with `TLSv1.3:`, since modern browsers negotiate TLS 1.3 and [CloudFront offers it](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html). Not set on a request the CDN saw as plain HTTP when `ssl` is mapped, like the TLS fingerprints. Known false positive: a corporate TLS-inspecting proxy that only speaks TLS 1.2 | `cloudfront-viewer-tls` trusted |

A modern browser is one whose `User-Agent` claims a version that sends `Sec-Fetch-Mode`, from [MDN's compatibility data](https://github.com/mdn/browser-compat-data/blob/main/http/headers/Sec-Fetch-Mode.json): Chrome 76 (and Edge, Opera and other Chromium browsers, which report a `Chrome/` version), Firefox 90 and Safari 16.4. Chrome, Firefox and Edge on iOS are never counted, since they send what Safari sends. Browsers send `Sec-Fetch-*` and client hints only over HTTPS, so those signals need an `ssl` source. A signal whose source field isn't configured or whose CDN header isn't [trusted](../deploy/edge.md#cdn-headers), or `browser_outdated` without a floor, can never fire, and validation refuses a rule that names it. A config naming any of the four CDN signals needs schema 8 edges: admin waits for them.

## Operators

| Operator | Types | Text form |
|---|---|---|
| `eq`, `ne` | string, ip, int | `eq`, `ne` |
| `contains`, `starts_with`, `ends_with` | string | `contains`, functions |
| `wildcard`, `strict_wildcard` | string | `wildcard "*.example.com"` (ASCII case-insensitive), `strict wildcard` (case-sensitive) |
| `in`, `not_in` | string, ip (CIDRs allowed), int | `in {...}`, `not ... in {...}` |
| `gt`, `ge`, `lt`, `le` | int | |
| `matches` | string | RE2 regex. Only when the deployment sets `ALLOW_REGEX=true` |
| `is_true`, `is_false` | bool | bare field, `not field` |

`not_contains`, `not_starts_with`, `not_ends_with` and `not_in` are written with a leading `not`, for example `not http.host contains "x"`.

On a list field (headers, cookies, query args, claims), a condition matches if **any** value matches. A negated condition means **no** value matches.

In wildcards, `*` matches any characters and the pattern must match the whole value. `\*` and `\\` are the only escapes, and `**` is rejected as a likely typo. `wildcard` folds case for ASCII letters only; other letters must match exactly.

## Value lists

A value list is a named set of values for one field, kept in the policy at `global.lists` and managed on the **Value lists** page: it lists each value list with the rules that use it, **New value list** adds one, and a value list's own page edits its name, field and values. Renaming a value list changes `$name` in every rule that uses it, in the same draft edit. A condition names it with `$name` where a value or a list would go:

```text
http.user_agent contains $bad-agents
ip.src.country in $eu-only
not starts_with(http.request.uri.path, $public-paths)
```

`in $name` matches when the field equals any value of the value list, as `in {...}` does. A pattern operator (`contains`, `starts_with`, `ends_with`, `wildcard`, `strict_wildcard`, `matches`) matches when any value matches, and its negated form when none does. A value list belongs to one field and is used only with that field, and its values are checked as that field's when the policy is saved and again where a rule uses it, with that rule's operator: a URL paths value list holding `.php` works with `ends_with` and is refused with `in`, since a path starts with `/`.

| Value list kind | Field | Operators |
|---|---|---|
| User agents | `http.user_agent` | `in` and the pattern operators |
| URL paths | `http.request.uri.path` | `in` and the pattern operators |
| Hostnames | `http.host` | `in` and the pattern operators |
| Referers | `http.referer` | `in` and the pattern operators |
| Header values | `http.request.headers` | `in` and the pattern operators |
| Cookie values | `http.request.cookies` | `in` and the pattern operators |
| Query values | `http.request.uri.args` | `in` and the pattern operators |
| JWT claim values | `http.request.jwt.claims` | `in` and the pattern operators |
| Countries | `ip.src.country` | `in`, `not_in` |
| Continents | `ip.src.continent` | `in`, `not_in` |
| AS numbers | `ip.src.asnum` | `in`, `not_in` |
| JA4 fingerprints | `tls.client.ja4` | `in`, `not_in` |
| JA3 fingerprints | `tls.client.ja3` | `in`, `not_in` |

Addresses go in an [IP list](../use/bots.md#ip-lists), read through `client.ip_lists`, not in a value list. A value list is part of the policy, so a change takes effect when you publish, and it needs schema 13 edges. A value list no rule uses is warned about, and removing one a rule still uses is refused at that rule.

## Limits

| Limit | Value |
|---|---|
| Text length | 4000 bytes |
| Conditions | 32. With a pattern operator, each value of a value list counts as one; `in $name` counts once |
| Nesting depth | 8 |
| A literal value | 4096 bytes |
| A regex | 1024 bytes |
| Value lists | 100, each of 1 to 10,000 values |
| Value list values across every use | 200,000, since each use is compiled on its own |
