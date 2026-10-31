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
| `http.request.headers["name"]` | list | Header name lowercase |
| `http.request.cookies["name"]` | list | |
| `http.cookie`, `http.referer`, `http.user_agent`, `http.x_forwarded_for` | string | |
| `ip.src` | ip | The trusted client IP |
| `ip.src.country`, `ip.src.continent` | string | Uppercase. Needs a trusted viewer header |
| `ip.src.asnum` | int | Needs a trusted viewer header |
| `ssl`, `client_cert.verified` | bool | Need a trusted viewer header |
| `http.request.version` | string | `1.0`, `1.1`, `2.0` or `3.0` for every source, whatever form the CDN sends (`HTTP/2` becomes `2.0`); any other value is absent. A literal the edge maps the same way, such as `HTTP/2`, matches as that version; any other literal gets a validation warning. Needs a trusted viewer header |
| `tls.client.ja4` | string | The client's [JA4](https://github.com/FoxIO-LLC/ja4) TLS fingerprint, such as `t13d1516h2_8daaf6152771_02713d6af862`. A header value of another shape is absent, and `eq` or `in` with a value of another shape is refused. Matched exactly, letter case included. Needs a trusted viewer header. With an `ssl` source, absent on a request that wasn't HTTPS, since TLS fingerprints exist only for TLS |
| `tls.client.ja3` | string | The client's [JA3](https://github.com/salesforce/ja3) TLS fingerprint, 32 lowercase hex characters, with the same rules as JA4, including absent on a request that wasn't HTTPS. Needs a trusted viewer header |
| `client.signals` | list | Names of the [client signals](#client-signals) the request shows. Only `eq`, `ne`, `in` and `not_in` apply, with signal names as values |
| `client.verified_bot` | bool | True when `ip.src` is in a crawler range admin fetched from `VERIFIED_BOT_SOURCES`. Needs `VERIFIED_BOT_SOURCES` on admin, or validation refuses the rule; false until admin's first fetch succeeds |
| `http.request.jwt.claims["name"]` | list | Verified claims only. Not in the `config` phase |
| `edge.locale` | string | The detected locale. Not in the `config` phase; values must be in the supported list |

A field marked "needs a trusted viewer header" is refused by validation unless the deployment's CDN preset or `VIEWER_HEADERS` provides it.

## Client signals

`client.signals` lists what a request shows of automation, computed by the edge from the request's headers and viewer fields. A signal is a hint, not proof: match it in a rule set to log only first, and combine it with other conditions. [Bot detection](../use/bots.md) has recipes.

| Signal | When | Needs |
|---|---|---|
| `ua_missing` | No `User-Agent`, or an empty one. Then no other signal is set | |
| `ua_tool` | The `User-Agent` names an HTTP library, a command-line tool or a scanner, such as `curl/`, `python-requests/`, `sqlmap` or `nuclei`. Scanners come from the OWASP Core Rule Set's [scanner list](https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data). Only the first 512 bytes are read | |
| `ua_headless` | The `User-Agent` says `HeadlessChrome` or `PhantomJS` | |
| `browser_no_accept_language` | A modern browser without `Accept-Language` | |
| `browser_no_sec_fetch` | A modern browser over HTTPS without `Sec-Fetch-Mode` | `ssl` |
| `chromium_no_client_hints` | Chrome 89 or later over HTTPS without `Sec-CH-UA` | `ssl` |
| `client_hints_mismatch` | A Chromium browser over HTTPS whose `Sec-CH-UA` "Chromium" or "Google Chrome" version differs from its `User-Agent` | `ssl` |
| `browser_http1` | A modern browser over HTTPS with HTTP/1.0 or HTTP/1.1, since browsers negotiate HTTP/2 only over TLS. Never on a WebSocket handshake (`Upgrade: websocket`, `Connection: upgrade` and `Sec-WebSocket-Key`). The handshake headers come from the client, so a client that adds them skips these checks; the exemption exists because browsers open WebSockets over HTTP/1.1. | `ssl`, `http.request.version` |
| `browser_tls_mismatch` | A modern browser whose JA4 is not TLS 1.3, or negotiated neither `h2` nor `h3`. On a WebSocket handshake only the TLS version is checked. The handshake headers come from the client, so a client that adds them skips these checks; the exemption exists because browsers open WebSockets over HTTP/1.1. | `tls.client.ja4` |

A modern browser is one whose `User-Agent` claims a version that sends `Sec-Fetch-Mode`, from [MDN's compatibility data](https://github.com/mdn/browser-compat-data/blob/main/http/headers/Sec-Fetch-Mode.json): Chrome 76 (and Edge, Opera and other Chromium browsers, which report a `Chrome/` version), Firefox 90 and Safari 16.4. Chrome, Firefox and Edge on iOS are never counted, since they send what Safari sends. Browsers send `Sec-Fetch-*` and client hints only over HTTPS, so those signals need an `ssl` source. A signal whose source field isn't configured can never fire, and validation refuses a rule that names it.

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

## Limits

| Limit | Value |
|---|---|
| Text length | 4000 bytes |
| Conditions | 32 |
| Nesting depth | 8 |
| A literal value | 4096 bytes |
| A regex | 1024 bytes |
