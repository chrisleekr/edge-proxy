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
| `http.request.full_uri`, `http.request.uri`, `http.request.uri.path`, `http.request.uri.query` | string | The path is normalized; ambiguous encodings such as `%2F`, and `..` segments, are rejected with 400 before any rule runs |
| `http.request.uri.args["name"]` | list | Query arguments |
| `http.host` | string | Lowercase |
| `http.request.method` | string | Uppercase |
| `http.request.headers["name"]` | list | Header name lowercase |
| `http.request.cookies["name"]` | list | |
| `http.cookie`, `http.referer`, `http.user_agent`, `http.x_forwarded_for` | string | |
| `ip.src` | ip | The trusted client IP |
| `ip.src.country`, `ip.src.continent` | string | Uppercase. Needs a trusted viewer header |
| `ip.src.asnum` | int | Needs a trusted viewer header |
| `ssl`, `client_cert.verified` | bool | Need a trusted viewer header |
| `http.request.version` | string | Needs a trusted viewer header |
| `http.request.jwt.claims["name"]` | list | Verified claims only. Not in the `config` phase |
| `edge.locale` | string | The detected locale. Not in the `config` phase; values must be in the supported list |

A field marked "needs a trusted viewer header" is refused by validation unless the deployment's CDN preset or `VIEWER_HEADERS` provides it.

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

In wildcards, `*` matches any characters; `\*` and `\\` are the only escapes.

## Limits

| Limit | Value |
|---|---|
| Text length | 4000 bytes |
| Conditions | 32 |
| Nesting depth | 8 |
| A literal value | 4096 bytes |
| A regex | 1024 bytes |
