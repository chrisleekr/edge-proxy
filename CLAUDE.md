# CLAUDE.md

> Engineering charter for Claude Code. Keep it short. The full design lives in `docs/design.md`.

## Project

Edge Proxy is a lightweight Go reverse proxy that sits between a WAF/CDN and the one load balancer or gateway that routes the services (CDN → edge → LB/gateway → services). It enforces policy rules (typed rule expressions, grouped in phases), then forwards every request, Host unchanged, to that single `UPSTREAM_URL`. It never routes. That policy covers:

- distributed rate limiting (Valkey)
- JWT validation
- CORS
- conditional header rules
- locale detection
- templated HTML/JSON responses

An admin service with an admin UI manages policy in Postgres, validates it, publishes versioned snapshots, runs canaries and rolls back degraded publishes. The design is platform-agnostic: nothing in the binaries depends on one cloud provider.

## Architecture principles

**Correctness first.** Before writing code, confirm the design is sound:

- Surface the tradeoffs.
- Name the simplest option that preserves the invariants below.
- Cite authoritative references (official docs, release notes, RFCs, the actual source) for any version or API claim.
- Push back when a request would violate an invariant, and ask before guessing.

**Availability first.** When correctness of enforcement and availability of traffic conflict, availability wins unless a rule explicitly opts into fail-closed.

## Core invariants

- **A running edge never stops serving because a dependency failed.**
  - Valkey, admin, Postgres, the IdP and stats ingest all have a defined degraded mode.
  - `/readyz` reflects only "snapshot loaded and not draining", never dependency health.
- **Config is loaded off the request path.** The request path does one `atomic.Pointer.Load` of the compiled snapshot. There is no I/O, parsing or compilation per request.
- **One validator.** `internal/snapshot.Compile` (validates and compiles in one pass) is the only validation path. Admin runs it on every save and publish, and the edge runs it before activation. No second copy of validation logic anywhere.
- **Nothing invalid is saved, published or activated.** An edge that can't compile a snapshot keeps its current one.
- **Policy is rules in phases** (`config`, `rate_limit`, `request_headers`): expression + action.
  - Expressions are stored as an AST.
  - They are parsed and compiled only by `internal/expr`; there's no second parser, and none in the browser.
  - They are evaluated from compiled closures, with lazily extracted request fields.
- **At most one Valkey round trip per request.** All rate-limit rules matched by a request are pipelined: up to 2 site-wide rules plus 5 others. Every Lua script touches exactly one key, passed in `KEYS`, and reads time with server `TIME`.
- **Rate-limit calls are never retried.** Send plain `EVALSHA` commands (never marked retryable) in one `DoMulti`, with `DisableRetry` set; never `NewLuaScriptRetryable`. A retried call can consume quota twice. Only `NOSCRIPT` → `EVAL` and `MOVED`/`ASK` resend, because the script did not run. (`Lua.ExecMulti` is not used: it runs `SCRIPT LOAD` on every node on every call.)
- **Bounded memory everywhere.** Every in-process map, cache and buffer has a max size and an eviction or overflow rule. Logging and stats drop data rather than block or grow.
- **The request path takes no global locks and allocates as little as possible.**
  - Stats are `atomic` adds.
  - Caches are sharded.
  - Per-IP limiters lock only themselves.
- **Trust comes only from deployment config.**
  - Trusted proxies, the client-IP source, the upstream URL, OIDC providers and secrets come from environment variables, never from admin-editable config.
  - The one exception is JWKS URLs, and every JWKS fetch goes through the SSRF guard in `internal/jwks`.
- **Forwarding headers are set explicitly from trusted values.** Never call `ProxyRequest.SetXForwarded()`: it uses the LB's address and the edge's own TLS state.
- **Every edge-generated response sends `Cache-Control: no-store`.** CORS responses whose allowed origin varies send `Vary: Origin`.
- **Client-supplied copies of edge-managed headers are always stripped.** This covers `X-Edge-*`, the client-IP and geo source headers, and `X-Request-Id` from untrusted peers.
- **Postgres is the durable source of truth** for policy, versions, audit and stats. Valkey holds only rate-limit state, and every Valkey key has a TTL.
- **Authorization checks permissions, never role names.**
- **Audit is complete, append-only and tamper-evident.**
  - Every config, identity, access-control, settings and automated (guard, JWKS) event writes an `audit_events` row in the same transaction as the change.
  - Rows are HMAC-chained, with the key held outside Postgres.
  - The runtime DB role has no `UPDATE`, `DELETE` or `TRUNCATE` on the table, and triggers block them.
  - There is no code path that edits or deletes audit rows, ever.
- **Edge and admin are separate deployables.** The edge scales horizontally and is stateless. Admin is fixed-size, internal-only, and never on the user request path.

## Stack

- **Language:** Go (latest stable). Stdlib first: `net/http`, `httputil.ReverseProxy` with `Rewrite` (never the deprecated `Director`), `log/slog` JSON.
- **Runtime dependencies:** keep them minimal. Adding a dependency to `cmd/edge` needs a stated reason.
  - `valkey-io/valkey-go`
  - `golang-jwt/jwt/v5`
  - `golang.org/x/text`
  - Admin only: `jackc/pgx/v5`, `golang.org/x/crypto`, and later `coreos/go-oidc/v3` and `golang.org/x/oauth2`.
- **Admin UI:** React + Vite + TypeScript (strict) + Tailwind CSS, with `react-querybuilder` for the rule builder and CodeMirror 6 for expression text.
  - It's built to `web/admin/dist/app`, embedded by `web/admin/ui.go` (`go:embed`) and served by admin. Node is needed at build time only.
  - The UI never parses, renders or validates expressions; it calls the admin `/api/expr/*` API.
- **Data:** Postgres (admin) and Valkey (rate-limit state).
- **Tests:** stdlib `testing`, fuzz tests, and `testcontainers-go` for real Valkey and Postgres. Load tests use k6.

## Repo layout

| Path | Responsibility |
| --- | --- |
| `cmd/edge`, `cmd/admin` | Thin `main` packages that call `edge.Main` and `admin.Main` |
| `internal/expr` | Rule expression parser, renderer, type checker, compiler. Shared |
| `internal/snapshot` | Config types, strict decode, `Compile`. Shared by edge and admin |
| `internal/ratelimit` | Algorithms (Lua + local store), backstop |
| `internal/jwks` | JWKS fetch, parse, SSRF guard. Shared |
| `internal/edge` | Wiring, `http.Server`, shutdown, and the request pipeline: client IP, JWT, CORS, header rules, locale, responses, proxy, stats |
| `internal/envparse` | Deployment config from env vars. Shared |
| `internal/admin` | Admin API, identity, sessions, RBAC, publish, snapshot endpoint, stats ingest, JWKS refresh, canary, rollback guard, observed routes (access-log ingest, route patterns, route flow), first-start bootstrap |
| `internal/admindb` | Postgres queries, migrations, audit log |
| `internal/testenv` | Testcontainers helpers and the Playwright browser server. Test tooling, outside edge scope |
| `web/admin` | Admin UI SPA and the Go package that embeds it |
| `loadtest` | k6 scripts; mock upstream, IdP, LB, gateway and microservices; seed (`loadtest/tools`); compose environments |
| `build` | Dockerfiles for the edge, admin and load-test images |
| `scripts` | CI steps (`scripts/ci`) and capacity scripts |
| `docs` | MkDocs site (`mkdocs.yml`): user, operator and developer docs, plus the full design |

## Testing policy

**Edge: 100% statement coverage, enforced in CI.**

- **Scope:** every package except the admin-only list (`cmd/admin`, `internal/admin`, `internal/admindb`, `loadtest`, `web/admin`) and the test tooling in `internal/testenv` (testcontainers helpers), defined in `scripts/ci/test.sh`. This includes the shared `expr`, `snapshot`, `ratelimit` and `jwks` packages.
- **CI fails if `cmd/edge` imports an admin-only or test-tooling package.**
- **Merged from:**
  - unit and integration tests (`-coverpkg=<edge package list>`)
  - end-to-end runs of `cmd/edge` built with `go build -cover` (`GOCOVERDIR`, merged with `go tool covdata`)

**Admin: no coverage gate.** Scenario tests are still required for:
- audit
- auth, sessions, CSRF and permissions
- validation (nothing invalid saved)
- publish, revert, canary and guard
- the snapshot endpoint

The admin UI gets browser smoke tests for the rule builder, publish and revert.

How tests must be written:

- **Scenario-based.** Each test states a real situation and asserts the observable outcome (status, headers, Valkey state, audit row, log line). Never write a test to reach a line. Coverage is the result of covering the scenarios.
- **Valid cases only.** Inputs must be things that can really happen. If a line is reachable only by an impossible input, delete the line or restructure the code so the state can't exist.
- **Straightforward.**
  - Table-driven when cases share a shape.
  - Case names read as behavior ("over limit with penalty stays blocked for 5m").
  - One behavior per case.
  - No clever helpers that hide what is asserted.
- **Real dependencies.** Valkey and Postgres via testcontainers. Mock only what can't run locally (CDN, IdP, upstream), using the shared mock servers in `loadtest/`.
- **Hard-to-reach failures** (e.g. `crypto/rand`) are injected at a narrow boundary (a function variable or small interface) and tested as real scenarios.
- **No coverage exclusion comments or ignore lists** in edge scope.
- **Every bug fix starts with a failing scenario test** that reproduces it.

**Downtime protection.** A panic or a wrong match in the edge is an outage, so code on the request or config-load path also needs:

- **A no-panic fuzz test** for anything that takes admin- or client-supplied input (expressions, snapshots, headers, keys). Anything validation accepts must also compile and run.
- **A differential fuzz test** for every optimized matcher or data structure, comparing it to a slow, obviously correct reference (wildcard vs RE2, IP set vs linear scan).
- **A zero-allocation test** (`testing.AllocsPerRun`) for request-path matchers. It is deterministic, unlike ns/op.
- **Agreement between validation and execution.** Values that can never match are rejected at validation, not discovered in production.
- **Fuzz crashers stay** in `testdata/fuzz` as permanent regression seeds.

## Required commands

- `make test` (`scripts/ci/test.sh`): `go test -race ./...`, then the 100% edge coverage gate and the admin-import check. Integration tests start their own Valkey/Postgres with testcontainers and never target shared or development infrastructure.
- `make lint` (`scripts/ci/lint.sh`): `go vet`, golangci-lint, shellcheck and the citation check (`scripts/ci/citations.sh`). It uses the pinned Docker image if golangci-lint isn't installed.
- `make vuln` (`scripts/ci/vuln.sh`): govulncheck.
- `make fuzz` (`scripts/ci/fuzz.sh`): every fuzz target for `FUZZTIME` (default 20s). Use `FUZZTIME=5m` before merging parser or matcher changes.
- `make bench` (`scripts/ci/bench.sh`): every benchmark, briefly, so they keep compiling and passing.
- `make ui` (`scripts/ci/ui.sh`): admin UI `npm ci`, ESLint, typecheck and build, then the Playwright smoke tests against a real admin and Postgres (`TestUISmoke`, run only with `UI_SMOKE=1`) and the edge's SSE, streamed fetch and WebSocket tests in Chromium, Firefox and WebKit (`TestBrowserStreams`, run only with `BROWSER_SMOKE=1`).
- `make screenshots` (`scripts/ci/screenshots.sh`): renders the admin pages shown in the docs from fixed data in a pinned Playwright browser in Docker and fails when any differs from `docs/assets/screenshots`; `scripts/ci/screenshots.sh update` rewrites them. It runs inside `make ui`.
- `make docs` (`scripts/ci/docs.sh`): strict MkDocs build; broken links, anchors and pages missing from the nav fail it. Docs state only what the code does; check a claim against the code before writing it.
- `make demo` / `make demo-down`: the local demo used by the Get started guide (load-test compose, one edge).
- `make ci`: lint, test, fuzz, bench, vuln, ui, docs, container, load, in CI order.
- `make infra-up` / `infra-down`: local Valkey + Postgres via `compose.yaml`, for manual runs only.
- **CI wiring:** GitHub Actions (`.github/workflows/ci.yml`) and GitLab CI (`.gitlab-ci.yml`) only call `scripts/ci/*.sh`. Change behavior in the scripts, never in provider YAML.
- `make container` (`scripts/ci/image.sh`): build the images; the edge must become ready from a bootstrap snapshot.
- `make load` (`scripts/ci/load.sh`): Tier 1 k6 smoke and a Valkey outage against `loadtest/compose.yaml`.
- `make load-full` (`scripts/ci/load-full.sh`): the full load profile (outages, accuracy, 200 rules, hot key, penalty, JWT and locale, publish and canary under load, over-blocking canary, streams and drain, rolling restart, losing an edge, Valkey cluster). Nightly in CI; `PROFILE=release` before a release.
- `make capacity` (`scripts/capacity-scenario.sh`): one edge at fixed rates with scenario-shaped traffic; reports p99 against `BUDGET_MS`, edge CPU, Valkey calls per request, bytes per key and CPU per call, and with `STREAMS=N` edge memory per open stream (reported, not gated).
- `make capacity-max` (`scripts/capacity-max.sh`): the maximum rate of one 2 vCPU / 2 GiB edge within `BUDGET_MS` added at p99, in front of a mock gateway routing to four mock microservices with network delay (`loadtest/compose.capacity.yaml`). Not a CI gate; run it on a quiet host.
- **Releases:** GitHub only; GitLab CI never cuts a version, it only pushes a rolling amd64-only `latest` from `main` to its own registry. release-please (`release-please-config.json`) from Conventional Commits; `scripts/ci/publish.sh` pushes multi-arch images on a release tag. Dependency updates come from Renovate (`renovate.json`) as `chore` commits, so they never cut a release.

## Quality gates (CI must enforce)

| Gate | What it protects |
| --- | --- |
| `go vet ./...` + `golangci-lint run` | Correctness and style |
| `go test -race ./...` | Unit and integration, against real Valkey (standalone and cluster) and Postgres |
| Edge merged coverage = 100% | Every edge statement is exercised by a scenario (unit + integration + e2e binary) |
| Fuzz smoke (`scripts/ci/fuzz.sh`) | Parsers and matchers on the trust boundary: no panics, agreement with reference implementations |
| `govulncheck ./...` | Known vulnerabilities in dependencies |
| Zero-allocation tests + benchmarks run (`scripts/ci/bench.sh`) | Request-path allocations (gated by tests). ns/op is reported, not gated: shared runners are too noisy |
| k6 smoke (Tier 1) | End-to-end behavior under load, including a Valkey outage. Admin, Postgres and IdP outages run in `make load-full` |
| Container build + smoke | Image starts and becomes ready from a bootstrap snapshot |
| Docs screenshots match the UI (`scripts/ci/screenshots.sh`) | A UI change can't leave the docs showing the old UI |
| Docs reference tables match the code (`TestDocsListEvery*` in `internal/admin/docs_test.go`) | Every env var, admin API route with its permission, and expression field is documented, and nothing documented is gone |

## Writing rules

- Comments are terse and factual. They explain *why*, not *what*.
- No em dashes. No marketing adjectives.
- No architecture decision records or `architecture/` directory. Explain notable decisions in the merge request and update `docs/design.md`.
- Never cite an issue or MR number, an ADR, a design section (`design §4.6`) or a doc path in code, tests, docs or commit messages. State the reason itself. Sections of named standards (`RFC 9110 §15.5.2`) are fine, and docs cross-reference with Markdown links, which `make docs` checks. `scripts/ci/citations.sh` (run by `make lint`) catches ADR numbers, `docs/design` paths, `design §` and bare `§N` citations; issue and MR numbers and other doc paths are left to review.
- A change to behavior, settings, API or UI updates the docs and the screenshots in the same MR.
- Docs are concise and state only current, useful facts. No "checked on" or "updated on" dates and no change history; git records when.
- Link every source where it is used. No separate list of bare URLs.
- Mermaid in `docs/` has no `classDef` or `style`: the Material theme colours diagrams for light and dark, and custom fills make labels unreadable in one of them. Never convey meaning by colour alone.

## Anti-patterns to refuse

- **Request-path dependencies:**
  - Doing I/O, config parsing or compilation on the request path.
  - Making readiness depend on Valkey, admin, Postgres or the IdP.
- **Rate-limit state in Valkey:**
  - A second Valkey round trip per request, or a Lua script that builds key names internally or touches more than one slot.
  - Retrying a quota-consuming Valkey call.
  - Valkey keys without a TTL, or using Valkey for config or durable data.
  - Sliding-window *log* (per-request sorted-set entries) or queueing/delaying requests in the proxy.
- **Trust and spoofing:**
  - Trusting a client-IP or geo header from a peer outside `TRUSTED_PROXIES`.
  - Falling back to `remote_addr` when the client-IP header is missing.
  - Matching on a path with ambiguous encodings (`%5C`, `%00`) instead of rejecting it, or decoding `%2F` to `/` for matching (it stays inside its segment, as the gateway routes it).
  - Rate-limit rules keyed only on attacker-controlled values (header, cookie, query) without an IP or JWT-claim partner rule.
  - Header-based exemptions.
  - Using unverified JWT claims for anything.
  - Matching on the raw path instead of the normalized path.
  - Viewer fields (country, ASN, scheme, HTTP version) from untrusted peers.
  - Moving trusted-proxy, upstream, OIDC-provider or secret settings into admin-editable config.
  - Letting a snapshot overwrite JWKS keys newer than the edge's own.
  - Caching verified tokens without the key generation in the cache key.
  - Serving a bootstrap snapshot older than `BOOTSTRAP_MAX_AGE` without the explicit override.
  - Fetching a user-supplied URL without the SSRF guard.
- **Admin and config handling:**
  - A second validation path, or saving config that hasn't passed `snapshot.Compile`.
  - Expression parsing, formatting or validation in TypeScript.
  - Reverting by rewriting history (a revert is always a new version).
  - Restoring old JWKS keys on revert.
  - Checking role names instead of permissions.
  - Skipping the audit log.
  - Storing passwords with anything but Argon2id, or session IDs unhashed.
  - Any `UPDATE`/`DELETE` on `audit_events`.
  - An audit write outside the transaction of the change it records.
  - A state change with no audit row.
  - Putting the audit HMAC key in Postgres.
  - Putting the admin service on the user request path.
- **Resource use:**
  - Unbounded maps, caches, channels or goroutines.
  - Parsing or compiling expressions, regexes or templates per request.
  - Routing in the edge: per-host or per-rule upstreams, or any upstream besides `UPSTREAM_URL`. The LB or gateway behind the edge routes.
  - Locks or allocations on the request path where an atomic or a precompiled structure works.
- **Tests:**
  - Tests written to hit lines rather than behaviors.
  - Tests with impossible inputs.
  - Coverage exclusions in edge scope.
  - Mocking Valkey or Postgres.
- **Logging and dependencies:**
  - Logging `Authorization`, `Cookie` or query values (key names are fine).
  - Adding a runtime dependency to the edge for something the stdlib or a few dozen lines can do.
