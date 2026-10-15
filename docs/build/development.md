# Development

One Go module with two binaries, plus a React admin UI embedded into admin. The rules every change must keep are in [`CLAUDE.md`](https://github.com/chrisleekr/edge-proxy/blob/main/CLAUDE.md); the reasoning behind them is in the [Design](../design.md).

## Layout

| Path | Holds |
|---|---|
| `cmd/edge`, `cmd/admin` | Binaries |
| `internal/expr` | Expression parser, renderer, type checker, compiler |
| `internal/snapshot` | Config types and `Compile`, the single validator used by admin and edges |
| `internal/ratelimit` | Algorithms (Lua and Go twins), Valkey batching, backstop |
| `internal/jwks` | JWKS fetch with SSRF guard |
| `internal/edge` | Request pipeline |
| `internal/admin`, `internal/admindb` | Admin API, identity, canary, guard, audit; Postgres and migrations |
| `web/admin` | Admin UI (React, Vite, TypeScript), built into `web/admin/dist/app` |
| `loadtest` | k6 scenarios, mock upstream, IdP and LB, compose environment |
| `build` | Dockerfiles |
| `scripts/ci` | Every CI step. Both CI providers only call these |

## Prerequisites

Go (version in `go.mod`), Docker, Node 24 for the UI, and [uv](https://docs.astral.sh/uv/) for the docs.

## Commands

| Command | Does |
|---|---|
| `make test` | Unit and integration tests with the race detector against real Valkey and Postgres (testcontainers), then the 100% edge coverage gate. Zero-allocation tests for request-path matchers, and per-request allocation ceilings for allowed, RateLimit-header and 429 requests, run here |
| `make lint` | `go vet`, golangci-lint, shellcheck, and a check that comments and docs don't cite design sections or doc paths |
| `make fuzz` | Every fuzz target (`FUZZTIME=5m` before merging parser or matcher changes) |
| `make bench` | Every benchmark, briefly, so they keep compiling and running |
| `make vuln` | govulncheck |
| `make ui` | UI lint, typecheck and build, then browser smoke tests against a real admin, and SSE and WebSocket through a real edge in Chromium, Firefox and WebKit |
| `make docs` / `make docs-serve` | Strict docs build / live preview at `http://127.0.0.1:8000/edge-proxy/` |
| `make container` | Build the images; the edge must start from a bootstrap file alone |
| `make load` | k6 smoke and a Valkey outage against the compose environment |
| `make load-full` | The full load profile; `PROFILE=release` before a release |
| `make capacity` | Per-unit costs for sizing: p99, CPU and Valkey cost per request at each rate, memory per stream with `STREAMS=N` ([Capacity planning](../deploy/capacity.md)) |
| `make ci` | Everything CI runs, in order |
| `make demo` / `make demo-down` | The local demo from [Get started](../get-started.md) |

Dashboard screenshots in these docs come from `npx playwright test -c playwright.docs.config.ts` in `web/admin`, run against `make demo`.

## Testing rules

- Every edge statement is covered by a scenario test; CI fails below 100%. Admin has no gate but needs scenario tests for audit, auth, validation, publish, canary and guard.
- Tests use real Valkey and Postgres, never mocks.
- Code on the request or config-load path also needs a no-panic fuzz test, a differential fuzz test for optimized matchers, and a zero-allocation test.
- Every bug fix starts with a failing test that reproduces it.

## CI

| Provider | Runs |
|---|---|
| GitHub Actions | `ci.yml` on every PR and push to main; `docs.yml` and `docs-deploy.yml` (GitHub Pages); `nightly.yml` for `load-full`; `release-please.yml` |
| GitLab CI | The same `scripts/ci` steps in `.gitlab-ci.yml`; `load-full` on schedules. Versions are released on GitHub only; pushes to `main` publish `latest` to the GitLab registry |

## Release

Releases are cut by [release-please](https://github.com/googleapis/release-please) from [Conventional Commits](https://www.conventionalcommits.org/):

1. Merging to `main` updates a Release PR with the next version and its changelog. `feat` bumps the minor version, `fix` the patch, and `!` or `BREAKING CHANGE` the major.
2. Merging the Release PR tags `v<x.y.z>`, updates `CHANGELOG.md` and creates the GitHub release.
3. The release workflow then runs `scripts/ci/publish.sh`, which pushes `chrisleekr/edge-proxy` and `chrisleekr/edge-proxy-admin` for amd64 and arm64, tagged with the version and `latest`.

CI rejects a PR whose title or commits aren't Conventional Commits (`scripts/ci/commits.sh`), since release-please skips subjects it can't parse.

GitHub needs the secrets `RELEASE_TOKEN` (a token that can open PRs, so CI runs on the Release PR), `DOCKER_USERNAME` and `DOCKER_PASSWORD`.

Run `make load-full PROFILE=release` before merging a Release PR.

## Dependencies

[Renovate](https://docs.renovatebot.com/) (`renovate.json`) opens weekly PRs: one for every non-major update (GitHub Actions, Go modules, npm, Python, images in Dockerfiles, compose, GitLab CI and the pins in scripts), one for majors, one for Node, and one refreshing the npm and uv lock files. Updates wait 7 days after release, except images whose registry gives no release date. Dependency bumps use the `chore` type, so they never cut a release on their own.

A Node bump also changes the tarball checksums in `scripts/ci/ui.sh`, which Renovate can't compute. Its PR fails GitLab's `ui` job (GitHub installs Node with setup-node) until the two hashes are updated from the release's `SHASUMS256.txt`.
