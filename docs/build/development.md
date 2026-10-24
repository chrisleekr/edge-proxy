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
| `internal/envparse` | Deployment settings from environment variables, shared by edge and admin |
| `internal/tracing` | OpenTelemetry tracer provider, shared by edge and admin: OTLP/HTTP export, capped sampler |
| `internal/admin`, `internal/admindb` | Admin API, identity, canary, guard, audit, Routes from access logs, first-start bootstrap; Postgres and migrations |
| `internal/testenv` | Test tooling: Valkey, Postgres, an OpenTelemetry Collector and the Playwright browser server in Docker |
| `web/admin` | Admin UI (React, Vite, TypeScript), built into `web/admin/dist/app` |
| `loadtest` | k6 scenarios; mock upstream, IdP, LB, gateway and microservices; the demo seed; compose environments |
| `build` | Dockerfiles |
| `scripts/ci` | Every CI step. Both CI providers only call these |
| `scripts` | Capacity scripts |

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
| `make ui` | UI lint, typecheck and build, then browser smoke tests against a real admin, SSE and WebSocket through a real edge in Chromium, Firefox and WebKit, and `make screenshots` |
| `make screenshots` | Renders the admin pages shown in these docs and fails when any differs from `docs/assets/screenshots` (see [Docs and screenshots](#docs-and-screenshots)) |
| `make docs` / `make docs-serve` | Strict docs build / live preview at `http://127.0.0.1:8000/edge-proxy/` |
| `make container` | Build the images; the edge must start from a bootstrap file alone |
| `make load` | k6 smoke and a Valkey outage against the compose environment |
| `make load-full` | The full load profile; `PROFILE=release` before a release |
| `make capacity` | Per-unit costs for sizing: p99, CPU and Valkey cost per request at each rate, memory per stream with `STREAMS=N` ([Capacity planning](../deploy/capacity.md)) |
| `make capacity-max` | One 2 vCPU edge's maximum rate within `BUDGET_MS` added at p99, in front of a mock gateway routing to four mock microservices with network delay ([Capacity planning](../deploy/capacity.md#find-one-edges-maximum)) |
| `make ci` | Everything CI runs, in order |
| `make demo` / `make demo-down` | The local demo from [Get started](../get-started.md) |
| `make demo-traffic` | Steady traffic against the demo until Ctrl+C, covering every part of the demo policy |
| `make demo-outage` | Pause the demo's Valkey for `OUTAGE` seconds (90), to see each fail mode |

## Docs and screenshots

A change to behavior, settings, the API or the UI updates the docs in the same merge request. Two checks fail CI when it doesn't:

- **Reference tables match the code** (`make test`, `internal/admin/docs_test.go`). Every environment variable the edge and admin read is in [Edge settings](../deploy/edge.md) or [Admin settings](../deploy/admin.md), every admin route is in the [API reference](../reference/api.md) with the permission it needs, and every expression field is in [Expressions](../reference/expressions.md). Each check also fails on an entry the code no longer has.
- **Screenshots match the UI** (`make screenshots`, part of `make ui`). `TestDocScreenshots` starts admin with the demo policy, an hour of stats and some access logs, all at a fixed time, and renders each page shown in [Using the dashboard](../use/dashboard.md) in Chromium at 1280x800. It compares every image with `docs/assets/screenshots`; a single changed pixel fails.

After a deliberate UI change, rewrite the images and commit them with the change:

```bash
./scripts/ci/screenshots.sh update
```

The browser runs in the pinned `mcr.microsoft.com/playwright` image for `linux/amd64`, on a Mac too, so an image rendered locally matches CI. Its version must equal `@playwright/test` in `web/admin/package.json`; the test fails until `testenv.PlaywrightVersion` is changed to match. To add a page, add it to `web/admin/docs-shots/screenshots.spec.ts` and, if it needs data, seed it in `internal/admin/docshots_test.go`.

## Testing rules

- Every edge statement is covered by a scenario test; CI fails below 100%. Admin has no gate but needs scenario tests for audit, auth, validation, publish, canary and guard.
- Tests use real Valkey and Postgres, never mocks.
- Code on the request or config-load path also needs a no-panic fuzz test, a differential fuzz test for optimized matchers, and a zero-allocation test.
- Every bug fix starts with a failing test that reproduces it.

## CI

| Provider | Runs |
|---|---|
| GitHub Actions | `ci.yml` on every PR and push to main; `docs.yml` and `docs-deploy.yml` (GitHub Pages); `nightly.yml` for `load-full`; `release-please.yml` |
| GitLab CI | The same `scripts/ci` steps in `.gitlab-ci.yml`; `load-full` on schedules. Versions are released on GitHub only; pushes to `main` publish a rolling, amd64-only `latest` to the GitLab registry |

On both providers a new commit cancels the older run of the same PR, merge request or branch, `main` included; a started GitLab `publish-latest` still finishes. The image build and the load smoke share one `load` job, so compose reuses the images it just built. GitLab caches Go modules and build output per job, and the `ui` job's npm packages and Playwright browsers; GitHub caches them through `setup-go`, `setup-node` and `actions/cache`.

## Release

Releases are cut by [release-please](https://github.com/googleapis/release-please) from [Conventional Commits](https://www.conventionalcommits.org/):

1. Merging to `main` updates a Release PR with the next version and its changelog. `feat` bumps the minor version, `fix` the patch, and `!` or `BREAKING CHANGE` the major.
2. Merging the Release PR tags `v<x.y.z>`, updates `CHANGELOG.md` and creates the GitHub release.
3. The release workflow then runs `scripts/ci/publish.sh`, which pushes `chrisleekr/edge-proxy` and `chrisleekr/edge-proxy-admin` for amd64 and arm64, tagged with the version and `latest`.
4. Once both images are pushed, it sends an `edge-proxy-released` dispatch to [chrisleekr/helm-charts](https://github.com/chrisleekr/helm-charts), which opens a PR that bumps the chart's `appVersion` to the new version.

CI rejects a PR whose title or commits aren't Conventional Commits (`scripts/ci/commits.sh`), since release-please skips subjects it can't parse.

GitHub needs the secrets `RELEASE_TOKEN`, `DOCKER_USERNAME` and `DOCKER_PASSWORD`. `RELEASE_TOKEN` opens the Release PR, so CI runs on it, and sends the chart dispatch, so it also needs Contents write on `chrisleekr/helm-charts` (or the classic `repo` scope). If it lacks that access, the dispatch fails after the images are pushed, and no chart PR opens.

Run `make load-full PROFILE=release` before merging a Release PR.

## Dependencies

[Renovate](https://docs.renovatebot.com/) (`renovate.json`) opens weekly PRs: one for every non-major update (GitHub Actions, Go modules, npm, Python, images in Dockerfiles, compose, GitLab CI and the pins in scripts), one for majors, one for Node, and one refreshing the npm and uv lock files. Updates wait 7 days after release, except images whose registry gives no release date. Dependency bumps use the `chore` type, so they never cut a release on their own.

A Playwright bump fails `make ui` until `testenv.PlaywrightVersion` matches it and the screenshots are rewritten, because a new browser can render differently. A Node bump also changes the tarball checksums in `scripts/ci/ui.sh`, which Renovate can't compute. Its PR fails GitLab's `ui` job (GitHub installs Node with setup-node) until the two hashes are updated from the release's `SHASUMS256.txt`.
