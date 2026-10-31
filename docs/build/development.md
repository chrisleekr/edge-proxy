# Development

One Go module with two binaries, plus a React admin UI embedded into admin, and the autopilot runner in TypeScript. The rules every change must keep are in [`CLAUDE.md`](https://github.com/chrisleekr/edge-proxy/blob/main/CLAUDE.md); the reasoning behind them is in the [Design](../design.md).

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
| `internal/admin`, `internal/admindb` | Admin API, identity, canary, guard, audit, Routes from access logs, autopilot and its read-only Prometheus, Grafana and Datadog connectors, first-start bootstrap; Postgres and migrations |
| `internal/testenv` | Test tooling: Valkey, Postgres, an OpenTelemetry Collector, Prometheus, Grafana and the Playwright browser server in Docker |
| `web/admin` | Admin UI (React, Vite, TypeScript), built into `web/admin/dist/app` |
| `autopilot` | [Autopilot runner](../deploy/autopilot.md) (TypeScript on Node): `src` is the image and `src/replay.ts` the [replay](#replay-and-golden-cases) command; `test` holds its unit tests, the scripted adapter that `TestAutopilotRunner` runs in place of a model, and the golden cases in `test/golden` |
| `loadtest` | k6 scenarios; mock upstream, IdP, LB, gateway and microservices; the demo seed; the scripted autopilot agent; compose environments |
| `build` | Dockerfiles |
| `scripts/ci` | Every CI step. Both CI providers only call these |
| `scripts` | Capacity scripts |

## Prerequisites

Go (version in `go.mod`), Docker, Node 26 for the UI and the autopilot runner, and [uv](https://docs.astral.sh/uv/) for the docs.

## Commands

| Command | Does |
|---|---|
| `make test` | Unit and integration tests with the race detector against real Valkey and Postgres (testcontainers), then the 100% edge coverage gate. Zero-allocation tests for request-path matchers, and per-request allocation ceilings for allowed, RateLimit-header and 429 requests, run here |
| `make lint` | `go vet`, golangci-lint, shellcheck, and a check that comments and docs don't cite design sections or doc paths |
| `make fuzz` | Every fuzz target (`FUZZTIME=5m` before merging parser or matcher changes) |
| `make bench` | Every benchmark, briefly, so they keep compiling and running |
| `make vuln` | govulncheck |
| `make ui` | UI lint, typecheck and build, then browser smoke tests against a real admin, SSE and WebSocket through a real edge in Chromium, Firefox and WebKit, and `make screenshots` |
| `make autopilot` | Runner lint, typecheck and unit tests, then `TestAutopilotRunner`: the real runner, with a scripted adapter in place of a model, against a real admin and Postgres. It covers a case closing with a proposal, a claim refused for a missing credential, a run timing out, an answer without a verdict, two cases running at once with `AUTOPILOT_CONCURRENCY=2`, a lapsed lease and SIGTERM |
| `make screenshots` | Renders the admin pages shown in these docs and fails when any differs from `docs/assets/screenshots` (see [Docs and screenshots](#docs-and-screenshots)) |
| `make docs` / `make docs-serve` | Strict docs build / live preview at `http://127.0.0.1:8000/edge-proxy/` |
| `make container` | Build the images; the edge must start from a bootstrap file alone, and the runner must refuse to start without its settings on a read-only root |
| `make load` | k6 smoke and a Valkey outage against the compose environment |
| `make load-full` | The full load profile, including [five attacks](#autopilot-load-test) the autopilot must block; `PROFILE=release` before a release. `ONLY=<regex>` runs the steps whose names match |
| `make capacity` | Per-unit costs for sizing: p99, CPU and Valkey cost per request at each rate, memory per stream with `STREAMS=N`, and with `SENSORS=N` the same figures with N log-only rules shaped like the autopilot's sensors ([Capacity planning](../deploy/capacity.md)) |
| `make capacity-max` | One 2 vCPU edge's maximum rate within `BUDGET_MS` added at p99, in front of a mock gateway routing to four mock microservices with network delay ([Capacity planning](../deploy/capacity.md#find-one-edges-maximum)) |
| `make ci` | Everything CI runs, in order |
| `make demo` / `make demo-down` | The local demo from [Get started](../get-started.md) |
| `make demo-autopilot` | Add the autopilot runner to the running demo, with the model credential exported in your shell |
| `make demo-traffic` | Steady traffic against the demo until Ctrl+C, covering every part of the demo policy |
| `make demo-outage` | Pause the demo's Valkey for `OUTAGE` seconds (90), to see each fail mode |

## Replay and golden cases

Replay runs a recorded autopilot case against a model, from the `autopilot` directory, with the provider's credential in the same variables as the [runner](../deploy/autopilot.md):

```bash
npm run replay -- <case> [--run N] --admin URL --token-file F [--provider P --model M] [--prompt FILE] [--save FILE | --file FILE] [--max-turns N]
```

- `--admin` and `--token-file` read the case and `GET /api/autopilot/contract` from admin. The token needs `autopilot.read`, `stats.read` and `config.read`, and `autopilot.manage` for a run with connector calls, or admin hides the recorded answers and replay stops, naming what the token lacks. It replays the case's run, or run `N` with `--run`.
- `--save FILE` writes the case, its run, its calls and the contract less the prompt as a bundle, and runs no model. A bundle holds client IPs and stats, so the file is readable only by its owner, including one that already existed. `--file FILE` replays a saved bundle without admin, and takes no `--admin`, `--save` or `--run`.
- `--provider` (`claude` or `openai`) and `--model` default to the recorded run's. `--prompt` replaces the current `internal/admin/autopilot_prompt.md`. `--max-turns` is 1 to 100, default 30.

The model gets only the run's recorded answers, from an MCP server on 127.0.0.1 that answers only requests with a token made for this replay and its own `Host`; a call the run didn't make is an error the model sees. It prints a JSON report: `recorded` and `replay` (provider, model, verdict, tokens and cost), and `differences` (`verdict`, `prompt_changed`, `tools_changed`, `unrecorded_calls` and `recorded_calls_not_made`). See [Replay and evaluation](../use/autopilot.md#replay-and-evaluation).

**Golden cases** are bundles saved from the [load test](#autopilot-load-test)'s five attacks, in `autopilot/test/golden`, each with the verdict a model should reach in `expect`. `npm test` only checks that each loads and names a verdict. `AUTOPILOT_LIVE=1 node --test test/golden.test.ts` replays each against the real provider and fails on a different verdict, reporting its tokens and time. It spends tokens, so it runs only by hand, never in CI.

## Autopilot load test

`ONLY='Autopilot' make load-full` runs only the step "Autopilot: five attacks". It starts `agent`, a scripted runner (`tools agent`, compose profile `autopilot-load`) that claims cases from admin and answers them from a fixed plan over admin's MCP, so the edge, admin's checks and the rule lifecycle run for real with no model:

```bash
tools agent -admin URL -token-file F [-plan FILE] [-concurrency 1..4]
```

On a sweep it proposes each plan sensor not yet live. On an anomaly of a plan sensor it reads the case, the autopilot state, the sensor's stats and the rules, checks each top subject that is an IP, then proposes the plan's enforce rule citing the sensor and the stats read as evidence, after a `first_try` rule admin should refuse where the plan has one. It answers any other case benign. `-plan` replaces the embedded `loadtest/tools/autopilot-plan.json`; `-concurrency` (default 4) is how many cases it answers at once.

`loadtest/k6/full/autopilot.js` publishes a policy with no rate-limit rules, puts autopilot in `auto` mode with short timings, waits for the five sensors, then runs background traffic and five 8 minute attacks: walking order IDs, scraping a catalog with one JWT over many IPs, credential stuffing, a path scanner, and an attack from one AS among legitimate clients, where a key on the AS alone must be refused. For each attack a case must open within 180 seconds, its rule must enforce within 180 seconds of the case, at least half the attack's requests must then get 429, legitimate requests must get under `MAX_BLOCK_SHARE` 429s, and the rule must expire once the attack stops. It takes about 25 minutes, since an enforcing rule renews while it blocked in the last 10 minutes and then runs out its 5 minute TTL. The k6 variables `MAX_BLOCK_SHARE` (default 0.05) and `BACKGROUND_RPS` (default 800) set the collateral threshold and the background rate; `load-full.sh` uses the defaults.

## Docs and screenshots

A change to behavior, settings, the API or the UI updates the docs in the same merge request. Two checks fail CI when it doesn't:

- **Reference tables match the code** (`make test`, `internal/admin/docs_test.go`). Every environment variable the edge, admin and runner read is in [Edge settings](../deploy/edge.md), [Admin settings](../deploy/admin.md) or [Autopilot runner](../deploy/autopilot.md), every admin route is in the [API reference](../reference/api.md) with the permission it needs, and every expression field is in [Expressions](../reference/expressions.md). Each check also fails on an entry the code no longer has.
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

On both providers a new commit cancels the older run of the same PR, merge request or branch, `main` included; a started GitLab `publish-latest` still finishes. The image build and the load smoke share one `load` job, so compose reuses the images it just built. GitLab caches Go modules and build output per job, and the `ui` and `autopilot` jobs' npm packages and `ui`'s Playwright browsers; GitHub caches them through `setup-go`, `setup-node` and `actions/cache`.

## Release

Releases are cut by [release-please](https://github.com/googleapis/release-please) from [Conventional Commits](https://www.conventionalcommits.org/):

1. Merging to `main` updates a Release PR with the next version and its changelog. `feat` bumps the minor version, `fix` the patch, and `!` or `BREAKING CHANGE` the major.
2. Merging the Release PR tags `v<x.y.z>`, updates `CHANGELOG.md` and creates the GitHub release.
3. The release workflow then runs `scripts/ci/publish.sh`, which pushes `chrisleekr/edge-proxy`, `chrisleekr/edge-proxy-admin` and `chrisleekr/edge-proxy-autopilot` for amd64 and arm64, tagged with the version and `latest`. release-please also writes the version into `autopilot/package.json` and its lock file, which the runner reports to admin.
4. Once every image is pushed, it sends an `edge-proxy-released` dispatch to [chrisleekr/helm-charts](https://github.com/chrisleekr/helm-charts), which opens a PR that bumps the chart's `appVersion` to the new version.

CI rejects a PR whose title or commits aren't Conventional Commits (`scripts/ci/commits.sh`), since release-please skips subjects it can't parse.

GitHub needs the secrets `RELEASE_TOKEN`, `DOCKER_USERNAME` and `DOCKER_PASSWORD`. `RELEASE_TOKEN` opens the Release PR, so CI runs on it, and sends the chart dispatch, so it also needs Contents write on `chrisleekr/helm-charts` (or the classic `repo` scope). If it lacks that access, the dispatch fails after the images are pushed, and no chart PR opens.

Run `make load-full PROFILE=release` before merging a Release PR.

## Dependencies

[Renovate](https://docs.renovatebot.com/) (`renovate.json`) opens weekly PRs: one for every non-major update (GitHub Actions, Go modules, npm, Python, images in Dockerfiles, compose, GitLab CI and the pins in scripts), one for majors, one for Node, and one refreshing the npm and uv lock files. Updates wait 7 days after release, except images whose registry gives no release date. Dependency bumps use the `chore` type, so they never cut a release on their own.

A Playwright bump fails `make ui` until `testenv.PlaywrightVersion` matches it and the screenshots are rewritten, because a new browser can render differently. A Node bump also changes the tarball checksums in `scripts/ci/node.sh`, which Renovate can't compute. Its PR fails GitLab's `ui` and `autopilot` jobs (GitHub installs Node with setup-node) until the two hashes are updated from the release's `SHASUMS256.txt`.
