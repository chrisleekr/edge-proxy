# Plain `make` lists the targets.
.DEFAULT_GOAL := help

.PHONY: help test lint vuln fuzz bench ui autopilot screenshots docs docs-serve container load load-full capacity capacity-max ci infra-up infra-down demo demo-autopilot demo-down demo-traffic demo-outage

# Unit + integration tests, then the 100% edge coverage gate.
test:
	./scripts/ci/test.sh

# Go vet, golangci-lint, shellcheck and the citation check.
lint:
	./scripts/ci/lint.sh

# Known vulnerabilities in dependencies (govulncheck).
vuln:
	./scripts/ci/vuln.sh

# Short fuzz run of every target; FUZZTIME=5m for a longer local run.
fuzz:
	./scripts/ci/fuzz.sh

# Every benchmark, briefly, so they keep compiling and passing.
bench:
	./scripts/ci/bench.sh

# Admin UI: lint, build, and browser smoke tests against a real admin.
ui:
	./scripts/ci/ui.sh

# Autopilot runner: lint, typecheck, unit tests, and the real runner against admin.
autopilot:
	./scripts/ci/autopilot.sh

# Docs screenshots match the UI; `./scripts/ci/screenshots.sh update`
# rewrites them after a deliberate UI change. Part of `make ui`.
screenshots:
	./scripts/ci/screenshots.sh

# Strict docs build (broken links and orphan pages fail it).
docs:
	./scripts/ci/docs.sh

# Docs site with live reload.
docs-serve:
	uv run --locked --group docs mkdocs serve

# Edge, admin, runner and load-test images; the edge must start from a bootstrap.
container:
	./scripts/ci/image.sh

# Tier 1 load smoke with k6 against loadtest/compose.yaml.
load:
	./scripts/ci/load.sh

# Full load profile, nightly and before a release (PROFILE=release).
load-full:
	./scripts/ci/load-full.sh

# Capacity scenario against one edge, at each of STEPS (reported, not gated).
# Reports p99 against BUDGET_MS, edge CPU, Valkey calls and bytes per key.
capacity:
	./scripts/capacity-scenario.sh

# Maximum RPS of one 2 vCPU / 2 GiB edge in a cloud-shaped local environment
# (loadtest/compose.capacity.yaml). Needs a Docker VM with at least 8 CPUs.
capacity-max:
	./scripts/capacity-max.sh

# Same gates CI runs, in order.
ci: lint test fuzz bench vuln ui autopilot docs container load

# Local Valkey and Postgres for manual runs. Tests start their own containers.
infra-up:
	docker compose up -d --wait

# Stop the local Valkey and Postgres and delete their data.
infra-down:
	docker compose down -v

# Start the demo: admin UI on 127.0.0.1:8081, edge on 127.0.0.1:8080.
# Sign in as admin / local-dev-login. Seeded with the demo policy
# (loadtest/tools/demo-policy.json): an example of each rule type, template,
# CORS policy, issuer and setting.
# Reuses the load-test environment. Docker's port forward hides the peer
# address, so the demo trusts any peer; the port is bound to 127.0.0.1.
# Never do this in a deployment.
demo:
	cd loadtest && export TRUSTED_PROXIES=0.0.0.0/0,::/0 SEED_POLICY=demo VALKEY_TIMEOUT=$${VALKEY_TIMEOUT:-150ms} && docker compose -p edge-demo build && docker compose -p edge-demo up -d --wait collector edge-1 upstream log-shipper

# Add the autopilot runner to the running demo (needs a model credential).
# Export CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY first, or
# OPENAI_API_KEY with an OpenAI model set on the Autopilot page.
demo-autopilot:
	cd loadtest && docker compose -p edge-demo --profile autopilot up -d --build autopilot

# Send traffic to the running demo until Ctrl+C; watch it on the dashboard.
# It exercises every rule, template, CORS policy and issuer in the demo
# policy (loadtest/k6/demo.js). RATE per second (200), IPS client addresses (300), DURATION
# cap (24h). Not a test: nothing is asserted. make load cannot run beside
# the demo: both use the same fixed subnet.
demo-traffic:
	cd loadtest && export TRUSTED_PROXIES=0.0.0.0/0,::/0 && docker compose -p edge-demo --profile k6 build k6 && \
		docker compose -p edge-demo run --rm --no-deps k6 run --quiet -e RATE=$${RATE:-200} -e IPS=$${IPS:-300} -e DURATION=$${DURATION:-24h} /scripts/demo.js

# Pause the demo's Valkey for OUTAGE seconds (90) while demo-traffic runs,
# so each fail mode shows on the dashboard. Over 60s, because login-per-ip
# (fail_mode closed) answers from its 1m penalty cache until that expires.
demo-outage:
	cd loadtest && docker compose -p edge-demo pause valkey && trap 'docker compose -p edge-demo unpause valkey' EXIT && trap 'exit 130' INT TERM && sleep $${OUTAGE:-90}

# Stop the demo and delete its data; make demo starts it fresh.
demo-down:
	cd loadtest && docker compose -p edge-demo --profile demo --profile autopilot down -v

# This list: each target with the first line of its comment.
help:
	@awk '/^# /{ if (!d) d = substr($$0, 3); next } /^[a-z][a-z-]*:/{ split($$0, t, ":"); printf "  %-14s %s\n", t[1], d } { d = "" }' $(MAKEFILE_LIST)
