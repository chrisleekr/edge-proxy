.PHONY: test lint vuln fuzz bench ui docs docs-serve container load load-full capacity ci infra-up infra-down demo demo-down

# Unit + integration tests, then the 100% edge coverage gate.
test:
	./scripts/ci/test.sh

lint:
	./scripts/ci/lint.sh

vuln:
	./scripts/ci/vuln.sh

# Short fuzz run of every target; FUZZTIME=5m for a longer local run.
fuzz:
	./scripts/ci/fuzz.sh

bench:
	./scripts/ci/bench.sh

# Admin UI: lint, build, and browser smoke tests against a real admin.
ui:
	./scripts/ci/ui.sh

# Strict docs build (broken links and orphan pages fail it).
docs:
	./scripts/ci/docs.sh

docs-serve:
	uv run --locked --group docs mkdocs serve

# Edge, admin and load-test images; the edge must start from a bootstrap.
container:
	./scripts/ci/image.sh

# Tier 1 load smoke with k6 against loadtest/compose.yaml.
load:
	./scripts/ci/load.sh

# Full load profile, nightly and before a release (PROFILE=release).
load-full:
	./scripts/ci/load-full.sh

# Capacity scenario against one edge: p99 against BUDGET_MS, edge CPU,
# Valkey calls and bytes per key at each of STEPS (reported, not gated).
capacity:
	./scripts/capacity-scenario.sh

# Same gates CI runs, in order.
ci: lint test fuzz bench vuln ui docs container load

# Local Valkey and Postgres for manual runs. Tests start their own containers.
infra-up:
	docker compose up -d --wait

infra-down:
	docker compose down -v

# Local demo: admin UI on 127.0.0.1:8081, one edge on 127.0.0.1:8080, seeded
# with a sample policy. Reuses the load-test environment. Docker's port
# forward hides the peer address, so the demo trusts any peer; the port is
# bound to 127.0.0.1. Never do this in a deployment.
demo:
	cd loadtest && export TRUSTED_PROXIES=0.0.0.0/0,::/0 && docker compose -p edge-demo build && docker compose -p edge-demo up -d --wait edge-1 upstream

demo-down:
	cd loadtest && docker compose -p edge-demo down -v
