#!/usr/bin/env bash
# Lints, typechecks and unit tests the autopilot runner, then runs the real
# runner with a scripted adapter against a real admin and Postgres
# (TestAutopilotRunner). Needs Docker for testcontainers.
set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=scripts/ci/node.sh
. scripts/ci/node.sh

(
  cd autopilot
  npm ci
  npx eslint .
  npx tsc
  npm test
)

AUTOPILOT_RUNNER=1 go test -count=1 -run '^TestAutopilotRunner$' ./internal/admin
