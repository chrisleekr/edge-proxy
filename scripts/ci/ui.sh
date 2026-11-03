#!/usr/bin/env bash
# Builds and lints the admin UI, then runs its browser smoke tests against a
# real admin and Postgres, the edge's stream tests in Chromium, Firefox and
# WebKit, and the docs screenshot check. Needs Docker for testcontainers.
set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=scripts/ci/node.sh
. scripts/ci/node.sh

(
  cd web/admin
  npm ci
  npx eslint .
  npm run build
  npx playwright install --with-deps chromium firefox webkit
)

UI_SMOKE=1 go test -count=1 -run '^TestUISmoke$' ./internal/admin
BROWSER_SMOKE=1 go test -count=1 -run '^TestBrowserStreams$' ./internal/edge
./scripts/ci/screenshots.sh
