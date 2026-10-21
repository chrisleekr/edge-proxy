#!/usr/bin/env bash
# Docs screenshot gate: renders the pages shown in the docs from fixed data
# in a pinned browser and fails when any differs from docs/assets/screenshots.
# After a deliberate UI change, run with "update" and commit the images.
# Needs Docker and web/admin's npm packages (npm ci).
set -euo pipefail
cd "$(dirname "$0")/../.."

(cd web/admin && npm run build)

mode=1
if [ "${1:-}" = update ]; then
  mode=update
fi
DOC_SCREENSHOTS="$mode" go test -count=1 -timeout 15m -run '^TestDocScreenshots$' ./internal/admin
