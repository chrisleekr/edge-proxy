#!/usr/bin/env bash
# Known-vulnerability scan of dependencies and the standard library.
set -euo pipefail

if [[ -z "$(go list ./... 2>/dev/null || true)" ]]; then
  echo "no Go packages yet; nothing to scan"
  exit 0
fi

go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
