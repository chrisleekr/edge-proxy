#!/usr/bin/env bash
# Static checks. golangci-lint runs from its pinned image so no local install is needed.
set -euo pipefail

golangci_image="golangci/golangci-lint:v2.14.0@sha256:ad862ba6b3798cbe0fd9fd7408d498fd74fbd2623a92406b2fd3898faf0bf98f"

if [[ -z "$(go list ./... 2>/dev/null || true)" ]]; then
  echo "no Go packages yet; nothing to lint"
  exit 0
fi

"$(dirname "$0")/citations.sh"

go vet ./...

# GitHub runners and dev machines have shellcheck; the GitLab lint image does not.
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck scripts/*.sh scripts/ci/*.sh
else
  echo "shellcheck not installed; shell scripts not checked"
fi

if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run ./...
else
  docker run --rm -v "$(pwd)":/app -w /app "${golangci_image}" golangci-lint run ./...
fi
