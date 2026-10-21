#!/usr/bin/env bash
# Static checks. golangci-lint runs from its pinned image so no local install is needed.
set -euo pipefail

golangci_image="golangci/golangci-lint:v2.15.0@sha256:fbfcfd12a6f8d7f1b97b3362ca80fc2a244d46863148c73cb88e7793af96c481"

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
