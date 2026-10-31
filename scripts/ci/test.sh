#!/usr/bin/env bash
# Runs every test with the race detector and enforces 100% statement coverage
# on edge scope: every package in this module except the admin-only ones.
# Admin-only packages are tested but not gated.
set -euo pipefail

mod="$(go list -m)"
# Packages outside edge scope: admin-only code, and test tooling that starts
# containers and mock servers. The edge must never import any of them;
# checked below.
admin_only="^${mod}/(cmd/admin|internal/admin|internal/admindb|internal/testenv|loadtest|web/admin)(/|$)"

all_pkgs="$(go list ./... 2>/dev/null || true)"
if [[ -z "${all_pkgs}" ]]; then
  echo "no Go packages yet; nothing to test"
  exit 0
fi

go test -race -count=1 -timeout 20m ./...

if [[ -d cmd/edge ]]; then
  leaked="$(go list -deps ./cmd/edge | grep "^${mod}/" | grep -E "${admin_only}" || true)"
  if [[ -n "${leaked}" ]]; then
    echo "edge imports admin-only packages:" >&2
    echo "${leaked}" >&2
    exit 1
  fi
fi

edge_pkgs="$(echo "${all_pkgs}" | grep -Ev "${admin_only}" || true)"
if [[ -z "${edge_pkgs}" ]]; then
  echo "no edge-scope packages yet; coverage gate skipped"
  exit 0
fi

coverpkg="$(echo "${edge_pkgs}" | paste -sd, -)"
# shellcheck disable=SC2086 # word splitting of the package list is intended
go test -count=1 -covermode=atomic -coverpkg="${coverpkg}" -coverprofile=cover.out ${edge_pkgs}

# End-to-end: run the real edge binary built with -cover and merge its
# profile, so cmd/edge (main, signals, exit codes) is measured too.
if [[ -d cmd/edge ]]; then
  e2e="$(mktemp -d)"
  trap 'rm -rf "${e2e}"' EXIT
  mkdir -p "${e2e}/data"
  go build -tags grpcnotrace -cover -covermode=atomic -coverpkg="${coverpkg}" -o "${e2e}/edge" ./cmd/edge
  EDGE_BIN="${e2e}/edge" GOCOVERDIR="${e2e}/data" go test -count=1 -run '^TestE2E' ./cmd/edge
  go tool covdata textfmt -i="${e2e}/data" -o "${e2e}/e2e.out"
  tail -n +2 "${e2e}/e2e.out" >> cover.out
fi

total="$(go tool cover -func=cover.out | awk '/^total:/ {print $3}')"
# The total is rounded, so one uncovered statement in thousands still prints
# 100.0%. Each package's run lists every block, so a block is uncovered only
# when its counts sum to zero.
uncovered="$(awk 'NR > 1 { c[$1] += $3; n[$1] = $2 } END { for (k in c) if (c[k] == 0 && n[k] > 0) print k }' cover.out | sort)"
if [[ -n "${uncovered}" ]]; then
  echo "edge coverage is ${total}; every statement must be covered. Uncovered blocks:" >&2
  echo "${uncovered}" >&2
  exit 1
fi
echo "edge coverage ${total}"
