#!/usr/bin/env bash
# Runs every fuzz target briefly. Seed corpora in testdata/fuzz run in every
# `go test`; this adds new random inputs so parser and matcher regressions on
# the trust boundary fail CI. Go fuzzes one target per invocation.
set -euo pipefail

fuzztime="${FUZZTIME:-20s}"
found=0
for pkg in $(go list ./...); do
  for target in $(go test -list '^Fuzz' "${pkg}" | grep '^Fuzz' || true); do
    found=1
    echo "fuzz ${pkg} ${target} for ${fuzztime}"
    go test -run='^$' -fuzz="^${target}\$" -fuzztime="${fuzztime}" "${pkg}"
  done
done
if [[ "${found}" == 0 ]]; then
  echo "no fuzz targets yet"
fi
