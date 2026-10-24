#!/bin/sh
# Tier 1 load smoke: builds the images, starts
# loadtest/compose.yaml, runs the k6 smoke, then a Valkey outage under load.
# Reports print to stdout; compose logs land in loadtest/results. RATE
# overrides the smoke request rate.
# POSIX sh, so it also runs in the docker image GitLab uses.
set -eu
cd "$(dirname "$0")/../../loadtest"

compose() { docker compose -p edge-load "$@"; }
trap 'compose logs --no-color > results/compose.log 2>&1 || true; compose down -v >/dev/null 2>&1' EXIT
mkdir -p results

compose --profile k6 build
compose up -d --wait collector upstream edge-1 edge-2 edge-3
compose run --rm --no-deps -e RATE="${RATE:-300}" k6 run --quiet /scripts/smoke.js

# Valkey goes away 15s into the run and returns 20s later; rules fail open
# and readiness must not change.
compose run --rm --no-deps k6 run --quiet /scripts/outage.js &
k6_pid=$!
sleep 20
compose stop valkey
sleep 20
compose start valkey
wait "${k6_pid}"
