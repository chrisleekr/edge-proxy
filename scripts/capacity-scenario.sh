#!/bin/sh
# Capacity scenario: steps one edge through fixed request rates
# with scenario-shaped traffic (loadtest/k6/scenario.js) and reports, per
# step, p99 against BUDGET_MS, the edge's CPU, Valkey calls per request, and
# Valkey bytes per key. These per-unit figures feed capacity sizing.
# STREAMS=N first opens N streams (half SSE, half WebSocket), reports the
# edge's memory per stream, and keeps them open while the steps run.
# Not a CI gate: the edge shares the Docker VM with k6 and Valkey.
#
#   STEPS="500 1000 2000" BUDGET_MS=10 IPS=100000 DURATION=30s STREAMS=2000 scripts/capacity-scenario.sh
set -eu
cd "$(dirname "$0")/../loadtest"

STEPS="${STEPS:-500 1000 2000 3000 4000 5000}"
BUDGET_MS="${BUDGET_MS:-10}"
IPS="${IPS:-100000}"
DURATION="${DURATION:-30s}"
STREAMS="${STREAMS:-0}"

project="edge-scenario"
compose() { docker compose -p "${project}" "$@"; }
trap 'compose --profile k6 down -v >/dev/null 2>&1' EXIT

compose --profile k6 build --quiet
compose up -d --wait edge-1 upstream >/dev/null 2>&1
k6() { compose run --rm --no-deps k6 run --quiet -e BUDGET_MS="${BUDGET_MS}" -e IPS="${IPS}" "$@" /scripts/scenario.js; }
vk() { compose exec -T valkey valkey-cli "$@" | tr -d '\r'; }
evalsha() { vk INFO commandstats | sed -n 's/^cmdstat_evalsha:calls=\([0-9]*\),.*/\1/p'; }

k6 -e PUBLISH=1 -e RATE=20 -e DURATION=5s >/dev/null
# Warm connections and pools before measuring; the result is discarded.
k6 -e RATE=500 -e DURATION=20s >/dev/null 2>&1 || true
edge="$(compose ps -q edge-1)"
cores="$(docker info --format '{{.NCPU}}')"

if [ "${STREAMS}" -gt 0 ]; then
  metric() { compose exec -T valkey wget -qO- http://edge-1:9090/metrics | sed -n "s/^$1 //p"; }
  mib() { docker stats --no-stream --format '{{.MemUsage}}' "${edge}" | awk '{ v = $1 + 0; if ($1 ~ /GiB/) v *= 1024; if ($1 ~ /KiB/) v /= 1024; printf "%.0f", v }'; }
  before="$(mib)"
  compose run --rm --no-deps upstream streams -url http://edge-1:8080 -sse $((STREAMS / 2)) -ws $((STREAMS - STREAMS / 2)) -for 24h >/dev/null 2>&1 &
  for _ in $(seq 120); do
    [ "$(metric edge_streams)" -ge "${STREAMS}" ] 2>/dev/null && break
    sleep 1
  done
  sleep 5 # let memory settle
  after="$(mib)"
  echo "Streams: $(metric edge_streams) of ${STREAMS} open, edge memory ${before} -> ${after} MiB, $(( (after - before) * 1024 / STREAMS )) KiB per stream"
fi

echo "Budget p99 ${BUDGET_MS} ms, ${IPS} client IPs, ${DURATION} per step, Docker VM ${cores} vCPUs"
echo "  target  achieved   p50 ms   p99 ms  errors  dropped  verdict  edge CPU  Valkey calls/req"
for rate in ${STEPS}; do
  before="$(evalsha)"
  # Sample the edge's CPU while the step runs; docker stats reports 100% per core.
  (while :; do docker stats --no-stream --format '{{.CPUPerc}}' "${edge}" | tr -d '%'; done) > .cpu &
  sampler=$!
  line="$(k6 -e RATE="${rate}" -e DURATION="${DURATION}" 2>/dev/null | sed -n 's/^RESULT //p')"
  kill "${sampler}" 2>/dev/null
  wait "${sampler}" 2>/dev/null || true
  calls=$(( $(evalsha) - before ))
  cpu="$(awk 'NR>1 { s += $1; n++ } END { if (n) printf "%.0f%%", s / n; else print "n/a" }' .cpu)"
  # shellcheck disable=SC2086 # split the result fields into $1..$7
  set -- ${line}
  per_req="$(awk -v c="${calls}" -v r="$2" -v d="${DURATION%s}" 'BEGIN { if (r > 0) printf "%.2f", c / (r * d); else print "n/a" }')"
  printf '%8s %9s %8s %8s %6s%% %8s %8s %9s %17s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "${cpu}" "${per_req}"
done
rm -f .cpu

keys="$(vk DBSIZE)"
mem="$(vk INFO memory | sed -n 's/^used_memory_dataset:\([0-9]*\)/\1/p')"
usec="$(vk INFO commandstats | sed -n 's/^cmdstat_evalsha:.*usec_per_call=\([0-9.]*\).*/\1/p')"
echo "Valkey: ${keys} keys, ${mem} bytes of data, $(( mem / (keys > 0 ? keys : 1) )) bytes per key, ${usec} µs of Valkey CPU per call"
