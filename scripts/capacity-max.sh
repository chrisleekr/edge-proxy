#!/bin/sh
# Maximum capacity of one edge (2 vCPU, 2 GiB) in a cloud-shaped local
# environment (loadtest/compose.capacity.yaml): four mock microservices,
# network delay to Valkey and the services, and k6 on its own cores.
#
# It doubles the rate until a step fails (or halves it, down to 100 RPS, when
# the first one fails), then narrows the gap to within 5%.
# A step passes when what the edge adds to each request stays within
# BUDGET_MS at p99, at most 0.1% of answers are unexpected, and k6 sent at
# least 99% of the target. A step is invalid, and the run stops, when k6 or a
# mock service ran out of CPU: the result would measure them, not the edge.
# A step is noisy when a direct call to a service, without the edge, took
# over FLOOR_MS at p99: the host or VM stalled, so the step runs again, at
# most twice.
# When a failing rate bounds it, the highest passing rate is run REPEAT more
# times to show the spread.
# The report lands in loadtest/results/capacity-max.txt.
#
#   BUDGET_MS=5 DURATION=60s START=1000 REPEAT=2 scripts/capacity-max.sh
set -eu
cd "$(dirname "$0")/../loadtest"

BUDGET_MS="${BUDGET_MS:-5}"
DURATION="${DURATION:-60s}"
START="${START:-1000}"
REPEAT="${REPEAT:-2}"
IPS="${IPS:-100000}"
FLOOR_MS="${FLOOR_MS:-2.5}"
# k6 and the calls-per-request figure read DURATION as a count of seconds.
case "${DURATION%s}" in
  "${DURATION}" | '' | 0* | *[!0-9]*) echo "DURATION must be whole seconds, like 60s." >&2; exit 1 ;;
esac

project="edge-cap"
compose() { docker compose -p "${project}" -f compose.yaml -f compose.capacity.yaml "$@"; }
trap 'compose logs --no-color > results/capacity-compose.log 2>&1 || true; compose --profile k6 down -v >/dev/null 2>&1' EXIT
mkdir -p results
report=results/capacity-max.txt

cpus="$(docker info --format '{{.NCPU}}')"
if [ "${cpus}" -lt 8 ]; then
  echo "The Docker VM has ${cpus} CPUs; compose.capacity.yaml pins work to 8." >&2
  exit 1
fi
# The container limits add up to about 5 GiB and k6 may grow to its 8 GiB
# GOMEMLIMIT; below that, an OOM kill would read as a failed step. The VM
# kernel reports a few hundred MiB less than the size it was given, so the
# floor sits under the 16 GiB the docs ask for.
mem="$(docker info --format '{{.MemTotal}}')"
if [ "${mem}" -lt $((14 * 1024 * 1024 * 1024)) ]; then
  echo "The Docker VM has $((mem / 1024 / 1024)) MiB of memory; set the Docker VM to 16 GiB." >&2
  exit 1
fi

compose --profile k6 build --quiet
compose up -d --wait collector edge-1 catalog orders account content delay-valkey delay-catalog delay-orders delay-account delay-content >/dev/null 2>&1 ||
  { echo "compose up failed; see loadtest/results/capacity-compose.log" >&2; exit 1; }
k6() { compose run --rm --no-deps k6 run --quiet -e IPS="${IPS}" "$@" /scripts/capacity-max.js; }
vk() { compose exec -T valkey valkey-cli "$@" | tr -d '\r'; }
evalsha() { vk INFO commandstats | sed -n 's/^cmdstat_evalsha:calls=\([0-9]*\),.*/\1/p'; }

k6 -e PUBLISH=1 -e RATE=50 -e DURATION=5s >/dev/null
# Warm connections, pools and caches; the result is discarded.
k6 -e RATE="${START}" -e DURATION=30s >/dev/null 2>&1 || true

# stats samples CPU (100 per core) and memory of the edge, Valkey, each
# service and k6 until stopped, one line per sample.
ids() { for s in edge-1 valkey catalog orders account content; do compose ps -q "$s"; done; }
stats() {
  while :; do
    # shellcheck disable=SC2046 # one argument per container ID
    # The k6 container can exit between listing it and sampling it.
    docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' $(ids) $(docker ps -q --filter "label=com.docker.compose.project=${project}" --filter "label=com.docker.compose.service=k6") 2>/dev/null || true
  done
}
# peak NAME FIELD: the highest CPU (2) or memory in MiB (3) seen for a
# container. Its first sample is skipped: it covers k6 starting up.
peak() {
  awk -v n="$1" -v f="$2" '$1 ~ n && seen[$1]++ {
    v = $f; gsub(/%/, "", v); x = v + 0
    if (f == 3) { if (v ~ /GiB/) x *= 1024; else if (v ~ /KiB/) x /= 1024 }
    if (x > m) m = x
  } END { printf "%.0f", m }' .stats
}

# step RATE prints one report line and sets verdict to pass, fail, invalid
# or noisy.
step() {
  echo "step: $1 RPS for ${DURATION}" >&2
  before="$(evalsha)"
  # A sampler left from the last step keeps writing to the unlinked file.
  rm -f .stats
  stats > .stats &
  sampler=$!
  out="$(k6 -e RATE="$1" -e DURATION="${DURATION}" 2>/dev/null || true)"
  kill "${sampler}" 2>/dev/null || true
  wait "${sampler}" 2>/dev/null || true
  calls=$(( $(evalsha) - before ))
  if ! echo "${out}" | grep -q '^RESULT '; then
    echo "  $1 RPS: k6 printed no result" | tee -a "${report}"
    echo "${out}" | tail -5 >&2
    verdict=invalid
    return
  fi
  echo "${out}" | sed -n 's/^KIND /    /p' > .kinds
  # shellcheck disable=SC2046 # split RESULT into $1..$9
  set -- $(echo "${out}" | sed -n 's/^RESULT //p')
  target=$1 achieved=$2 p50=$3 p99=$4 answer=$5 unexpected=$6 dropped=$7 floor="$8/$9"
  edge_cpu="$(peak edge-1 2)" edge_mem="$(peak edge-1 3)" valkey_cpu="$(peak valkey 2)" k6_cpu="$(peak k6 2)"
  svc_cpu=0 svc_sum=0
  for s in catalog orders account content; do
    c="$(peak "$s" 2)"
    svc_sum=$(( svc_sum + c ))
    if [ "$c" -gt "${svc_cpu}" ]; then svc_cpu=$c; fi
  done
  per_req="$(awk -v c="${calls}" -v r="${achieved}" -v d="${DURATION%s}" 'BEGIN { if (r > 0) printf "%.2f", c / (r * d); else print "n/a" }')"
  # 70% of a service's 0.25 CPU, 70% of the one core the four share, and 90%
  # of k6's 3 CPUs.
  if [ "${svc_cpu}" -gt 17 ] || [ "${svc_sum}" -gt 70 ] || [ "${k6_cpu}" -gt 270 ]; then
    verdict=invalid
  elif awk -v f="$9" -v m="${FLOOR_MS}" 'BEGIN { exit !(f == "n/a" || f + 0 > m + 0) }'; then
    verdict=noisy
  elif awk -v p="${p99}" -v b="${BUDGET_MS}" -v u="${unexpected}" -v a="${achieved}" -v t="${target}" \
    'BEGIN { exit !(p != "n/a" && p + 0 <= b + 0 && u + 0 <= 0.1 && a + 0 >= 0.99 * t) }'; then
    verdict=pass
  else
    verdict=fail
  fi
  printf '%7s %8s %7s %7s %8s %7s%% %7s %11s %8s%% %6s MiB %7s%% %7s%% %7s%% %8s  %s\n' \
    "${target}" "${achieved}" "${p50}" "${p99}" "${answer}" "${unexpected}" "${dropped}" "${floor}" "${edge_cpu}" "${edge_mem}" "${valkey_cpu}" "${svc_cpu}" "${k6_cpu}" "${per_req}" "${verdict}" | tee -a "${report}"
  cat .kinds >> "${report}"
}

{
  echo "Edge 2 vCPU / 2 GiB, budget: added p99 <= ${BUDGET_MS} ms, ${DURATION} per step, ${IPS} client IPs, Docker VM ${cpus} vCPUs"
  echo "Added = request time at k6 minus the service's own time (Server-Timing). Edge answers (429, 401, preflight) are timed as a whole; the 504 timeout route is left out."
  echo "Floor = the same for k6 calling a service directly: network any setup pays, edge or not (p50/p99)."
  echo "  target achieved add-p50 add-p99 answer99 unexpect dropped  floor50/99 edge-cpu edge-mem  valkey  service      k6 calls/req  verdict"
  echo "    (per kind: name added-p50 added-p99 unexpected%)"
} | tee "${report}"

# measure RATE runs a step, again up to twice while it is noisy.
measure() {
  for _ in 1 2 3; do
    step "$1"
    if [ "${verdict}" != noisy ]; then return; fi
  done
  echo "  $1 RPS: noisy three times; the host is too busy to measure the edge" | tee -a "${report}"
  verdict=invalid
}

# Find a passing and a failing rate, then bisect between them to within 5%.
lo=0 hi=0 rate="${START}" stopped=0
while :; do
  measure "${rate}"
  case "${verdict}" in
    invalid) stopped=1; break ;;
    pass) lo="${rate}"; [ "${hi}" -gt 0 ] && break; rate=$(( rate * 2 )) ;;
    fail)
      hi="${rate}"
      [ "${lo}" -gt 0 ] && break
      [ $(( rate / 2 )) -lt 100 ] && break
      rate=$(( rate / 2 )) ;;
  esac
done
while [ "${stopped}" -eq 0 ] && [ "${lo}" -gt 0 ] && [ "${hi}" -gt 0 ] && [ $(( (hi - lo) * 100 )) -gt $(( lo * 5 )) ]; do
  rate=$(( (lo + hi) / 2 ))
  measure "${rate}"
  case "${verdict}" in
    pass) lo="${rate}" ;;
    fail) hi="${rate}" ;;
    invalid) stopped=1 ;;
  esac
done
if [ "${stopped}" -eq 1 ]; then
  echo "Stopped: the step above did not measure the edge (k6 or a mock out of CPU, no result, or a busy host)." | tee -a "${report}"
fi

if [ "${stopped}" -eq 0 ] && [ "${lo}" -gt 0 ] && [ "${hi}" -gt 0 ]; then
  echo "Repeating ${lo} RPS ${REPEAT} more times for the spread:" | tee -a "${report}"
  i=0
  while [ "${i}" -lt "${REPEAT}" ]; do
    measure "${lo}"
    i=$(( i + 1 ))
  done
  echo "Maximum: ${lo} RPS per edge within ${BUDGET_MS} ms added at p99 (lowest failing step: ${hi})" | tee -a "${report}"
elif [ "${lo}" -gt 0 ] && [ "${hi}" -gt 0 ]; then
  echo "Between ${lo} and ${hi} RPS; the search stopped before narrowing to 5%." | tee -a "${report}"
elif [ "${lo}" -gt 0 ]; then
  echo "At least ${lo} RPS; the search stopped before a step failed." | tee -a "${report}"
elif [ "${hi}" -gt 0 ]; then
  # With no pass, the search only halved, so rate is the lowest one tried.
  echo "No step passed from ${START} down to ${rate} RPS." | tee -a "${report}"
else
  echo "No step measured the edge." | tee -a "${report}"
fi

keys="$(vk DBSIZE)"
mem="$(vk INFO memory | sed -n 's/^used_memory_dataset:\([0-9]*\)/\1/p')"
usec="$(vk INFO commandstats | sed -n 's/^cmdstat_evalsha:.*usec_per_call=\([0-9.]*\).*/\1/p')"
echo "Valkey: ${keys} keys, $(( mem / (keys > 0 ? keys : 1) )) bytes per key, ${usec} µs of Valkey CPU per call" | tee -a "${report}"
rm -f .stats .kinds
