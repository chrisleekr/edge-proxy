#!/bin/sh
# Full load profile, nightly and before a release: dependency
# outages, algorithm accuracy across many IPs, 200 rules per phase, a hot
# key, penalties, JWT and locale, publishing and canaries under load, an
# over-blocking canary, five attacks the autopilot must enforce against,
# long-lived streams and drain, rolling restarts, losing an edge, and a
# Valkey cluster. PROFILE=release uses 1M IPs and
# holds 10k streams for an hour. ONLY=<regex> runs just the scenarios whose
# names match it. The report lands in loadtest/results/full-report.txt.
# POSIX sh, as load.sh.
set -eu
cd "$(dirname "$0")/../../loadtest"

if [ "${PROFILE:-local}" = release ]; then
  IPS=1000000 STREAMS=5000 STREAM_FOR=1h
else
  IPS="${IPS:-20000}" STREAMS="${STREAMS:-5000}" STREAM_FOR="${STREAM_FOR:-5m}"
fi

project=edge-full
compose() { docker compose -p "${project}" "$@"; }
mkdir -p results
report=results/full-report.txt
: > "${report}"
failed=""

note() { echo "$*" | tee -a "${report}"; }
# step NAME CMD...: runs one scenario, records pass or fail, and goes on.
step() {
  name=$1
  shift
  echo "${name}" | grep -Eq "${ONLY:-.}" || return 0
  note ""
  note "== ${name}"
  if "$@" 2>&1 | tee -a "${report}" | grep -v 'level=warn'; then :; fi
  # tee hides the exit status in POSIX sh, so each command writes its own.
  if [ "$(cat results/.status)" != 0 ]; then failed="${failed} ${name}"; fi
}
k6() {
  set +e
  compose run --rm --no-deps "$@"
  echo $? > results/.status
  set -e
}
valkey_info() { compose exec -T valkey valkey-cli INFO "$1" | tr -d '\r'; }
field() { grep "^$1:" | head -1 | cut -d: -f2; }
mem() { docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' "${project}-edge-1-1" "${project}-edge-2-1" "${project}-edge-3-1"; }

up() {
  compose --profile k6 build
  compose up -d --wait collector upstream lb edge-1 edge-2 edge-3
}

outage() {
  svc=$1
  stop=$2
  start=$3
  k6 k6 run --quiet /scripts/outage.js &
  pid=$!
  sleep 20
  compose "${stop}" "${svc}"
  sleep 20
  compose "${start}" "${svc}"
  wait "${pid}"
}

# The first field only: later ones (rejected_calls, failed_calls) also end in calls=.
evalsha_calls() { valkey_info commandstats | grep '^cmdstat_evalsha:' | sed 's/^cmdstat_evalsha:calls=//; s/,.*//'; }
# edge_metric sums one counter over the edges.
edge_metric() {
  for e in edge-1 edge-2 edge-3; do
    compose exec -T valkey wget -qO- "http://${e}:9090/metrics" | grep "^$1 " | cut -d' ' -f2
  done | awk '{ s += $1 } END { print s + 0 }'
}
# edge_errors counts calls that failed or never went out because a breaker
# was open; either way the rule took its fail mode.
edge_errors() { echo $(( $(edge_metric edge_valkey_errors_total) + $(edge_metric edge_valkey_breaker_open_total) )); }
# restart_edge starts an edge again without re-running the one-shot seed.
restart_edge() { compose up -d --no-deps --wait "$1"; }
penalty() {
  before=$(evalsha_calls)
  k6 k6 run --quiet /scripts/full/penalty.js
  status=$(cat results/.status)
  calls=$(( $(evalsha_calls) - before ))
  echo "Valkey EVALSHA calls for 12000 requests: ${calls} (want under 100)"
  [ "${calls}" -lt 100 ] || status=1
  echo "${status}" > results/.status
}

# accuracy IPS: every algorithm allows exactly the limit per IP, except
# where a Valkey call timed out or met an open breaker and the rule failed
# open by design, so the excess must not exceed those events.
accuracy() {
  cpu_before=$(valkey_info cpu | field used_cpu_user)
  events_before=$(edge_errors)
  k6 k6 run --quiet -e IPS="$1" /scripts/full/accuracy.js | tee results/.accuracy
  status=$(cat results/.status)
  cpu_after=$(valkey_info cpu | field used_cpu_user)
  events=$(( $(edge_errors) - events_before ))
  over=$(grep '^ALLOWED' results/.accuracy | tr ' ' '\n' | grep '=' | cut -d= -f2 | awk -v want=$(( $1 * 10 )) '{ if ($1 - want > m) m = $1 - want } END { print m + 0 }')
  echo "Most over-allowed: ${over}; Valkey fail-open events at the edges: ${events} (excess must not exceed them)"
  echo "Valkey memory $(valkey_info memory | field used_memory_human), user CPU $(awk "BEGIN { print ${cpu_after} - ${cpu_before} }")s"
  [ "${over}" -le "${events}" ] || status=1
  echo "${status}" > results/.status
}

streams_hold() {
  echo "edge memory before:"; mem
  (sleep 60 && echo "edge memory after 1m:" && mem) &
  set +e
  compose run --rm --no-deps upstream streams -url http://lb:8000 -sse "${STREAMS}" -ws "${STREAMS}" -for "${STREAM_FOR}"
  echo $? > results/.status
  set -e
  echo "edge memory at the end:"; mem
}

drain() {
  compose run --rm --no-deps upstream streams -url http://lb:8000 -sse 1500 -ws 1500 -for 2m >/dev/null 2>&1 &
  pid=$!
  sleep 30
  start=$(date +%s)
  compose stop -t 45 edge-1
  took=$(( $(date +%s) - start ))
  code=$(docker inspect -f '{{.State.ExitCode}}' "${project}-edge-1-1")
  echo "edge-1 drained with streams open in ${took}s, exit code ${code} (want 0 within 45s)"
  restart_edge edge-1
  wait "${pid}" || true
  if [ "${code}" = 0 ] && [ "${took}" -lt 45 ]; then echo 0; else echo 1; fi > results/.status
}

rolling() {
  k6 -e DURATION=120s -e LABEL='Rolling restart through the LB' k6 run --quiet /scripts/full/steady-lb.js &
  pid=$!
  sleep 15
  for e in edge-1 edge-2 edge-3; do
    compose restart -t 45 "${e}"
    sleep 15 # ready again and back in the LB
  done
  wait "${pid}"
}

lose_edge() {
  k6 -e DURATION=60s -e MAX_ERRORS=0.005 -e LABEL='Losing one of three edges' k6 run --quiet /scripts/full/steady-lb.js &
  pid=$!
  sleep 20
  compose kill edge-2
  wait "${pid}"
  restart_edge edge-2
}

# autopilot_attacks runs the five attacks with the scripted agent answering
# the autopilot's cases, then stops the agent.
autopilot_attacks() {
  compose --profile autopilot-load up -d agent
  k6 k6 run --quiet /scripts/full/autopilot.js
  status=$(cat results/.status)
  compose logs --no-color agent | tail -40
  compose --profile autopilot-load stop agent
  echo "${status}" > results/.status
}

cleanup() { compose down -v >/dev/null 2>&1 || true; }
trap 'compose logs --no-color > "results/${project}.log" 2>&1 || true; cleanup' EXIT

up
step "Valkey outage" outage valkey stop start
step "Admin outage" outage admin stop start
step "Postgres outage" outage postgres stop start
step "IdP hangs" outage idp pause unpause
step "Trace collector outage" outage collector stop start
step "Trace collector hangs" outage collector pause unpause
step "JWT cached and uncached, locale" k6 k6 run --quiet /scripts/full/jwt-locale.js
step "Accuracy over ${IPS} IPs" accuracy "${IPS}"
step "200 rules per phase" k6 k6 run --quiet /scripts/full/rules200.js
step "Hot key" k6 k6 run --quiet /scripts/full/hotkey.js
step "One client over its limit with a penalty" penalty
step "Publish every 10s and a canary" k6 k6 run --quiet /scripts/full/publish.js
step "Over-blocking canary" k6 k6 run --quiet /scripts/full/overblock.js
step "Autopilot: five attacks" autopilot_attacks
step "$((STREAMS * 2)) streams for ${STREAM_FOR}" streams_hold
step "Drain with streams open" drain
step "Rolling restart" rolling
step "Lose one of three edges" lose_edge
compose logs --no-color > results/full-compose.log 2>&1 || true
cleanup

# The same shared-quota and accuracy checks on a 3-shard cluster.
if echo "Cluster: smoke|Cluster: accuracy" | grep -Eq "${ONLY:-.}"; then
project=edge-full-cluster
export COMPOSE_PROFILES=cluster
export VALKEY_URL='redis://10.77.0.21:6379?addr=10.77.0.22:6379&addr=10.77.0.23:6379'
compose --profile k6 build >/dev/null
compose run --rm valkey-cluster-init >/dev/null
compose up -d --wait collector upstream edge-1 edge-2 edge-3
step "Cluster: smoke" k6 k6 run --quiet /scripts/smoke.js
step "Cluster: accuracy over 5000 IPs" accuracy 5000
fi

note ""
if [ -n "${failed}" ]; then
  note "FAILED:${failed}"
  exit 1
fi
note "All full-profile scenarios passed."
