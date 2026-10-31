# Capacity planning

Sizing starts from two numbers you supply, the **p99 latency the edge may add** and **peak requests per second**. It then uses per-unit costs you measure with `make capacity`. Below is a worked example with a made-up scenario and costs measured on a laptop.

## Measure the per-unit costs

```bash
STEPS="500 1000 2000 4000" BUDGET_MS=10 IPS=100000 DURATION=30s make capacity
```

It runs one edge with traffic shaped like a public API: 50% `/api/`, 45% pages and 5% `/login`. Every request matches a site-wide per-IP rule, so the average is 1.55 rate-limit rules per request. `STREAMS=2000` first opens that many streams (half SSE, half WebSocket), reports the edge's memory per stream, and keeps them open during the steps. For each rate it reports:

| Column | Use |
|---|---|
| p99 and verdict | Whether that rate stays within `BUDGET_MS` |
| edge CPU | Requests per second per vCPU (`docker stats`, 100% = one vCPU) |
| Valkey calls/req | Valkey operations per request |
| bytes per key, µs per call | Valkey memory per key and Valkey CPU per call |

`SENSORS=N` adds N log-only rules shaped like the autopilot's sensors, alternating a per-IP 404 count and a per-IP distinct-paths count over `/api/items`, `/pages/home` and `/login`. Two runs, `SENSORS=0` and `SENSORS=10`, give the cost of a sensor.

Run it on hardware like your production edges, with k6 on a separate machine if you can. On a shared machine the load generator competes with the edge: dropped iterations and p99 spikes at low edge CPU are the load generator, not the edge. k6's own garbage collector adds 10–40 ms to the p99 of even a direct request at its default; `make capacity-max` runs it with `GOGC=800` and `GOMEMLIMIT=8GiB`.

### Cost of a sensor

**Measured** with `SENSORS=0 make capacity` and `SENSORS=10 make capacity` on Docker Desktop (10-vCPU VM) on a 10-core laptop also running desktop apps, with a load average of 6 to 9. This is not a quiet benchmark host:

| Rate | p99, 0 sensors | p99, 10 sensors | Edge CPU, 0 → 10 | Valkey calls/req, 0 → 10 |
|---|---|---|---|---|
| 500 RPS | 0.94 ms | 1.48 ms | 17% → 20% | 1.54 → 3.50 |
| 1,000 RPS | 0.93 ms | 3.76 ms | 23% → 26% | 1.55 → 3.50 |
| 2,000 RPS | 0.99 ms | 1.13 ms | 44% → 47% | 1.55 → 3.50 |
| 3,000 RPS | 1.60 ms | 1.74 ms | 70% → 71% | 1.55 → 3.50 |
| 4,000 RPS | 1.02 ms | 1.13 ms | 86% → 87% | 1.55 → 3.50 |
| 5,000 RPS | 1.69 ms | 1.57 ms | 104% → 108% | 1.51 → 3.50 |

Per sensor:

- **A distinct sensor costs one Valkey call per request it matches.** The five distinct sensors matched 1.95 times per request in this mix, and Valkey calls rose by exactly 1.95. A request still makes one Valkey round trip: the calls are pipelined.
- **A 404-count sensor costs no Valkey call.** It counts in each edge's memory.
- **Edge CPU** rose 1 to 4 points for all ten, under half a point per sensor at every rate. At 5,000 RPS the edge served about 4,600 RPS per vCPU instead of 4,800.
- **p99** stayed within 1 ms of the run without sensors at every rate but 1,000 RPS, where one 3.76 ms step is the host's load: the 2,000 to 5,000 RPS steps differ by 0.1 to 0.2 ms either way.
- **Valkey memory** went from 133k keys and 16 MB to 450k keys and 100 MB, 122 to 221 bytes per key on average, because a distinct key holds a 128-byte bitmap of the values it has seen. That is about 63k keys and 17 MB per distinct sensor here, for 100k client IPs. Valkey CPU per call stayed at about 13 µs.

## Find one edge's maximum

```bash
BUDGET_MS=10 DURATION=60s START=1000 make capacity-max
```

It runs one edge as a small cloud task (2 vCPU pinned, 2 GiB) in front of four mock microservices, with k6 on its own cores and the mocks sharing one core, 0.25 CPU each (`loadtest/compose.capacity.yaml`, needs a Docker VM with at least 8 CPUs and 16 GiB of memory):

| Service | Routes |
|---|---|
| `catalog` | `/api/items` (2–8 KB, median 15 ms, p99 120 ms), `/api/fast`, `/api/slow` (0.3–2 s) |
| `orders` | `POST /api/orders` (1–64 KB body), `/api/flaky` (2% 503), `/api/timeout` (past a 1 s upstream timeout) |
| `account` | `POST /login` (per-IP limit with a 5 minute penalty), `/private/*` (JWT required) |
| `content` | `/pages/*` (30 KB, localized), `/static/*` (100 KB or 1 MB) |

Each service reports its own time in `Server-Timing`, so the run measures what the edge adds to each request: k6's time minus the service's. Traffic includes CORS preflight, missing and fresh tokens, and 20 abusive IPs. Valkey gets 0.5 ms more round trip and each service 0.25 ms, as between hosts in one region.

The rate doubles until a step fails, or halves down to 100 RPS when the first step fails, then narrows to within 5%. The highest passing rate is then repeated for the spread and reported as the maximum. A run that stops early reports the range it found instead. A step passes when the added p99 is within `BUDGET_MS`, at most 0.1% of answers are unexpected, and k6 sent at least 99% of the target. It is **invalid**, and the run stops, when k6 or the mocks ran out of CPU, k6 printed no result, or the step was noisy three times. It is **noisy**, and runs again, when a direct call to a service, without the edge, took over `FLOOR_MS` (2.5 ms) at p99, or had no samples: the host stalled.

Run it on a quiet, dedicated Linux host or in one cloud region. On a laptop the host's own load sets the tail, as below.

**Measured** on Docker Desktop (10-vCPU VM) on a 10-core laptop also running desktop apps. The table is a one-off manual comparison, not script output: nginx 1.29 in the edge's slot with upstream keepalive, the same policy with no rate-limit rules, and all three called in the same k6 iteration:

| 125 RPS, no rate-limit rules (no Valkey calls) | p50 | p99 | p99.9 |
|---|---|---|---|
| Direct to the service | 0.54 ms | 2.07 ms | 7.11 ms |
| nginx | 0.68 ms | 2.73 ms | 7.92 ms |
| Edge | 0.77 ms | 2.96 ms | 7.91 ms |

With the full policy (1.85 Valkey calls per request), the edge added **1.4 ms at p50** at every rate from 125 to 2,000 RPS. The difference from nginx is the one Valkey round trip. Every answer was the expected one, and the edge used 36–71 MiB.

The laptop found no maximum. The direct call's own p99 ranged from 1 ms to 980 ms across runs as the host's load average went from 6 to 53. On quiet steps the edge's added p99 was already 6.9 ms at 125 RPS, over 5 ms, while the edge used 10% CPU, and the 10 ms search stopped at rates where the edge used under half a core.

## Worked example

**Scenario** (hypothetical):

| Input | Value |
|---|---|
| Latency budget | 10 ms added at p99 |
| Peak | 20k RPS, growing 2× in a year: plan for **40k RPS** |
| Clients | 1M distinct IPs per minute; 1.55 rules matched per request |
| Streams | 10k concurrent WebSocket/SSE |
| Upstream p99 | 200 ms |
| Topology | 3 zones; edge pods with 2 vCPU and 1 GiB |
| Busiest legitimate client | An office NAT at 300 RPS |

**Measured** with `make capacity` on Docker Desktop with 2 vCPUs, shared by k6, one edge, Valkey and the mocks:

| Rate | p99 | Edge CPU | Valkey calls/req |
|---|---|---|---|
| 500 RPS | 2.2 ms | 11% | 1.55 |
| 1,000 RPS for 3 minutes | 9.3 ms | 19% | 1.54 |
| 3,000 RPS | 2.8 ms | 27% | 1.55 |
| 4,000–5,000 RPS | 10–13 ms, with k6 dropping iterations | 42–45% | 1.55 |

Valkey used **124 bytes per key** and **21 µs of CPU per call**. With `STREAMS=2000`, each open stream cost the edge **72 KiB** of memory (16 → 158 MiB), and HTTP p99 at 500–2,000 RPS was 13–61 ms at 15–34% edge CPU, with k6 dropping iterations: the VM, now also running the stream clients, was the limit again. The edge used about 5,300 RPS per vCPU at the cleanest step and about 11,000 at the busiest. The steps that went over budget did so while the edge had idle CPU, so this machine can't find the edge's own limit. The sizing below uses the conservative 5,300.

**Sizing:**

| Item | Derivation | Result |
|---|---|---|
| Edge pods | 2 vCPU × 5,300 × 60% target CPU ≈ 6,300 RPS per pod. 40k ÷ 6.3k → 7 pods. Losing 1 of 3 zones must leave 7 → 7 × 3/2 | **12 pods**, 4 per zone; `EXPECTED_REPLICAS=12` |
| Valkey CPU | 40k × 1.55 = 62k calls/s × 21 µs = 1.3 cores. One shard runs on one core; keep each under 50% | **3-shard cluster** |
| Valkey memory | The site-wide sliding-window key lives up to 2 minutes: 1M IPs/min × 2 min, plus 5% for login ≈ 2.1M keys × 124 B ≈ 260 MB, × 1.5 for overhead | **≈ 400 MB in total**, 512 MB per shard leaves room |
| `VALKEY_TIMEOUT` | Well inside the 10 ms budget, above in-region Valkey p99 (1–2 ms) | **5ms** |
| `MAX_STREAMS` | 10k streams ÷ 8 pods left after losing a zone = 1,250 per pod; default is 1,000. At the cap, 2,500 × 72 KiB ≈ 180 MiB of the 1 GiB pod | **2500** |
| `MAX_INFLIGHT` | Little's law after a zone loss: 5k RPS × 0.2 s = 1,000 concurrent, × 2 for bursts = 2,000. Memory: about 100 KiB per in-flight request. The default from `GOMEMLIMIT` (about 920 MiB in a 1 GiB pod) is 3,680: 3,680 × 100 KiB ≈ 360 MiB, plus 180 MiB of streams, fits | default |
| Backstop (**Settings → Backstop**) | Per pod. Connections pin a client to a pod, so the NAT's 300 RPS can land on one. Default is 100/s, burst 200, which would block it | **limit 1000/s, burst 2000** |
| `LOG_SAMPLE_RATE` | 40k RPS × ~400 B ≈ 16 MB/s of access logs unsampled | **0.05** (rejections and 5xx are always logged) |

Two of the defaults (`MAX_STREAMS`, backstop) are too low for this scenario. That is why sizing from your own numbers matters.

## Then prove it

Set the thresholds in `loadtest/k6` to your budget, then run `make load-full` against a deployment sized like the table. Finally, take one zone's pods away under peak load and check that p99 stays within budget.
