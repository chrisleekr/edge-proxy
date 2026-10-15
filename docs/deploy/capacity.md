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

Run it on hardware like your production edges, with k6 on a separate machine if you can. On a shared machine the load generator competes with the edge: dropped iterations and p99 spikes at low edge CPU are the load generator, not the edge.

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
| `MAX_UPSTREAM_INFLIGHT` | Little's law after a zone loss: 5k RPS × 0.2 s = 1,000 concurrent, × 2 for bursts, plus 1,250 streams; default is 2,000 | **4000** |
| `MAX_INFLIGHT` | 2,000 ordinary concurrent requests at worst | **10000** (default) |
| Backstop (**Settings → Backstop**) | Per pod. Connections pin a client to a pod, so the NAT's 300 RPS can land on one. Default is 100/s, burst 200, which would block it | **limit 1000/s, burst 2000** |
| `LOG_SAMPLE_RATE` | 40k RPS × ~400 B ≈ 16 MB/s of access logs unsampled | **0.05** (rejections and 5xx are always logged) |

Three of the defaults (`MAX_STREAMS`, `MAX_UPSTREAM_INFLIGHT`, backstop) are too low for this scenario. That is why sizing from your own numbers matters.

## Then prove it

Set the thresholds in `loadtest/k6` to your budget, then run `make load-full` against a deployment sized like the table. Finally, take one zone's pods away under peak load and check that p99 stays within budget.
