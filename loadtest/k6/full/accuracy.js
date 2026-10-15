// Accuracy of every algorithm across many client IPs.
// Each IP sends 12 requests to each algorithm's path, limited to 10 per
// hour, so exactly 10 per IP should pass. IPS=1000000 before a release.
// Concurrency stays where Valkey answers within VALKEY_TIMEOUT: a timed-out
// call fails open by design and would count as an over-allow here.
// load-full.sh reports the edges' Valkey errors during the run.
import http from 'k6/http';
import exec from 'k6/execution';
import { Counter } from 'k6/metrics';
import { session, publish, converged } from '../admin.js';
import { edges, path, pick, rule, thresholdReport, viewer, waitReady } from '../lib.js';

const IPS = Number(__ENV.IPS || 20000);
const LIMIT = 10;
const SENT = 12;
const algorithms = { fixed: 'fixed_window', sliding: 'sliding_window', token: 'token_bucket', leaky: 'leaky_bucket' };
const allowed = Object.fromEntries(Object.keys(algorithms).map((a) => [a, new Counter(`allowed_${a}`)]));

export const options = {
  setupTimeout: '120s',
  scenarios: { ips: { executor: 'shared-iterations', vus: Number(__ENV.VUS || 20), iterations: IPS, maxDuration: '120m' } },
  // Never fewer than the limit. load-full.sh checks the ceiling: any excess
  // must be covered by fail-open events the edges counted.
  thresholds: Object.fromEntries(Object.keys(algorithms).map((a) => [`allowed_${a}`, [`count>=${IPS * LIMIT}`]])),
};

export function setup() {
  waitReady();
  const cookie = session();
  const v = publish(cookie, (c) => ({
    ...c,
    rate_limit_rules: Object.entries(algorithms).map(([name, algorithm]) =>
      rule(`alg-${name}`, path('eq', `/alg/${name}`), { algorithm, limit: LIMIT, period: '1h', ...(algorithm.endsWith('bucket') && { burst: LIMIT }) }),
    ),
  }), { message: 'accuracy: one rule per algorithm', tests: [] });
  converged(cookie, v);
}

export default function () {
  const headers = viewer(exec.scenario.iterationInTest + 1);
  for (const name of Object.keys(algorithms)) {
    const reqs = Array.from({ length: SENT }, () => ({ method: 'GET', url: `${pick(edges)}/alg/${name}`, params: { headers, responseCallback: http.expectedStatuses(200, 429) } }));
    for (const r of http.batch(reqs)) if (r.status === 200) allowed[name].add(1);
  }
}

export function handleSummary(data) {
  const counts = Object.keys(algorithms).map((a) => `${a}=${data.metrics[`allowed_${a}`]?.values.count ?? 0}`);
  return { stdout: `\nAccuracy over ${IPS} IPs, expecting ${IPS * LIMIT} allowed per algorithm\nALLOWED ${counts.join(' ')}\n` + thresholdReport(data) };
}
