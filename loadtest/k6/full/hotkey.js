// Hot key: every request is the same client on one rule, so
// every Valkey call hits one key on one shard. Steps find where it saturates.
import http from 'k6/http';
import { session, publish, converged } from '../admin.js';
import { edges, path, pick, rule, waitReady } from '../lib.js';

const steps = (__ENV.STEPS || '500,1000,2000,4000,6000').split(',').map(Number);
const stepSeconds = 20;
const scenarios = {};
steps.forEach((rate, i) => {
  scenarios[`rps_${rate}`] = { executor: 'constant-arrival-rate', rate, timeUnit: '1s', duration: `${stepSeconds}s`, startTime: `${i * (stepSeconds + 5)}s`, preAllocatedVUs: 100, maxVUs: 2000 };
});

export const options = {
  setupTimeout: '120s',
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  scenarios,
  thresholds: Object.fromEntries(steps.flatMap((r) => [
    [`http_req_duration{scenario:rps_${r}}`, ['max>=0']],
    [`http_req_failed{scenario:rps_${r}}`, ['rate>=0']],
    [`dropped_iterations{scenario:rps_${r}}`, ['count>=0']],
    [`http_reqs{scenario:rps_${r}}`, ['count>=0']],
  ])),
};

export function setup() {
  waitReady();
  const cookie = session();
  const v = publish(cookie, (c) => ({
    ...c,
    rate_limit_rules: [rule('hot', path('eq', '/hot'), { algorithm: 'token_bucket', limit: 1000000, period: '1s', burst: 1000000 })],
  }), { message: 'hot key', tests: [] });
  converged(cookie, v);
}

export default function () {
  http.get(`${pick(edges)}/hot`, { headers: { Host: 'api.example.com', 'CloudFront-Viewer-Address': '192.0.2.200:443' } });
}

export function handleSummary(data) {
  const v = (name) => data.metrics[name]?.values ?? {};
  const lines = ['', 'Hot key: target RPS   achieved   p50 ms   p99 ms   errors   dropped'];
  for (const r of steps) {
    const d = v(`http_req_duration{scenario:rps_${r}}`);
    lines.push(`${String(r).padStart(19)} ${(v(`http_reqs{scenario:rps_${r}}`).count / stepSeconds).toFixed(0).padStart(10)} ${d.med?.toFixed(2).padStart(8)} ${d['p(99)']?.toFixed(2).padStart(8)} ${((v(`http_req_failed{scenario:rps_${r}}`).rate ?? 0) * 100).toFixed(2).padStart(7)}% ${String(v(`dropped_iterations{scenario:rps_${r}}`).count ?? 0).padStart(9)}`);
  }
  return { stdout: lines.join('\n') + '\n' };
}
