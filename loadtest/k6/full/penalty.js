// One client far over its limit, with a penalty: after the
// first block every edge serves 429 from its local penalty cache, so Valkey
// sees almost none of this traffic. load-full.sh compares Valkey's EVALSHA
// count before and after.
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { session, publish, converged } from '../admin.js';
import { edges, path, pick, rule, thresholdReport, waitReady } from '../lib.js';

const allowed = new Counter('penalty_allowed');

export const options = {
  setupTimeout: '120s',
  scenarios: { flood: { executor: 'constant-arrival-rate', rate: 200, timeUnit: '1s', duration: '60s', preAllocatedVUs: 50, maxVUs: 200 } },
  thresholds: { penalty_allowed: ['count<=10'], checks: ['rate==1'] },
};

export function setup() {
  waitReady();
  const cookie = session();
  const v = publish(cookie, (c) => ({
    ...c,
    rate_limit_rules: [rule('pen', path('eq', '/pen'), { algorithm: 'fixed_window', limit: 10, period: '1m', penalty: '5m' })],
  }), { message: 'penalty', tests: [] });
  converged(cookie, v);
}

export default function () {
  const r = http.get(`${pick(edges)}/pen`, { headers: { Host: 'api.example.com', 'CloudFront-Viewer-Address': '192.0.2.201:443' }, responseCallback: http.expectedStatuses(200, 429) });
  check(r, { '200 or 429': (r) => r.status === 200 || r.status === 429 });
  if (r.status === 200) allowed.add(1);
}

export function handleSummary(data) {
  return { stdout: `\nPenalty: ${data.metrics.http_reqs.values.count} requests from one client\n` + thresholdReport(data) };
}
