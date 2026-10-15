// Latency at the rule budget: 200 rules in every phase.
// Requests match only a few, so this measures evaluating the rest.
import http from 'k6/http';
import { check } from 'k6';
import { session, publish, converged } from '../admin.js';
import { edges, latencyReport, path, pick, rule, thresholdReport, viewer, waitReady } from '../lib.js';

const steady = (exec) => ({ executor: 'constant-arrival-rate', exec, rate: 300, timeUnit: '1s', duration: '60s', preAllocatedVUs: 50, maxVUs: 500 });

export const options = {
  setupTimeout: '120s',
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  scenarios: { direct: steady('direct'), edge: steady('viaEdge') },
  thresholds: {
    'http_req_duration{scenario:edge}': ['p(99)<50'],
    'http_req_duration{scenario:direct}': ['p(99)<50'],
    'http_req_failed{scenario:edge}': ['rate<0.001'],
  },
};

const range = (n) => Array.from({ length: n }, (_, i) => i);

export function setup() {
  waitReady();
  const cookie = session();
  const v = publish(cookie, (c) => ({
    ...c,
    config_rules: range(200).map((i) => ({ id: `cfg-${i}`, expression: path('starts_with', `/c/${i}/`), settings: { ratelimit_headers: true } })),
    rate_limit_rules: [
      ...range(199).map((i) => rule(`rl-${i}`, path('eq', `/rl/${i}`), { algorithm: 'sliding_window', limit: 1000, period: '1m' })),
      rule('api-per-ip', path('starts_with', '/api/'), { algorithm: 'token_bucket', limit: 1000, period: '1s', burst: 1000 }),
    ],
    request_header_rules: range(200).map((i) => ({ id: `hdr-${i}`, expression: path('eq', `/h/${i}`), ops: [{ op: 'set', name: `X-Rule-${i}`, value: 'yes' }] })),
  }), { message: '200 rules per phase', tests: [] });
  converged(cookie, v);
}

export function direct() {
  check(http.get('http://upstream:8080/api/items'), { 'direct 200': (r) => r.status === 200 });
}

let n = 0;
export function viaEdge() {
  check(http.get(`${pick(edges)}/api/items`, { headers: viewer(__VU * 100000 + n++) }), { 'edge 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  return { stdout: '\n200 rules per phase' + latencyReport(data, 'direct', 'edge') + thresholdReport(data) };
}
