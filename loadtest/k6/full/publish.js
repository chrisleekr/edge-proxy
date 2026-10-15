// Publishing under load: a publish every 10s while traffic
// flows, each reaching every edge; then a 30% canary whose rule marks its
// requests, so the share and per-client stickiness can be checked.
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { call, session, publish, converged } from '../admin.js';
import { edges, path, pick, rule, thresholdReport, viewer, waitReady } from '../lib.js';

const convergence = new Trend('convergence_seconds');
// The share of client IPs in the candidate's cohort.
const share = new Rate('canary_share');

export const options = {
  setupTimeout: '120s',
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    traffic: { executor: 'constant-arrival-rate', exec: 'traffic', rate: 300, timeUnit: '1s', duration: '90s', preAllocatedVUs: 50, maxVUs: 500 },
    publisher: { executor: 'per-vu-iterations', exec: 'publisher', vus: 1, iterations: 1, maxDuration: '90s' },
    canary: { executor: 'constant-arrival-rate', exec: 'canary', rate: 100, timeUnit: '1s', duration: '30s', startTime: '100s', preAllocatedVUs: 20, maxVUs: 200 },
  },
  thresholds: {
    'http_req_duration{scenario:traffic}': ['p(99)<50'],
    'checks{scenario:traffic}': ['rate>0.999'],
    'checks{scenario:canary}': ['rate==1'],
    convergence_seconds: ['max<20'],
    canary_share: ['rate>0.24', 'rate<0.36'],
  },
};

const rules = (limit) => [rule('api-per-ip', path('starts_with', '/api/'), { algorithm: 'token_bucket', limit, period: '1s', burst: limit })];

export function setup() {
  waitReady();
  return { cookie: session() };
}

let n = 0;
export function traffic() {
  check(http.get(`${pick(edges)}/api/items`, { headers: viewer(__VU * 100000 + n++) }), { 'served during publishes': (r) => r.status === 200 });
}

export function publisher(data) {
  for (let i = 0; i < 8; i++) {
    const start = Date.now();
    const v = publish(data.cookie, (c) => ({ ...c, rate_limit_rules: rules(1000 + i), request_header_rules: [] }), { message: `publish ${i} under load`, tests: [] });
    convergence.add(converged(data.cookie, v));
    sleep(Math.max(0, 10 - (Date.now() - start) / 1000));
  }
  const v = publish(data.cookie, (c) => ({
    ...c,
    request_header_rules: [{ id: 'mark-canary', expression: { combinator: 'and', rules: [] }, ops: [{ op: 'set', name: 'X-Canary', value: 'candidate' }] }],
  }), { message: 'canary marks its requests', canary: 30, tests: [] });
  converged(data.cookie, v);
}

export function canary() {
  const ip = Math.floor(Math.random() * 1000);
  const get = () => http.get(`${pick(edges)}/api/items`, { headers: viewer(ip) }).json('canary');
  const first = get();
  check(get(), { 'a client stays in its cohort': (second) => second === first });
  share.add(first === 'candidate');
}

export function teardown(data) {
  call(data.cookie, 'POST', '/api/canary/abort', { reason: 'load test done' }, {}, [204, 409]);
}

export function handleSummary(data) {
  return { stdout: '\nPublishing every 10s, then a 30% canary\n' + thresholdReport(data) };
}
