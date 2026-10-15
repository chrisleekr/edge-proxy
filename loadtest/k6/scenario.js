// Capacity scenario: one edge at a fixed rate with traffic shaped
// like a public API, checked against a p99 budget. loadtest/scenario.sh runs
// it once per step and adds CPU and Valkey figures. PUBLISH=1 installs the
// scenario policy first.
//
// Mix: 50% /api/ (site-wide + api rule), 45% pages (site-wide only),
// 5% /login (site-wide + login rule): 1.55 rate-limit rules per request.
// Limits are far above any one client's share, so nothing is limited and
// every matched rule costs a Valkey call.
import http from 'k6/http';
import { check } from 'k6';
import { session, publish, converged } from './admin.js';
import { path, rule, viewer } from './lib.js';

const rate = Number(__ENV.RATE || 500);
const budget = Number(__ENV.BUDGET_MS || 10);
const ips = Number(__ENV.IPS || 100000);
const seconds = parseInt(__ENV.DURATION || '30s', 10);

export const options = {
  setupTimeout: '120s',
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    load: { executor: 'constant-arrival-rate', exec: 'hit', rate, timeUnit: '1s', duration: __ENV.DURATION || '30s', preAllocatedVUs: 100, maxVUs: 2000 },
  },
  thresholds: {
    'http_req_duration{scenario:load}': [`p(99)<${budget}`],
    'http_req_failed{scenario:load}': ['rate<0.001'],
    // Under 1% of the run's iterations may start late (the load generator
    // shares the machine).
    'dropped_iterations{scenario:load}': [`count<${Math.ceil(rate * seconds * 0.01)}`],
    'http_reqs{scenario:load}': ['count>=0'],
  },
};

export function setup() {
  if (__ENV.PUBLISH !== '1') return;
  const cookie = session();
  const v = publish(cookie, (c) => ({
    ...c,
    rate_limit_rules: [
      rule('all-per-ip', { combinator: 'and', rules: [] }, { algorithm: 'sliding_window', limit: 6000, period: '1m' }),
      rule('api-per-ip', path('starts_with', '/api/'), { algorithm: 'token_bucket', limit: 100, period: '1s', burst: 200 }),
      rule('login', path('eq', '/login'), { algorithm: 'sliding_window', limit: 100, period: '1m' }),
    ],
  }), { message: 'capacity scenario', tests: [] });
  converged(cookie, v);
}

const paths = ['/api/items', '/pages/home', '/login'];
export function hit() {
  const r = Math.random();
  const p = r < 0.5 ? paths[0] : r < 0.95 ? paths[1] : paths[2];
  const res = http.get(`http://edge-1:8080${p}`, { headers: viewer(Math.floor(Math.random() * ips)) });
  check(res, { 'not limited or failed': (x) => x.status === 200 });
}

export function handleSummary(data) {
  const m = (n) => data.metrics[`${n}{scenario:load}`]?.values ?? {};
  const d = m('http_req_duration');
  const ok = Object.values(data.metrics).every((x) => Object.values(x.thresholds ?? {}).every((t) => t.ok));
  // One machine-readable line: rate achieved p50 p99 error% dropped verdict.
  return { stdout: `RESULT ${rate} ${((m('http_reqs').count ?? 0) / seconds).toFixed(0)} ${d.med?.toFixed(2)} ${d['p(99)']?.toFixed(2)} ${((m('http_req_failed').rate ?? 0) * 100).toFixed(2)} ${m('dropped_iterations').count ?? 0} ${ok ? 'within' : 'OVER'}\n` };
}
