// An over-blocking publish: a canary whose changed rule
// limits nearly every client. The guard must abort it on its own.
import http from 'k6/http';
import { sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { call, session, publish, converged } from '../admin.js';
import { edges, path, pick, rule as limitRule, thresholdReport, viewer, waitReady } from '../lib.js';

const aborted = new Counter('guard_aborted');
const abortedAfter = new Trend('aborted_after_seconds');

export const options = {
  setupTimeout: '120s',
  scenarios: {
    traffic: { executor: 'constant-arrival-rate', exec: 'traffic', rate: 300, timeUnit: '1s', duration: '240s', preAllocatedVUs: 50, maxVUs: 500 },
    watch: { executor: 'per-vu-iterations', exec: 'watch', vus: 1, iterations: 1, maxDuration: '240s' },
  },
  // Stats arrive every 5s, the guard runs every 30s and needs 1000
  // requests per cohort; three minutes is generous.
  thresholds: { guard_aborted: ['count==1'], aborted_after_seconds: ['max<180'] },
};

const rule = (limit, period) => limitRule('api-per-ip', path('starts_with', '/api/'), { algorithm: 'fixed_window', limit, period });

export function setup() {
  waitReady();
  const cookie = session();
  call(cookie, 'PUT', '/api/settings/guard', { ...call(cookie, 'GET', '/api/settings/guard').json(), enabled: true });
  const base = publish(cookie, (c) => ({ ...c, rate_limit_rules: [rule(1000, '1s')], request_header_rules: [] }), { message: 'baseline', tests: [] });
  converged(cookie, base);
  const bad = publish(cookie, (c) => ({ ...c, rate_limit_rules: [rule(1, '1h')] }), { message: 'over-blocking change', canary: 50, tests: [], guard: true });
  converged(cookie, bad);
  return { cookie, bad, started: Date.now() };
}

let n = 0;
export function traffic() {
  // Each client returns a few times, so the candidate's 1/hour limit blocks.
  http.get(`${pick(edges)}/api/items`, { headers: viewer(n++ % 3000), responseCallback: http.expectedStatuses(200, 429) });
}

export function watch(data) {
  for (let i = 0; i < 46; i++) {
    sleep(5);
    if (call(data.cookie, 'GET', '/api/canary').json('canary') === null) {
      const v = call(data.cookie, 'GET', `/api/versions/${data.bad}`).json();
      if (v.status === 'rolled_back') {
        aborted.add(1);
        abortedAfter.add((Date.now() - data.started) / 1000);
      }
      return;
    }
  }
}

export function handleSummary(data) {
  return { stdout: '\nOver-blocking canary, aborted by the guard\n' + thresholdReport(data) };
}
