// Tier 1 smoke: edge overhead against the upstream directly,
// one shared login quota across three edges, and JWT auth end to end.
// Latency thresholds are conservative defaults until the capacity inputs
// set the budget.
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { edges, latencyReport, pick, thresholdReport, viewer, waitReady } from './lib.js';

const allowed = new Counter('login_allowed');
const limited = new Counter('login_limited');

const rate = Number(__ENV.RATE || 300);
const steady = (exec, r, duration) => ({ executor: 'constant-arrival-rate', exec, rate: r, timeUnit: '1s', duration, preAllocatedVUs: 50, maxVUs: 500 });

export const options = {
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  insecureSkipTLSVerify: true, // the mock IdP's own CA
  scenarios: {
    direct: steady('direct', rate, '60s'),
    edge: steady('viaEdge', rate, '60s'),
    login: steady('login', 10, '40s'),
    auth: steady('auth', 20, '40s'),
  },
  thresholds: {
    'http_req_failed{scenario:edge}': ['rate<0.001'],
    'http_req_duration{scenario:edge}': ['p(99)<50'],
    'http_req_duration{scenario:direct}': ['p(99)<50'],
    checks: ['rate>0.999'],
    // 100 per minute per IP, shared by three edges. 40s at 10/s spans at
    // most two windows of the sliding window: at least 100, under 200.
    // Three separate counters would allow 300.
    login_allowed: ['count>=95', 'count<200'],
  },
};

export function setup() {
  waitReady();
  const tokens = [];
  for (let i = 0; i < 20; i++) tokens.push({ sub: `user-${i}`, token: http.get(`https://idp:8443/token?sub=user-${i}`).body });
  return { tokens };
}

export function direct() {
  check(http.get('http://upstream:8080/api/items'), { 'direct 200': (r) => r.status === 200 });
}

let n = 0;
export function viaEdge() {
  const r = http.get(`${pick(edges)}/api/items`, { headers: viewer(__VU * 100000 + n++) });
  check(r, { 'edge 200': (r) => r.status === 200 });
}

export function login() {
  const r = http.post(`${pick(edges)}/login`, null, {
    headers: { Host: 'api.example.com', 'CloudFront-Viewer-Address': '192.0.2.77:443' },
    responseCallback: http.expectedStatuses(200, 429),
  });
  check(r, { 'login 200 or 429': (r) => r.status === 200 || r.status === 429 });
  (r.status === 200 ? allowed : limited).add(1);
}

export function auth(data) {
  const t = pick(data.tokens);
  const e = pick(edges);
  const ok = http.get(`${e}/private/profile`, { headers: { ...viewer(n++), Authorization: `Bearer ${t.token}` } });
  check(ok, { 'token accepted and subject forwarded': (r) => r.status === 200 && r.json('sub') === t.sub });
  const no = http.get(`${e}/private/profile`, { headers: viewer(n++), responseCallback: http.expectedStatuses(401) });
  check(no, { 'no token is 401 with a challenge': (r) => r.status === 401 && r.headers['Www-Authenticate'] === 'Bearer' });
}

export function handleSummary(data) {
  const report = latencyReport(data, 'direct', 'edge') + thresholdReport(data);
  return { stdout: report };
}
