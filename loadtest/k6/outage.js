// A dependency outage under load. load.sh stops Valkey
// during the run; load-full.sh also stops admin, Postgres or the IdP.
// Requests keep succeeding (rate limits fail open, tokens verify with the
// keys the edge holds) and readiness never reflects dependency health.
import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { edges, pick, thresholdReport, viewer, waitReady } from './lib.js';

const limitedAfter = new Counter('limited_after_recovery');

export const options = {
  insecureSkipTLSVerify: true, // the mock IdP's own CA
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    traffic: { executor: 'constant-arrival-rate', exec: 'traffic', rate: 200, timeUnit: '1s', duration: '70s', preAllocatedVUs: 50, maxVUs: 500 },
    authed: { executor: 'constant-arrival-rate', exec: 'authed', rate: 20, timeUnit: '1s', duration: '70s', preAllocatedVUs: 10 },
    readiness: { executor: 'constant-arrival-rate', exec: 'readiness', rate: 3, timeUnit: '1s', duration: '70s', preAllocatedVUs: 5 },
    // Valkey is back by 40s; a fresh client over its login limit must be
    // limited again, so enforcement resumed rather than staying open.
    recovered: { executor: 'constant-arrival-rate', exec: 'recovered', rate: 15, timeUnit: '1s', startTime: '52s', duration: '15s', preAllocatedVUs: 10 },
  },
  thresholds: {
    'checks{scenario:traffic}': ['rate>0.999'],
    'checks{scenario:readiness}': ['rate==1'],
    'checks{scenario:authed}': ['rate>0.999'],
    // 225 logins against 100 per minute.
    limited_after_recovery: ['count>50'],
    // The breaker bounds how long requests wait on a dead Valkey.
    'http_req_duration{scenario:traffic}': ['p(99)<200'],
  },
};

export function setup() {
  waitReady();
  return { token: http.get('https://idp:8443/token?sub=outage-user').body };
}

export function authed(data) {
  const r = http.get(`${pick(edges)}/private/profile`, { headers: { ...viewer(n++), Authorization: `Bearer ${data.token}` } });
  check(r, { 'token verified without the IdP': (r) => r.status === 200 && r.json('sub') === 'outage-user' });
}

let n = 0;
export function traffic() {
  check(http.get(`${pick(edges)}/api/items`, { headers: viewer(__VU * 100000 + n++) }), { 'served while Valkey is down': (r) => r.status === 200 });
}

let e = 0;
export function readiness() {
  const url = edges[e++ % edges.length].replace(':8080', ':9090') + '/readyz';
  check(http.get(url), { 'stays ready': (r) => r.status === 200 });
}

export function recovered() {
  const r = http.post(`${pick(edges)}/login`, null, {
    headers: { Host: 'api.example.com', 'CloudFront-Viewer-Address': '192.0.2.88:443' },
    responseCallback: http.expectedStatuses(200, 429),
  });
  if (r.status === 429) limitedAfter.add(1);
}

export function handleSummary(data) {
  const report = thresholdReport(data);
  return { stdout: report};
}
