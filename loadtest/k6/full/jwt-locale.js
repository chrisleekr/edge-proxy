// JWT cached against uncached, and locale negotiation.
// Cached: 20 tokens reused. Uncached: each of 2000 tokens used once, so
// every request verifies a signature. load-full.sh reads edge_auth_total
// from each edge to report the cache hit rate.
import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import { session, publish, converged } from '../admin.js';
import { edges, path, pick, thresholdReport, viewer, waitReady } from '../lib.js';

const UNCACHED = 2000;
const steady = (fn, rate, duration, startTime = '0s') => ({ executor: 'constant-arrival-rate', exec: fn, rate, timeUnit: '1s', duration, startTime, preAllocatedVUs: 50, maxVUs: 500 });
const languages = ['en-US,en;q=0.9', 'fr-FR,fr;q=0.8,en;q=0.5', 'de', 'ja-JP', 'zh-TW,zh;q=0.9', 'pt-BR', 'es-419,es;q=0.9'];

export const options = {
  setupTimeout: '180s',
  insecureSkipTLSVerify: true,
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    cached: steady('cached', 300, '30s'),
    uncached: { executor: 'shared-iterations', exec: 'uncached', vus: 20, iterations: UNCACHED, startTime: '35s', maxDuration: '60s' },
    locale: steady('locale', 300, '30s', '100s'),
  },
  thresholds: {
    'http_req_duration{scenario:cached}': ['p(99)<50'],
    'http_req_duration{scenario:uncached}': ['p(99)<50'],
    'http_req_duration{scenario:locale}': ['p(99)<50'],
    checks: ['rate>0.999'],
  },
};

export function setup() {
  waitReady();
  const cookie = session();
  const v = publish(cookie, (c) => ({
    ...c,
    global: { ...c.global, locale: { supported: ['en', 'fr', 'de', 'ja', 'zh-Hant', 'pt'], default: 'en', output_header: 'X-Edge-Locale' } },
    config_rules: [
      { id: 'private-needs-auth', expression: path('starts_with', '/private/'), settings: { auth: { mode: 'required' } } },
      { id: 'pages-localized', expression: path('starts_with', '/pages/'), settings: { locale: true } },
    ],
    rate_limit_rules: [],
  }), { message: 'jwt and locale', tests: [] });
  converged(cookie, v);
  const token = (i) => http.get(`https://idp:8443/token?sub=user-${i}`).body;
  return { cached: Array.from({ length: 20 }, (_, i) => token(i)), uncached: Array.from({ length: UNCACHED }, (_, i) => token(1000 + i)) };
}

let n = 0;
const authed = (token) => http.get(`${pick(edges)}/private/profile`, { headers: { ...viewer(n++), Authorization: `Bearer ${token}` } });

export function cached(data) {
  check(authed(pick(data.cached)), { 'cached token accepted': (r) => r.status === 200 });
}

export function uncached(data) {
  check(authed(data.uncached[exec.scenario.iterationInTest]), { 'fresh token accepted': (r) => r.status === 200 });
}

export function locale() {
  const r = http.get(`${pick(edges)}/pages/home`, { headers: { ...viewer(n++), 'Accept-Language': pick(languages) } });
  check(r, { 'locale chosen': (r) => r.status === 200 && r.json('locale') !== '' });
}

// teardown prints each edge's verified-token cache counts.
export function teardown() {
  for (const e of edges) {
    const lines = http.get(e.replace(':8080', ':9090') + '/metrics').body.split('\n').filter((l) => l.startsWith('edge_auth_total'));
    console.log(`${e} ${lines.join(' ')}`);
  }
}

export function handleSummary(data) {
  const p99 = (s) => data.metrics[`http_req_duration{scenario:${s}}`]?.values['p(99)']?.toFixed(2);
  return { stdout: `\nJWT p99: cached ${p99('cached')} ms, uncached ${p99('uncached')} ms; locale p99 ${p99('locale')} ms\n` + thresholdReport(data) };
}
