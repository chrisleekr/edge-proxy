// Maximum capacity: one fixed rate against one edge, with traffic shaped
// like a public site in front of four microservices.
// scripts/capacity-max.sh runs it once per step and decides pass or fail.
//
// The services report their own time in Server-Timing, so edge_added is
// what the edge adds to each request: total time minus the service's time.
// Requests the edge answers itself (429, 401, preflight) have no service
// time and go to edge_answer instead, except the timeout route, whose 504
// takes its 1s timeout by design. One iteration in twenty also calls
// the gateway behind the edge directly: network_floor is the same
// subtraction without the edge, the network and gateway cost any setup pays. PUBLISH=1 installs the policy first.
import http from 'k6/http';
import { Counter, Rate, Trend } from 'k6/metrics';
import { sleep } from 'k6';
import { session, publish, converged } from './admin.js';
import { path, rule, viewer } from './lib.js';

const rate = Number(__ENV.RATE || 1000);
const ips = Number(__ENV.IPS || 100000);
const edge = 'http://edge-1:8080';

const languages = ['fr-FR,fr;q=0.9', 'de', 'ko-KR', 'en-GB', 'ja', 'en-US,en;q=0.8'];
const pick = (list) => list[Math.floor(Math.random() * list.length)];
const client = () => viewer(Math.floor(Math.random() * ips));
const abuser = () => viewer(ips + Math.floor(Math.random() * 20)); // 20 IPs outside the normal pool
const order = 'x'.repeat(64 << 10);

// One signed-in user per VU, reusing its token as a browser would; a fresh
// token now and then makes the edge verify a signature.
let token;
const idp = (sub) => http.get(`https://idp:8443/token?sub=${sub}`, { responseType: 'text', tags: { kind: 'idp' } }).body;
const bearer = () => ({ Authorization: `Bearer ${(token ??= idp(`user-${__VU}`))}` });
let fresh = 0;

// Each entry: [weight, kind, expected statuses, request]. Weights sum to 100.
const mix = [
  [38.9, 'items', [200], () => http.get(`${edge}/api/items`, { headers: { ...client(), Origin: 'https://app.example.com' } })],
  [10, 'fast', [200], () => http.get(`${edge}/api/fast`, { headers: client() })],
  [2, 'slow', [200], () => http.get(`${edge}/api/slow`, { headers: client() })],
  [15, 'pages', [200], () => http.get(`${edge}/pages/${pick(['home', 'pricing', 'docs', 'blog'])}`, { headers: { ...client(), 'Accept-Language': pick(languages) } })],
  [10, 'static', [200], () => http.get(`${edge}/static/${pick(['app.js', 'app.css', 'hero.webp'])}`, { headers: client() })],
  [5, 'orders', [201], () => http.post(`${edge}/api/orders`, order.slice(0, 1024 + Math.floor(Math.random() * (63 << 10))), { headers: { ...client(), 'Content-Type': 'application/json' } })],
  [3, 'flaky', [200, 503], () => http.get(`${edge}/api/flaky`, { headers: client() })],
  [0.1, 'timeout', [504], () => http.get(`${edge}/api/timeout`, { headers: client() })],
  [3, 'login', [200], () => http.post(`${edge}/login`, 'user=demo&password=x', { headers: client() })],
  [9, 'private', [200], () => http.get(`${edge}/private/me`, { headers: { ...client(), ...bearer() } })],
  [0.5, 'fresh-token', [200], () => http.get(`${edge}/private/me`, { headers: { ...client(), Authorization: `Bearer ${idp(`fresh-${__VU}-${fresh++}`)}` } })],
  [0.5, 'no-token', [401], () => http.get(`${edge}/private/me`, { headers: client() })],
  [1, 'preflight', [204], () => http.options(`${edge}/api/items`, null, { headers: { ...client(), Origin: 'https://app.example.com', 'Access-Control-Request-Method': 'POST' } })],
  [2, 'abuse', [200, 429], () => http.post(`${edge}/login`, 'user=admin&password=guess', { headers: abuser() })],
];
const total = mix.reduce((n, [w]) => n + w, 0);
const kinds = mix.map(([, k]) => k);

const added = new Trend('edge_added', true);
const answered = new Trend('edge_answer', true);
const unexpected = new Rate('unexpected');
const sent = new Counter('sent');
const floor = new Trend('network_floor', true);
const serviceTime = (res) => /app;dur=([0-9.]+)/.exec(res.headers['Server-Timing'] || '');

export const options = {
  setupTimeout: '180s',
  insecureSkipTLSVerify: true, // the mock IdP's own CA
  discardResponseBodies: true,
  summaryTrendStats: ['med', 'p(99)', 'max'],
  scenarios: {
    load: {
      executor: 'constant-arrival-rate', exec: 'hit', rate, timeUnit: '1s', duration: __ENV.DURATION || '60s',
      preAllocatedVUs: Math.min(Math.max(Math.ceil(rate / 5), 200), 3000), maxVUs: 8000,
    },
  },
  // Thresholds that always pass, so the summary keeps each kind's figures.
  thresholds: Object.fromEntries(kinds.flatMap((k) => [[`edge_added{kind:${k}}`, ['p(99)>=0']], [`unexpected{kind:${k}}`, ['rate>=0']]])),
};

export function setup() {
  for (let i = 0; http.get('http://edge-1:9090/readyz').status !== 200; i++) {
    if (i > 60) throw new Error(`${edge} not ready`);
    sleep(1);
  }
  if (__ENV.PUBLISH !== '1') return;
  const cookie = session();
  const v = publish(cookie, (c) => ({
    ...c,
    global: {
      ...c.global,
      locale: { supported: ['en', 'fr', 'de', 'ko', 'ja'], default: 'en', output_header: 'X-Edge-Locale' },
      cors_policies: {
        'web-app': { origins: ['https://app.example.com'], methods: ['GET', 'POST'], request_headers: ['Authorization', 'Content-Type'], exposed_headers: ['RateLimit', 'RateLimit-Policy'], credentials: true, max_age: '10m' },
      },
    },
    config_rules: [
      { id: 'private-needs-auth', expression: path('starts_with', '/private/'), settings: { auth: { mode: 'required' } } },
      { id: 'api-cors', expression: path('starts_with', '/api/'), settings: { cors_policy: 'web-app', ratelimit_headers: true } },
      { id: 'timeout-fast', expression: path('eq', '/api/timeout'), settings: { upstream_timeout: '1s' } },
      { id: 'pages-locale', expression: path('starts_with', '/pages/'), settings: { locale: true } },
    ],
    rate_limit_rules: [
      rule('site-per-ip', { combinator: 'and', rules: [] }, { algorithm: 'sliding_window', limit: 6000, period: '1m' }),
      rule('api-per-ip', path('starts_with', '/api/'), { algorithm: 'token_bucket', limit: 100, period: '1s', burst: 200 }),
      rule('login-per-ip', path('eq', '/login'), { algorithm: 'sliding_window', limit: 20, period: '1m', penalty: '5m' }),
      rule('pages-per-ip', path('starts_with', '/pages/'), { algorithm: 'fixed_window', limit: 1000, period: '1m', fail_mode: 'local' }),
      rule('private-per-user', path('starts_with', '/private/'), { key: ['jwt_claim:sub'], on_missing_key: 'skip', algorithm: 'leaky_bucket', limit: 600, period: '1m', burst: 60 }),
    ],
    request_header_rules: [
      { id: 'tag-service', expression: path('starts_with', '/api/'), ops: [{ op: 'set', name: 'X-Service', value: 'api' }] },
      { id: 'drop-debug', expression: { combinator: 'and', rules: [] }, ops: [{ op: 'remove', name: 'X-Debug' }] },
    ],
  }), { message: 'capacity max', tests: [] });
  converged(cookie, v);
}

export function hit() {
  let r = Math.random() * total;
  let i = 0;
  while ((r -= mix[i][0]) >= 0 && i < mix.length - 1) i++;
  const [, kind, want, send] = mix[i];
  const res = send();
  sent.add(1);
  const tags = { kind };
  unexpected.add(!want.includes(res.status), tags);
  const m = serviceTime(res);
  if (m) added.add(res.timings.duration - Number(m[1]), tags);
  else if (res.status !== 0 && kind !== 'timeout') answered.add(res.timings.duration, tags);
  if (Math.random() < 0.05) {
    const d = http.get('http://gateway:8080/api/fast', { tags: { kind: 'direct' } });
    const dm = serviceTime(d);
    if (dm) floor.add(d.timings.duration - Number(dm[1]));
  }
}

export function handleSummary(data) {
  const v = (n) => data.metrics[n]?.values ?? {};
  const secs = parseInt(__ENV.DURATION || '60s', 10);
  const a = v('edge_added');
  const f = (x) => (x === undefined ? 'n/a' : x.toFixed(2));
  const n = v('network_floor');
  // target achieved added_p50 added_p99 answer_p99 unexpected% dropped floor_p50 floor_p99
  const lines = [`RESULT ${rate} ${Math.round((v('sent').count ?? 0) / secs)} ${f(a.med)} ${f(a['p(99)'])} ${f(v('edge_answer')['p(99)'])} ${((v('unexpected').rate ?? 0) * 100).toFixed(3)} ${v('dropped_iterations').count ?? 0} ${f(n.med)} ${f(n['p(99)'])}`];
  for (const k of kinds) {
    const ka = v(`edge_added{kind:${k}}`);
    const ku = v(`unexpected{kind:${k}}`);
    lines.push(`KIND ${k} ${f(ka.med)} ${f(ka['p(99)'])} ${((ku.rate ?? 0) * 100).toFixed(2)}`);
  }
  return { stdout: lines.join('\n') + '\n' };
}
