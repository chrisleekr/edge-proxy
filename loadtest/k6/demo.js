// Demo traffic for `make demo-traffic`: a weighted mix that exercises every
// part of the demo policy, so each shows up on the admin dashboard and the
// Stats page. Not a test: nothing is asserted. RATE requests per second,
// for DURATION (default 24h; stop it with Ctrl+C).
//
// Clients come from a small pool of IPs (IPS, default 300), so the per-IP
// limits really bite: api-burst blocks, api-shadow would block, and
// login-per-ip blocks and holds its penalty.
import http from 'k6/http';
import { viewer } from './lib.js';

const rate = Number(__ENV.RATE || 200);
const ips = Number(__ENV.IPS || 300);
const edge = 'http://edge-1:8080';

export const options = {
  insecureSkipTLSVerify: true, // the mock IdP's own CA
  scenarios: {
    demo: { executor: 'constant-arrival-rate', exec: 'traffic', rate, timeUnit: '1s', duration: __ENV.DURATION || '24h', preAllocatedVUs: 50, maxVUs: 1000 },
  },
};

// Tokens last an hour; each VU fetches its own and renews it every 30
// minutes, so a long run never turns into auth failures.
const tokens = {};
function token(kind) {
  const t = tokens[kind];
  if (t && Date.now() - t.at < 30 * 60 * 1000) return t.value;
  const sub = `${kind}-${__VU}`;
  const q = kind === 'partner' ? `sub=${sub}&iss=https://idp/partner&aud=partner` : `sub=${sub}`;
  const value = http.get(`https://idp:8443/token?${q}`, { tags: { name: 'idp' } }).body;
  tokens[kind] = { value, at: Date.now() };
  return value;
}

const client = () => viewer(Math.floor(Math.random() * ips));
const languages = ['fr-FR,fr;q=0.9', 'de', 'ko-KR', 'en-GB', 'ja'];
const pick = (list) => list[Math.floor(Math.random() * list.length)];
// Built once per VU: a body over the default 1 MiB limit, and an upload
// that the uploads rule allows.
const tooLarge = 'x'.repeat(1_100_000);
const upload = 'x'.repeat(2_000_000);

// Each entry is [weight, what it shows, request]. Weights sum to 100.
const mix = [
  [34, 'pages: locale, fixed window', () => http.get(`${edge}/pages/${pick(['home', 'pricing', 'docs'])}`, { headers: { ...client(), 'Accept-Language': pick(languages) } })],
  [25, 'anonymous API: token bucket blocks, log only would block', () => http.get(`${edge}/api/items`, { headers: client() })],
  [12, 'signed-in API: per-user leaky bucket', () => http.get(`${edge}/api/orders`, { headers: { ...client(), Authorization: `Bearer ${token('user')}` } })],
  [4, 'public catalog: open CORS', () => http.get(`${edge}/api/catalog/books`, { headers: { ...client(), Origin: 'https://shop.example.net' } })],
  [3, 'CORS preflight from the web app', () => http.options(`${edge}/api/items`, null, { headers: { ...client(), Origin: 'https://app.example.com', 'Access-Control-Request-Method': 'PUT' } })],
  [1, 'CORS preflight from an unknown origin', () => http.options(`${edge}/api/items`, null, { headers: { ...client(), Origin: 'https://evil.example', 'Access-Control-Request-Method': 'DELETE' } })],
  // Ten IPs share the logins, so the 2 per minute limit and its penalty show.
  [5, 'login: sliding window with penalty', () => http.post(`${edge}/login`, 'user=demo', { headers: viewer(Math.floor(Math.random() * 10)) })],
  [3, 'private page without a token: 401', () => http.get(`${edge}/private/account`, { headers: client() })],
  [2, 'private page with a token', () => http.get(`${edge}/private/account`, { headers: { ...client(), Authorization: `Bearer ${token('user')}` } })],
  [2, 'partner API: API key and partner issuer', () => http.get(`${edge}/api/partner/orders`, { headers: { ...client(), Authorization: `Bearer ${token('partner')}`, 'X-Api-Key': `key-${__VU % 5}` } })],
  // Rate limits read the client's own X-Api-Key before header rules run, so
  // the legacy header alone is refused; sent beside it, the rename shows.
  [1, 'partner API with the legacy key header too, renamed', () => http.get(`${edge}/api/partner/orders`, { headers: { ...client(), Authorization: `Bearer ${token('partner')}`, 'X-Api-Key': `key-${__VU % 5}`, 'X-Legacy-Key': 'key-legacy' } })],
  [1, 'partner API without a key: rejected', () => http.get(`${edge}/api/partner/orders`, { headers: { ...client(), Authorization: `Bearer ${token('partner')}` } })],
  [2, 'bad token: auth failure', () => http.get(`${edge}/api/orders`, { headers: { ...client(), Authorization: 'Bearer not-a-real-token' } })],
  [2, 'upstream errors', () => http.get(`${edge}/api/items?status=${pick([500, 502, 503])}`, { headers: client() })],
  [1, 'slow upstream', () => http.get(`${edge}/api/items?latency=300ms`, { headers: { ...client(), 'X-Debug': '1' } })],
  [1, 'body over the default limit: 413', () => http.post(`${edge}/api/items`, tooLarge, { headers: client() })],
  [1, 'upload under its raised limit', () => http.post(`${edge}/api/upload`, upload, { headers: client() })],
];
const total = mix.reduce((n, [w]) => n + w, 0);

export function traffic() {
  let r = Math.random() * total;
  for (const [w, , send] of mix) {
    if ((r -= w) < 0) return send();
  }
}
