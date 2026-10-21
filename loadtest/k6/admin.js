// Admin API helpers for scenarios that change policy under load. Sessions
// use a Secure cookie, which k6's jar won't send over this plain internal
// hop, so the Cookie header is set explicitly.
import http from 'k6/http';
import { sleep } from 'k6';

const ADMIN = 'http://admin:8081';
const json = { 'Content-Type': 'application/json' };

export function session() {
  const r = http.post(`${ADMIN}/api/auth/login`, JSON.stringify({ username: 'admin', password: 'local-dev-login' }), { headers: json, responseType: 'text' });
  const c = r.cookies['__Host-edge_session'];
  if (!c) throw new Error(`admin login failed: ${r.status} ${r.body}`);
  return `__Host-edge_session=${c[0].value}`;
}

export function call(cookie, method, path, body, headers = {}, want = [200, 201, 204]) {
  // responseType keeps the body for scripts that discard response bodies.
  const r = http.request(method, `${ADMIN}${path}`, body === undefined ? null : JSON.stringify(body), { headers: { ...json, Cookie: cookie, ...headers }, responseType: 'text' });
  if (!want.includes(r.status)) throw new Error(`${method} ${path}: ${r.status} ${r.body}`);
  return r;
}

// publish saves mutate(draft config) and publishes it; returns the version.
// Load tests limit traffic on purpose, which the rollback guard would read
// as a bad publish, so each publish turns the guard off for itself with a
// reason, unless opts.guard asks for the guard.
export function publish(cookie, mutate, opts = {}) {
  let d = call(cookie, 'GET', '/api/draft').json();
  if (d.base_version !== null && d.base_version !== activeVersion(cookie)) {
    // A version replaced the draft's base meanwhile; take it in first.
    call(cookie, 'POST', '/api/draft/rebase', undefined, { 'If-Match': `"${d.revision}"` });
    d = call(cookie, 'GET', '/api/draft').json();
  }
  const saved = call(cookie, 'PUT', '/api/draft', { config: mutate(d.config), tests: opts.tests ?? d.tests }, { 'If-Match': `"${d.revision}"` });
  const guard = opts.guard
    ? {}
    : { guard_override: { ...call(cookie, 'GET', '/api/settings/guard').json(), enabled: false }, guard_override_reason: 'load test limits traffic on purpose' };
  const p = call(cookie, 'POST', '/api/publish', { message: opts.message ?? 'load test', canary_percent: opts.canary ?? 0, ...guard }, { 'If-Match': `"${saved.json('revision')}"` });
  return p.json('version');
}

const activeVersion = (cookie) => call(cookie, 'GET', '/api/versions').json().find((v) => v.status === 'active')?.version ?? null;

// converged waits until every live edge reports version, and returns the
// seconds it took (edges poll every 5s and report every 5s).
export function converged(cookie, version, timeout = 60) {
  const start = Date.now();
  for (;;) {
    const fleet = call(cookie, 'GET', '/api/fleet').json().filter((e) => e.live);
    if (fleet.length > 0 && fleet.every((e) => e.versions.includes(version))) return (Date.now() - start) / 1000;
    if (Date.now() - start > timeout * 1000) throw new Error(`version ${version} not on every edge after ${timeout}s`);
    sleep(0.5);
  }
}
