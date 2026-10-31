// Shared helpers for the load scenarios.
import http from 'k6/http';
import { sleep } from 'k6';

export const edges = ['http://edge-1:8080', 'http://edge-2:8080', 'http://edge-3:8080'];

// waitReady polls each edge's /readyz, so a run never measures start-up.
export function waitReady() {
  for (const e of edges) {
    const ready = e.replace(':8080', ':9090') + '/readyz';
    for (let i = 0; http.get(ready).status !== 200; i++) {
      if (i > 60) throw new Error(`${ready} not ready`);
      sleep(1);
    }
  }
}

// viewer is the header CloudFront would add for a client: n maps to one of
// 16.7M distinct addresses in 20.0.0.0/8, so a run can use a million IPs.
// asn adds the client's AS number, as CloudFront-Viewer-ASN.
export function viewer(n, asn) {
  const i = n % 16777216;
  const h = { Host: 'api.example.com', 'CloudFront-Viewer-Address': `20.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}:443` };
  if (asn !== undefined) h['CloudFront-Viewer-ASN'] = String(asn);
  return h;
}

// path builds the stored AST for a single path condition.
export const path = (operator, value) => ({ combinator: 'and', rules: [{ field: 'http.request.uri.path', operator, value }] });

// rule is a rate-limit rule keyed on the client IP with the defaults the
// scenarios share; extra sets the algorithm and limits.
export const rule = (id, expression, extra) => ({ id, expression, key: ['ip'], on_missing_key: 'fallback_ip', action: 'block', fail_mode: 'open', ...extra });

export const pick = (list) => list[Math.floor(Math.random() * list.length)];

const ms = (v) => (v === undefined ? 'n/a' : `${v.toFixed(2)} ms`);

// latencyReport prints direct vs through-edge percentiles and their gap.
export function latencyReport(data, a, b) {
  const m = (s) => data.metrics[`http_req_duration{scenario:${s}}`]?.values ?? {};
  const da = m(a);
  const db = m(b);
  const lines = ['', 'Latency            p50        p95        p99'];
  for (const [name, v] of [[a, da], [b, db]]) lines.push(`${name.padEnd(12)} ${ms(v.med).padStart(10)} ${ms(v['p(95)']).padStart(10)} ${ms(v['p(99)']).padStart(10)}`);
  lines.push(`added by edge ${ms(db.med - da.med).padStart(9)} ${ms(db['p(95)'] - da['p(95)']).padStart(10)} ${ms(db['p(99)'] - da['p(99)']).padStart(10)}`);
  return lines.join('\n') + '\n';
}

// thresholdReport lists every threshold with pass or fail.
export function thresholdReport(data) {
  const lines = ['', 'Thresholds'];
  for (const [name, m] of Object.entries(data.metrics)) {
    for (const [expr, t] of Object.entries(m.thresholds ?? {})) {
      const v = m.values;
      const shown = v.count ?? v.rate ?? v['p(99)'];
      lines.push(`${t.ok ? 'pass' : 'FAIL'}  ${name} ${expr}  (${typeof shown === 'number' ? shown.toFixed(3) : shown})`);
    }
  }
  return lines.join('\n') + '\n';
}
