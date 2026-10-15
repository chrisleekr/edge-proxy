import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../api';
import { Badge, Card, ErrorBox, Page, Table, when } from '../ui';

interface Edge {
  instance: string;
  last_seen: string;
  config_source: string;
  bootstrap_age_seconds: number;
  versions: number[];
  live: boolean;
}

export function Fleet() {
  const q = useQuery({ queryKey: ['fleet'], queryFn: () => api<Edge[]>('GET', '/api/fleet'), refetchInterval: 15_000 });
  return (
    <Page title="Fleet">
      <ErrorBox error={q.error} />
      <Table head={['Edge', 'State', 'Versions loaded', 'Config from', 'Last report']}>
        {q.data?.map((e) => (
          <tr key={e.instance}>
            <td className="px-3 py-2 font-mono">{e.instance}</td>
            <td className="px-3 py-2">
              <Badge tone={e.live ? 'green' : 'slate'}>{e.live ? 'live' : 'gone'}</Badge>
            </td>
            <td className="px-3 py-2">{e.versions.join(', ')}</td>
            <td className="px-3 py-2">
              {e.config_source}
              {e.config_source === 'bootstrap' && ` (${Math.round(e.bootstrap_age_seconds / 3600)}h old)`}
            </td>
            <td className="px-3 py-2">{when(e.last_seen)}</td>
          </tr>
        ))}
      </Table>
    </Page>
  );
}

interface Row {
  minute: string;
  version: number;
  requests: number;
  edge_5xx: number;
  upstream_5xx: number;
  auth_failures: number;
  rate_limit_rules: { id: string; evaluated: number; limited: number; would_limit: number; failed: number }[] | null;
  top_limited: { rule: string; key: string; display: string; limited: number }[] | null;
}

const sum = (rows: Row[], f: (r: Row) => number) => rows.reduce((n, r) => n + f(r), 0);
const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(2)}%` : '—');

// Bars draws requests per minute; a chart library is not needed for one series.
function Bars({ rows }: { rows: Row[] }) {
  const byMinute = new Map<string, number>();
  for (const r of rows) byMinute.set(r.minute, (byMinute.get(r.minute) ?? 0) + r.requests);
  const points = [...byMinute.entries()];
  const max = Math.max(1, ...points.map(([, n]) => n));
  const w = 600;
  const bw = w / Math.max(1, points.length);
  return (
    <svg viewBox={`0 0 ${w} 120`} className="h-32 w-full" role="img" aria-label="Requests per minute">
      {points.map(([m, n], i) => (
        <rect key={m} x={i * bw} y={120 - (110 * n) / max} width={Math.max(1, bw - 1)} height={(110 * n) / max} className="fill-slate-700">
          <title>
            {new Date(m).toLocaleTimeString()}: {n} requests
          </title>
        </rect>
      ))}
    </svg>
  );
}

export function Stats() {
  const [minutes, setMinutes] = useState(60);
  const q = useQuery({ queryKey: ['stats', minutes], queryFn: () => api<Row[]>('GET', `/api/stats?minutes=${minutes}`), refetchInterval: 60_000 });
  const rows = q.data ?? [];
  const versions = [...new Set(rows.map((r) => r.version))];
  const rules = new Map<string, NonNullable<Row['rate_limit_rules']>[number]>();
  const top = new Map<string, NonNullable<Row['top_limited']>[number]>();
  for (const r of rows) {
    for (const c of r.rate_limit_rules ?? []) {
      const t = rules.get(c.id) ?? { id: c.id, evaluated: 0, limited: 0, would_limit: 0, failed: 0 };
      for (const k of ['evaluated', 'limited', 'would_limit', 'failed'] as const) t[k] += c[k];
      rules.set(c.id, t);
    }
    for (const t of r.top_limited ?? []) {
      const e = top.get(t.rule + t.key) ?? { ...t, limited: 0 };
      e.limited += t.limited;
      top.set(t.rule + t.key, e);
    }
  }
  return (
    <Page
      title="Stats"
      actions={
        <select aria-label="Time range" className="rounded border border-slate-300 px-2 py-1 text-sm" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
          <option value={60}>Last hour</option>
          <option value={360}>Last 6 hours</option>
          <option value={1440}>Last day</option>
          <option value={10080}>Last week</option>
        </select>
      }
    >
      <ErrorBox error={q.error} />
      <Card title="Requests per minute">
        <Bars rows={rows} />
      </Card>
      <Table head={['Version', 'Requests', 'Edge 5xx', 'Upstream 5xx', 'Auth failures']}>
        {versions.map((v) => {
          const vr = rows.filter((r) => r.version === v);
          const n = sum(vr, (r) => r.requests);
          return (
            <tr key={v}>
              <td className="px-3 py-2">{v}</td>
              <td className="px-3 py-2">{n}</td>
              <td className="px-3 py-2">{pct(sum(vr, (r) => r.edge_5xx), n)}</td>
              <td className="px-3 py-2">{pct(sum(vr, (r) => r.upstream_5xx), n)}</td>
              <td className="px-3 py-2">{pct(sum(vr, (r) => r.auth_failures), n)}</td>
            </tr>
          );
        })}
      </Table>
      <Table head={['Rate limit rule', 'Evaluated', 'Limited', 'Would limit (shadow)', 'Failed']}>
        {[...rules.values()].map((r) => (
          <tr key={r.id}>
            <td className="px-3 py-2 font-mono">{r.id}</td>
            <td className="px-3 py-2">{r.evaluated}</td>
            <td className="px-3 py-2">{r.limited}</td>
            <td className="px-3 py-2">{r.would_limit}</td>
            <td className="px-3 py-2">{r.failed}</td>
          </tr>
        ))}
      </Table>
      <Table head={['Most limited', 'Rule', 'Limited (estimated)']}>
        {[...top.values()]
          .sort((a, b) => b.limited - a.limited)
          .slice(0, 20)
          .map((t) => (
            <tr key={t.rule + t.key}>
              <td className="px-3 py-2 font-mono">{t.display}</td>
              <td className="px-3 py-2 font-mono">{t.rule}</td>
              <td className="px-3 py-2">{t.limited}</td>
            </tr>
          ))}
      </Table>
    </Page>
  );
}
