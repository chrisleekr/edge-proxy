import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Fragment, type PointerEvent, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { api, useCan } from '../api';
import { LogLink, useLogSearch } from '../logSearch';
import { Link, useSearch } from '../router';
import { Badge, Button, Card, ErrorBox, Page, Rolling, Table, Title, ago, when } from '../ui';
import type { Event } from './Audit';
import { useVersions } from './Publish';

export interface Edge {
  instance: string;
  last_seen: string;
  config_source: string;
  bootstrap_age_seconds: number;
  versions: number[];
  upstream: string;
  live: boolean;
}

// useRole names a version's role, so "4, 5" reads as "v4 live, v5 canary".
function useRole() {
  const versions = useVersions();
  return (v: number) => {
    const s = versions.data?.find((x) => x.version === v)?.status;
    return s === 'active' ? `v${v} live` : s === 'canary' ? `v${v} canary` : `v${v}`;
  };
}

export function Fleet() {
  const q = useQuery({ queryKey: ['fleet'], queryFn: () => api<Edge[]>('GET', '/api/fleet'), refetchInterval: 15_000 });
  const role = useRole();
  return (
    <Page
      title="Fleet"
      info="Edges that fetched config from this admin. Live means it reported in the last minute. Versions loaded are the live version and, during a canary, the canary version. Config from says where an edge got the version it serves: admin, its cache file from an earlier run, or the bootstrap file it starts from when admin is unreachable. An edge on cache or bootstrap keeps serving; it switches to admin once it can reach it. Upstream is the edge's UPSTREAM_URL, the load balancer or gateway it forwards every request to. It is set in the edge's deployment, not here."
    >
      <ErrorBox error={q.error} />
      <Table head={['Edge', 'State', 'Versions loaded', 'Upstream', 'Config from', 'Last report']} empty={q.data && 'No edge has reported to this admin yet. Edges report once they fetch a snapshot.'}>
        {q.data?.map((e) => (
          <tr key={e.instance}>
            <td className="font-mono">{e.instance}</td>
            <td>
              <Badge tone={e.live ? 'green' : 'slate'}>{e.live ? 'live' : 'gone'}</Badge>
            </td>
            <td className="tabular-nums">{e.versions.map(role).join(', ')}</td>
            <td className="font-mono break-all">{e.upstream || 'not reported'}</td>
            <td>
              {e.config_source}
              {e.config_source === 'bootstrap' && ` (${Math.round(e.bootstrap_age_seconds / 3600)}h old)`}
            </td>
            <td>
              <time dateTime={e.last_seen} title={when(e.last_seen)}>
                {ago(e.last_seen)}
              </time>
            </td>
          </tr>
        ))}
      </Table>
    </Page>
  );
}

export interface Row {
  minute: string;
  version: number;
  requests: number;
  edge_5xx: number;
  upstream_5xx: number;
  auth_failures: number;
  rate_limit_rules: { id: string; evaluated: number; limited: number; would_limit: number; failed: number }[] | null;
  top_limited: { rule: string; key: string; display: string; limited: number; would_limit?: number }[] | null;
  rules: { phase: string; id: string; matched: number; blocked: number; would_block: number }[] | null;
  // Requests by status code, apart by who answered; codes with none are left out.
  status_codes: { edge?: Record<string, number>; upstream?: Record<string, number> };
  // The edge's upstream failures by cause; causes with none are left out.
  upstream_errors: Record<string, number>;
}

type Origin = 'edge' | 'upstream';

// statusCodes sums rows' status codes, most requests first.
export function statusCodes(rows: Row[]) {
  const m = new Map<string, { code: string; origin: Origin; n: number }>();
  for (const r of rows)
    for (const origin of ['edge', 'upstream'] as const)
      for (const [code, n] of Object.entries(r.status_codes[origin] ?? {})) {
        const e = m.get(origin + code) ?? { code, origin, n: 0 };
        e.n += n;
        m.set(origin + code, e);
      }
  return [...m.values()].sort((a, b) => b.n - a.n || Number(a.code) - Number(b.code));
}

// codeName says what a status slot holds: 0 is a request that got no
// answer, such as a client that left, and 600 any code above 599.
export const codeName = (code: string) => (code === '0' ? 'No answer' : code === '600' ? '600 or above' : code);

// statusOf is a slot's code for a log search: slots 0 and 600 hold no one
// code, so a search by status can't find their lines.
export const statusOf = (code: string) => (code === '0' || code === '600' ? undefined : code);

// causeWords say why the edge got no answer from the upstream.
export const causeWords: Record<string, string> = {
  dns: "The upstream's name did not resolve",
  refused: 'Nothing accepted the connection',
  reset: 'The upstream dropped the connection',
  tls: 'The TLS handshake failed',
  timeout: 'The upstream did not answer in time',
  other: 'Another error',
};
// causeStatus is the code the edge answers a cause with.
export const causeStatus = (cause: string) => (cause === 'timeout' ? '504' : '502');

// causes sums rows' upstream failures by cause, most first.
export function causes(rows: Row[]) {
  const m = new Map<string, number>();
  for (const r of rows) for (const [c, n] of Object.entries(r.upstream_errors ?? {})) m.set(c, (m.get(c) ?? 0) + n);
  return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

export const sum = (rows: Row[], f: (r: Row) => number) => rows.reduce((n, r) => n + f(r), 0);
export const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(2)}%` : '—');
export const count = (n: number) => n.toLocaleString();

// The ranges the time picker offers, by the key the address carries; each
// label finishes "in the …". step is the minutes the API sums into one row,
// so a month is 120 rows, not 43,200.
export const ranges = {
  '1h': { minutes: 60, step: 1, label: 'last hour' },
  '6h': { minutes: 360, step: 2, label: 'last 6 hours' },
  '24h': { minutes: 1440, step: 10, label: 'last 24 hours' },
  '7d': { minutes: 10080, step: 60, label: 'last 7 days' },
  '30d': { minutes: 43200, step: 360, label: 'last 30 days' },
} as const;
export type RangeKey = keyof typeof ranges;

// useRangeKey is the range the address names, 24 hours when it names none.
// Links and navigate carry it on, so it holds across screens.
export function useRangeKey() {
  const [params, set] = useSearch();
  const v = params.get('range') ?? '';
  const key: RangeKey = v in ranges ? (v as RangeKey) : '24h';
  return [key, (k: RangeKey) => set({ range: k === '24h' ? '' : k })] as const;
}

export function RangeSelect({ value, onChange }: { value: RangeKey; onChange: (k: RangeKey) => void }) {
  return (
    <select aria-label="Time range" value={value} onChange={(e) => onChange(e.target.value as RangeKey)}>
      {Object.entries(ranges).map(([k, { label }]) => (
        <option key={k} value={k}>
          {label[0]!.toUpperCase() + label.slice(1)}
        </option>
      ))}
    </select>
  );
}

const minute = 60_000;

// clock formats a chart time, with the date once a range spans days.
export const clock = (t: number, days: boolean) =>
  new Date(t).toLocaleString([], days ? { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' } : { hour: 'numeric', minute: '2-digit' });

// useRange holds the picked range, refetched every 10 seconds up to a day
// and every minute above, and a zoom dragged on the chart. rows are the
// steps inside the window shown.
export function useRange(enabled = true) {
  const [key, setKey] = useRangeKey();
  const { minutes, step, label } = ranges[key];
  // A zoom belongs to the range it was dragged on; another range drops it.
  const [zoomed, setZoomed] = useState<{ key: RangeKey; span: [number, number] } | null>(null);
  const zoom = zoomed?.key === key ? zoomed.span : null;
  const q = useQuery({
    queryKey: ['stats', minutes, step],
    queryFn: () => api<Row[]>('GET', `/api/stats?minutes=${minutes}&step=${step}`),
    refetchInterval: minutes <= 1440 ? 10_000 : 60_000,
    enabled,
  });
  // Before the first fetch, the time the page opened.
  const [opened] = useState(Date.now);
  const now = q.dataUpdatedAt || opened;
  // The window ends after the minute in progress, which admin writes as it
  // grows, and starts on a step, as the API's rows do, so the first is whole.
  const end = Math.floor(now / minute) * minute + minute;
  const start = Math.floor((end - minutes * minute) / (step * minute)) * step * minute;
  const [from, to] = zoom ?? [start, end];
  // Memoized so rows keeps its identity across renders, and the chart's
  // own memo recounts only when the data or the window changes.
  const rows = useMemo(
    () =>
      (q.data ?? []).filter((r) => {
        const t = Date.parse(r.minute);
        return t >= from && t < to;
      }),
    [q.data, from, to],
  );
  const days = to - from >= 1440 * minute;
  return {
    q,
    rows,
    key,
    minutes,
    step,
    label,
    from,
    to,
    now,
    zoom,
    setZoom: (span: [number, number] | null) => setZoomed(span && { key, span }),
    pick: (k: RangeKey) => {
      setKey(k);
      setZoomed(null);
    },
    // title names the window in a heading; phrase finishes a sentence.
    title: zoom ? `${clock(from, days)} to ${clock(to, days)}` : label,
    phrase: zoom ? `between ${clock(from, days)} and ${clock(to, days)}` : `in the ${label}`,
  };
}
export type Range = ReturnType<typeof useRange>;

// RangePicker is the page's time control: the range, and while zoomed a way
// back to it. Live says the figures refresh on their own.
export function RangePicker({ r }: { r: Range }) {
  return (
    <div className="flex items-center gap-3">
      {r.zoom ? (
        <Button onClick={() => r.setZoom(null)}>Reset zoom</Button>
      ) : (
        <span className="eyebrow flex items-center gap-1.5 text-body" title={`Updates every ${r.minutes <= 1440 ? '10 seconds' : 'minute'}`}>
          <span aria-hidden className={`size-1.5 rounded-full ${r.q.error ? 'bg-danger' : 'animate-pulse bg-success motion-reduce:animate-none'}`} />
          {r.q.error ? 'Not updating' : 'Live'}
        </span>
      )}
      <RangeSelect value={r.key} onChange={r.pick} />
    </div>
  );
}

// Bar sizes in minutes; the chart takes the smallest that keeps it to at
// most 180 bars. Stats are stored per minute, so one minute is the finest.
const steps = [1, 2, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440];
const tickSteps = [1, 2, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440, 2880];

// Bars draws requests over the window, stacked into served, rate limited
// and 5xx, so quiet stretches show as gaps and a spike shows what it was.
// Hover a bar for its numbers; drag across bars to zoom in to them. From
// the keyboard, arrows move between bars, Shift+arrows select, Enter zooms
// and Escape cancels; a live region reads out what is under the cursor.
// marks, when given, show releases in a strip above the bars.
export function Bars({ r, marks }: { r: Range; marks?: Mark[] }) {
  const { rows, from, to, now } = r;
  // Sized from the range, not from to - from, which flooring the start to a
  // step can make one step longer. A whole number of the API's steps, so
  // every bar holds the same number of rows.
  const length = r.zoom ? to - from : r.minutes * minute;
  const per = steps.find((s) => s % r.step === 0 && length / minute / s <= 180) ?? 1440;
  const size = per * minute;
  const n = Math.ceil((to - from) / size);
  // Memoized: hover and drag re-render on every pointer move.
  const [buckets, max] = useMemo(() => {
    const buckets = Array.from({ length: n }, (_, i) => ({ t: from + i * size, requests: 0, limited: 0, errors: 0 }));
    for (const row of rows) {
      const b = buckets[Math.floor((Date.parse(row.minute) - from) / size)];
      if (!b) continue;
      b.requests += row.requests;
      b.errors += row.edge_5xx + row.upstream_5xx;
      for (const c of row.rate_limit_rules ?? []) b.limited += c.limited;
    }
    return [buckets, Math.max(1, ...buckets.map((b) => b.requests))] as const;
  }, [rows, from, size, n]);
  const unit = per === 1 ? 'minute' : per < 60 ? `${per} minutes` : per === 60 ? 'hour' : per === 1440 ? 'day' : `${per / 60} hours`;
  const days = to - from >= 1440 * minute;
  const ref = useRef<HTMLDivElement>(null);
  const [cursor, setHover] = useState<number | null>(null);
  // A zoom or a new range changes the bar count; an index from before it
  // points at nothing.
  const hover = cursor !== null && cursor < n ? cursor : null;
  const [drag, setDrag] = useState<[number, number] | null>(null);
  const at = (e: PointerEvent) => {
    const box = ref.current!.getBoundingClientRect();
    return Math.min(n - 1, Math.max(0, Math.floor(((e.clientX - box.left) / box.width) * n)));
  };
  const [byKey, setByKey] = useState(false);
  const [more, setMore] = useState(0);
  const [lo, hi] = drag ? [Math.min(...drag), Math.max(...drag)] : [0, -1];
  const zoomIn = () => {
    // A click is not a zoom; two bars or more is.
    if (drag && hi > lo) {
      r.setZoom([buckets[lo]!.t, buckets[hi]!.t + size]);
      setHover(null);
    }
    setDrag(null);
  };
  // The tooltip shows the selection while one is made, else the bar under
  // the cursor.
  const span = (a: number, b: number) => {
    const bs = buckets.slice(a, b + 1);
    const t = (f: (x: (typeof buckets)[number]) => number) => bs.reduce((n, x) => n + f(x), 0);
    const end = buckets[b]!.t + size;
    return {
      title: `${clock(buckets[a]!.t, days)}${per > 1 || b > a ? ` to ${clock(end, days)}` : ''}${end > now ? ', in progress' : ''}`,
      line: `${count(t((x) => x.requests))} requests · ${count(t((x) => x.limited))} rate limited · ${count(t((x) => x.errors))} 5xx`,
    };
  };
  const anchor = drag && hi > lo ? (lo + hi) / 2 : hover;
  const tip =
    drag && hi > lo
      ? { ...span(lo, hi), hint: byKey ? 'Press Enter to zoom in, Escape to cancel.' : 'Release to zoom in.' }
      : hover !== null && !drag
        ? span(hover, hover)
        : undefined;
  const pctOf = (x: number) => `${(100 * x) / max}%`;
  // Ticks fall on round local times, at most five across the window.
  const every = tickSteps.find((m) => (to - from) / (m * minute) <= 5) ?? 10080;
  const off = -new Date(from).getTimezoneOffset() * minute;
  const ticks: number[] = [];
  for (let t = Math.ceil((from + off) / (every * minute)) * every * minute - off; t <= to; t += every * minute) ticks.push(t);
  return (
    <figure className="flex flex-col gap-2">
      <div className="eyebrow flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-body">
        <span>
          Peak {count(max)} per {unit}
        </span>
        <span className="flex flex-wrap items-center gap-3">
          <Key className="bg-heading/75">Served</Key>
          <Key className="bg-warning">Rate limited</Key>
          <Key className="bg-danger">5xx</Key>
          {!!marks?.length && <MarkKeys more={more} />}
        </span>
      </div>
      {marks && <Markers marks={marks} from={from} to={to} reach="h-[10.5rem]" onMore={setMore} />}
      <div
        ref={ref}
        tabIndex={0}
        role="group"
        aria-roledescription="chart"
        aria-label={`Requests per ${unit}, peak ${count(max)}. Drag across the chart, or use the arrow keys with Shift, to select bars and zoom in.`}
        className="relative flex h-40 cursor-crosshair touch-pan-y items-end gap-px border-t border-b border-line select-none"
        onPointerDown={(e) => {
          e.currentTarget.setPointerCapture(e.pointerId);
          const i = at(e);
          setByKey(false);
          setDrag([i, i]);
        }}
        onPointerMove={(e) => {
          const i = at(e);
          setByKey(false);
          setHover(i);
          if (drag) setDrag([drag[0], i]);
        }}
        onPointerUp={zoomIn}
        // A vertical swipe hands the pointer to page scrolling with no pointerup.
        onPointerCancel={() => setDrag(null)}
        onLostPointerCapture={() => setDrag(null)}
        onPointerLeave={() => !byKey && setHover(null)}
        onFocus={() => {
          setByKey(true);
          setHover((h) => (h !== null && h < n ? h : n - 1));
        }}
        onBlur={() => {
          setHover(null);
          setDrag(null);
        }}
        onKeyDown={(e) => {
          const step = { ArrowLeft: -1, ArrowRight: 1, Home: -n, End: n }[e.key];
          if (step !== undefined) {
            e.preventDefault();
            const cur = hover ?? n - 1;
            const i = Math.min(n - 1, Math.max(0, cur + step));
            setByKey(true);
            setHover(i);
            setDrag(e.shiftKey ? [drag?.[0] ?? cur, i] : null);
          } else if (e.key === 'Enter') {
            e.preventDefault();
            zoomIn();
          } else if (e.key === 'Escape' && drag) {
            e.stopPropagation();
            setDrag(null);
          }
        }}
      >
        {buckets.map((b, i) => {
          const ok = Math.max(0, b.requests - b.limited - b.errors);
          return (
            <div
              key={i}
              aria-hidden
              className={`flex h-full min-w-0 flex-1 flex-col justify-end transition-opacity ${(hover !== null && i !== hover && !drag) || b.t + size > now ? 'opacity-50' : ''}`}
            >
              <div className="bg-heading/75 transition-[height] duration-500 motion-reduce:transition-none" style={{ height: pctOf(ok) }} />
              <div className="bg-warning transition-[height] duration-500 motion-reduce:transition-none" style={{ height: pctOf(b.limited) }} />
              <div className="bg-danger transition-[height] duration-500 motion-reduce:transition-none" style={{ height: pctOf(b.errors) }} />
            </div>
          );
        })}
        {drag && (
          <div aria-hidden className="pointer-events-none absolute inset-y-0 border-x border-focus bg-focus/15" style={{ left: `${(100 * lo) / n}%`, width: `${(100 * (hi - lo + 1)) / n}%` }} />
        )}
        {tip && anchor !== null && (
          <div
            aria-hidden
            className="pointer-events-none absolute top-2 z-10 rounded-md bg-tip px-3 py-2 text-xs whitespace-nowrap text-on-tip shadow-float"
            style={{ left: `${(100 * (anchor + 0.5)) / n}%`, transform: `translateX(-${Math.round((100 * anchor) / Math.max(1, n - 1))}%)` }}
          >
            <p className="font-medium">{tip.title}</p>
            <p className="tabular-nums">{tip.line}</p>
            {'hint' in tip && <p className="text-on-tip/70">{tip.hint}</p>}
          </div>
        )}
        <p aria-live="polite" className="sr-only">
          {byKey && tip ? `${tip.title}: ${tip.line}. ${'hint' in tip ? tip.hint : ''}` : ''}
        </p>
      </div>
      <figcaption className="eyebrow relative h-4 text-body">
        {ticks.map((t, i) => {
          const at = (t - from) / (to - from);
          // Ends stay inside the chart; odd ticks drop on narrow screens.
          return (
            <span key={t} className={`absolute whitespace-nowrap ${i % 2 ? 'max-sm:hidden' : ''}`} style={{ left: `${100 * at}%`, transform: `translateX(-${100 * at}%)` }}>
              {clock(t, days)}
            </span>
          );
        })}
      </figcaption>
    </figure>
  );
}

export function Key({ className, children }: { className: string; children: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span aria-hidden className={`size-2 rounded-xs ${className}`} />
      {children}
    </span>
  );
}

// Unranked names the rules that limited requests but have no client in the
// list, so a missing rule reads as sampling, not as a rule that did nothing.
export function Unranked({ ids }: { ids: string[] }) {
  if (ids.length === 0) return null;
  return (
    <p className="text-sm text-body">
      No clients ranked for{' '}
      {ids.map((id, i) => (
        <span key={id}>
          {i > 0 && ', '}
          <code className="text-heading">{id}</code>
        </span>
      ))}
      . Each edge reports its 20 most limited clients across all rules each minute, counted from 1 in 16 limited requests, and admin keeps the 20 most limited of each rule in each bar, so a rule whose limits are spread over many clients can have none listed.
    </p>
  );
}

// Cell is a right-aligned table count that rolls as it updates.
const Cell = ({ text }: { text: string }) => (
  <td className="text-right tabular-nums">
    <Rolling text={text} />
  </td>
);

export function Stats() {
  const r = useRange();
  const logs = useLogSearch();
  const role = useRole();
  // Clients of one rule; a rule that limits a few clients often would
  // otherwise hide every client of one that limits many a little.
  const [only, setOnly] = useState('');
  const { q, rows } = r;
  // Edges report every loaded version each minute; ones that served nothing are noise.
  const versions = [...new Set(rows.filter((x) => x.requests > 0).map((x) => x.version))];
  const rules = new Map<string, NonNullable<Row['rate_limit_rules']>[number]>();
  const top = new Map<string, NonNullable<Row['top_limited']>[number]>();
  const blocks = new Map<string, { id: string; matched: number; blocked: number; would_block: number }>();
  for (const x of rows) {
    // Only config rules with a block setting decide blocks; the rest would be rows of zeros.
    for (const o of x.rules ?? []) {
      if (o.phase !== 'config' || o.blocked + o.would_block === 0) continue;
      const t = blocks.get(o.id) ?? { id: o.id, matched: 0, blocked: 0, would_block: 0 };
      for (const k of ['matched', 'blocked', 'would_block'] as const) t[k] += o[k];
      blocks.set(o.id, t);
    }
    for (const c of x.rate_limit_rules ?? []) {
      const t = rules.get(c.id) ?? { id: c.id, evaluated: 0, limited: 0, would_limit: 0, failed: 0 };
      for (const k of ['evaluated', 'limited', 'would_limit', 'failed'] as const) t[k] += c[k];
      rules.set(c.id, t);
    }
    for (const t of x.top_limited ?? []) {
      const e = top.get(t.rule + t.key) ?? { ...t, limited: 0, would_limit: 0 };
      e.limited += t.limited;
      e.would_limit = (e.would_limit ?? 0) + (t.would_limit ?? 0);
      top.set(t.rule + t.key, e);
    }
  }
  const none = `No traffic reported ${r.phrase}.`;
  const requests = sum(rows, (x) => x.requests);
  return (
    <Page title="Stats" actions={<RangePicker r={r} />}>
      <ErrorBox error={q.error} />
      <Card title={`Requests, ${r.title}`}>{q.data && requests === 0 && !r.zoom ? <p className="text-body">{none}</p> : <Bars r={r} />}</Card>
      <Title className="-mb-2" info="Edge 5xx are answers the edge made itself, such as 503 from a rule that fails closed. Upstream 5xx came from the upstream. During a canary, compare the two versions here.">
        By version
      </Title>
      <Table head={['Version', 'Requests', 'Edge 5xx', 'Upstream 5xx', 'Auth failures']} num={[1, 2, 3, 4]} empty={q.data && none}>
        {versions.map((v) => {
          const vr = rows.filter((x) => x.version === v);
          const n = sum(vr, (x) => x.requests);
          return (
            <tr key={v}>
              <td>{role(v)}</td>
              <Cell text={count(n)} />
              <Cell text={pct(sum(vr, (x) => x.edge_5xx), n)} />
              <Cell text={pct(sum(vr, (x) => x.upstream_5xx), n)} />
              <Cell text={pct(sum(vr, (x) => x.auth_failures), n)} />
            </tr>
          );
        })}
      </Table>
      <Title
        className="-mb-2"
        info="Every request is counted, not sampled. The edge answers a request itself when it refuses it or cannot reach the upstream, such as 502 when the upstream is down; the upstream answers every request the edge forwards."
      >
        Status codes
      </Title>
      {/* Requests without codes are from edges older than this admin, or minutes before it stored them. */}
      <Table
        head={['Status', 'Answered by', 'Requests', 'Share']}
        num={[2, 3]}
        empty={q.data && (requests ? `No status codes reported ${r.phrase}: edges older than this admin don't send them.` : none)}
      >
        {statusCodes(rows).map((c) => (
          <tr key={c.origin + c.code}>
            <td className="tabular-nums">
              <LogLink href={logs({ from: r.from, to: r.to, status: statusOf(c.code) })}>{codeName(c.code)}</LogLink>
            </td>
            <td>{c.origin === 'edge' ? 'The edge' : 'The upstream'}</td>
            <Cell text={count(c.n)} />
            <Cell text={pct(c.n, requests)} />
          </tr>
        ))}
      </Table>
      <Title
        className="-mb-2"
        info="Why the edge could not get an answer from the upstream, counted exactly. Each is a 502 the edge sent, or 504 when the upstream took too long. The access line of each request has the error."
      >
        Upstream failures
      </Title>
      <Table head={['Cause', 'Requests', 'Share']} num={[1, 2]} empty={q.data && `The edge reached the upstream every time ${r.phrase}.`}>
        {causes(rows).map(([c, n]) => (
          <tr key={c}>
            <td>
              <LogLink href={logs({ from: r.from, to: r.to, status: causeStatus(c) })}>{causeWords[c] ?? c}</LogLink>
            </td>
            <Cell text={count(n)} />
            <Cell text={pct(n, requests)} />
          </tr>
        ))}
      </Table>
      <Title
        className="-mb-2"
        info="Every request is counted, not sampled; only a report an edge could not deliver is missing. Checked: requests the rule matched. Blocked: requests it answered with 429. Over limit, log only: requests a log only rule found over its limit and let through. Valkey down: checks Valkey did not answer, which the rule's fail mode then handled."
      >
        Rate limit rules
      </Title>
      <Table head={['Rule', 'Checked', 'Blocked', 'Over limit, log only', 'Valkey down']} num={[1, 2, 3, 4]} empty={q.data && `No rate limit rule ran ${r.phrase}.`}>
        {[...rules.values()].map((x) => (
          <tr key={x.id}>
            <td className="font-mono">{x.id}</td>
            <Cell text={count(x.evaluated)} />
            <Cell text={count(x.limited)} />
            <Cell text={count(x.would_limit)} />
            <Cell text={count(x.failed)} />
          </tr>
        ))}
      </Table>
      <Title
        className="-mb-2"
        info="Config rules with a block setting. Matched: requests the rule matched. Blocked: requests it answered with 403. Would block, log only: requests a log only rule matched and let through, or that the block kill switch let through."
      >
        Blocking config rules
      </Title>
      <Table head={['Rule', 'Matched', 'Blocked', 'Would block, log only']} num={[1, 2, 3]} empty={q.data && `No config rule blocked a request ${r.phrase}.`}>
        {[...blocks.values()].map((x) => (
          <tr key={x.id}>
            <td className="font-mono">{x.id}</td>
            <Cell text={count(x.matched)} />
            <Cell text={count(x.blocked)} />
            <Cell text={count(x.would_block)} />
          </tr>
        ))}
      </Table>
      <div className="-mb-2 flex flex-wrap items-center justify-between gap-3">
        <Title info="Estimated from samples each edge keeps, so counts are approximate. Pick a rule to see who it limits, or who a log only rule would hit before switching it to block.">
          Most limited clients
        </Title>
        <select aria-label="Rule" value={only} onChange={(e) => setOnly(e.target.value)}>
          <option value="">All rules</option>
          {[...new Set([...top.values()].map((t) => t.rule))].sort().map((id) => (
            <option key={id} value={id}>
              {id}
            </option>
          ))}
        </select>
      </div>
      <Table head={['Key', 'Rule', 'Blocked (estimate)', 'Over limit, log only (estimate)']} num={[2, 3]} empty={q.data && `Nothing was limited ${r.phrase}.`}>
        {[...top.values()]
          .filter((t) => !only || t.rule === only)
          .sort((a, b) => b.limited + (b.would_limit ?? 0) - a.limited - (a.would_limit ?? 0))
          .slice(0, 20)
          .map((t) => (
            <tr key={t.rule + t.key}>
              <td className="font-mono">
                <Link to={`/subjects/${encodeURIComponent(t.display)}`} className="text-heading underline">
                  {t.display}
                </Link>
              </td>
              <td className="font-mono">{t.rule}</td>
              <Cell text={count(t.limited)} />
              <Cell text={count(t.would_limit ?? 0)} />
            </tr>
          ))}
      </Table>
      <Unranked ids={[...rules.values()].filter((x) => x.limited + x.would_limit > 0 && ![...top.values()].some((t) => t.rule === x.id)).map((x) => x.id)} />
    </Page>
  );
}

// Mark is one release on a traffic chart: a publish, a revert or a canary
// step, at the time the audit log has for it.
export interface Mark {
  seq: number;
  version: number;
  t: number;
  name: string;
  kill: boolean;
}

// The audit actions marked on traffic charts, in the words each mark says.
const marked: Record<string, string> = {
  'config.publish': 'published',
  'config.revert': 'published as a revert',
  'config.import': 'imported',
  'config.overlay_publish': 'published by autopilot',
  'canary.step': 'canary stepped up',
  'canary.promote': 'canary promoted',
  'canary.abort': 'canary aborted',
  // A guard rollback's own row names the bad version; the publish row names
  // the version edges now serve and carries its kill switch.
  'config.rollback': 'published by a guard rollback',
  'guard.canary_abort': 'canary aborted by the guard',
};

// killWords says what a kill switch was set to, from a publish's details.
const killWords = (k: { rate_limit?: boolean; auth?: boolean; block?: boolean }) =>
  [k.rate_limit && 'rate limiting off', k.block && 'blocking off', k.auth && 'JWT checks off'].filter(Boolean).join(', ') || 'everything enforced again';

// useMarks lists the releases since from, for a role that may read the
// audit log; for any other it is empty.
export function useMarks(from: number) {
  const can = useCan();
  // Whole minutes, so the query changes once a minute, not every render.
  const since = new Date(Math.floor(from / minute) * minute).toISOString();
  const q = useQuery({
    queryKey: ['marks', since],
    queryFn: () => api<Event[]>('GET', `/api/audit?since=${since}&action=${Object.keys(marked).join(',')}`),
    enabled: can('audit.read'),
    placeholderData: keepPreviousData,
    // The window start moves once a step, up to 6 hours, so new releases need a poll.
    refetchInterval: 60_000,
  });
  // ponytail: the API returns the newest 100 events, so a range with more releases marks only the latest 100; page with before= if that is ever too few.
  return useMemo(
    () =>
      (q.data ?? []).flatMap((e): Mark[] => {
        const v = /^version (\d+)$/.exec(e.target)?.[1];
        if (!v) return [];
        const t = Date.parse(e.occurred_at);
        const k = e.details?.kill_switch;
        const at = clock(t, true);
        return [{ seq: e.seq, version: Number(v), t, kill: !!k, name: `Version ${v} ${marked[e.action] ?? e.action}, ${at}${k ? `. Kill switch changed: ${killWords(k)}` : ''}` }];
      }),
    [q.data],
  );
}

// A release that changed a kill switch is square and red, in the key and on the chart.
const killLook = 'rounded-none bg-danger-wash shadow-[0_0_0_1px_var(--color-danger)]';

export const MarkKeys = ({ more }: { more: number }) => (
  <>
    <Key className="rounded-full bg-soft shadow-field">Release</Key>
    <Key className={killLook}>Kill switch changed</Key>
    {more > 0 && <span title="Releases with no room on the chart. Kill switch changes and the newest are marked first.">+{more} more</span>}
  </>
);

// Markers is a strip of links above a chart, one per release, each with a
// line down to its time; it sits outside the chart so it never takes a drag.
// reach is the height the lines go down: the gap and the chart below.
// onMore gets the count of releases with no room, for the key.
export function Markers({ marks, from, to, reach, onMore }: { marks: Mark[]; from: number; to: number; reach: string; onMore: (n: number) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const o = new ResizeObserver(([e]) => setWidth(e!.contentRect.width));
    o.observe(ref.current!);
    return () => o.disconnect();
  }, []);
  const inRange = marks.filter((m) => m.t >= from && m.t < to);
  const w = 30;
  // Only as many marks as fit side by side, kill switch changes then the
  // newest; unmeasured, all of them.
  const fit = width ? Math.floor(width / w) : inRange.length;
  const shown = inRange
    .sort((a, b) => Number(b.kill) - Number(a.kill) || b.t - a.t)
    .slice(0, fit)
    .sort((a, b) => a.t - b.t);
  const more = inRange.length - shown.length;
  useEffect(() => onMore(more), [more, onMore]);
  const at = (t: number) => (t - from) / (to - from);
  // Releases minutes apart would cover each other, so each mark keeps its
  // width from the one before, and marks past the right edge move back left.
  const x = shown.map((m) => at(m.t) * width - w / 2);
  for (let i = 0; i < x.length; i++) x[i] = Math.max(x[i]!, i ? x[i - 1]! + w : 0);
  for (let i = x.length - 1; i >= 0; i--) x[i] = Math.min(x[i]!, i < x.length - 1 ? x[i + 1]! - w : width - w);
  return (
    <div ref={ref} className={inRange.length ? 'relative h-6' : 'hidden'}>
      {shown.map((m, i) => (
        <Fragment key={m.seq}>
          <span aria-hidden className={`pointer-events-none absolute top-full z-[5] w-px ${reach} ${m.kill ? 'bg-danger/60' : 'bg-focus/50'}`} style={{ left: `${100 * at(m.t)}%` }} />
          <Link
            to={`/versions/${m.version}`}
            title={m.name}
            className={`absolute top-0 grid h-6 place-items-center text-xs font-medium tabular-nums text-heading hover:bg-soft ${m.kill ? killLook : 'rounded-full bg-panel shadow-field'}`}
            style={{ left: x[i], width: w - 2 }}
          >
            <span aria-hidden>v{m.version}</span>
            <span className="sr-only">{m.name}</span>
          </Link>
        </Fragment>
      ))}
    </div>
  );
}

// Spark draws one figure over a window as small bars beside the text that
// gives its numbers, so it is hidden from screen readers.
export function Spark({ rows, from, to, value }: { rows: Row[]; from: number; to: number; value: (r: Row) => number }) {
  const n = 24;
  const bins = new Array<number>(n).fill(0);
  for (const r of rows) {
    const i = Math.floor(((Date.parse(r.minute) - from) / (to - from)) * n);
    if (i >= 0 && i < n) bins[i] = bins[i]! + value(r);
  }
  const max = Math.max(1, ...bins);
  return (
    <span aria-hidden className="inline-flex h-4 w-24 shrink-0 items-end gap-px border-b border-line">
      {bins.map((b, i) => (
        <span key={i} className="flex-1 bg-heading/60" style={{ height: `${(100 * b) / max}%` }} />
      ))}
    </span>
  );
}

// ruleCounts sums one rule's counts over rows: a rate limit rule's checks,
// 429s and log only overs, or a config or header rule's matches and blocks.
// IDs are unique across phases, so one rule is in one list.
export function ruleCounts(rows: Row[], id: string) {
  const c = { matched: 0, limited: 0, would_limit: 0, blocked: 0, would_block: 0 };
  for (const r of rows) {
    for (const x of r.rate_limit_rules ?? [])
      if (x.id === id) {
        c.matched += x.evaluated;
        c.limited += x.limited;
        c.would_limit += x.would_limit;
      }
    for (const x of r.rules ?? [])
      if (x.id === id) {
        c.matched += x.matched;
        c.blocked += x.blocked;
        c.would_block += x.would_block;
      }
  }
  return c;
}

// countWords says a rule's counts the way Stats names its columns. Every
// request is counted, not sampled, so these are exact.
export const countWords = (c: ReturnType<typeof ruleCounts>) =>
  [
    `${count(c.matched)} matched`,
    c.limited > 0 && `${count(c.limited)} blocked with 429`,
    c.would_limit > 0 && `${count(c.would_limit)} over limit, log only`,
    c.blocked > 0 && `${count(c.blocked)} blocked with 403`,
    c.would_block > 0 && `${count(c.would_block)} would block, log only`,
  ]
    .filter(Boolean)
    .join(' · ');
