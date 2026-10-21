import { useQuery } from '@tanstack/react-query';
import { type PointerEvent, useMemo, useRef, useState } from 'react';
import { api } from '../api';
import { Badge, Button, Card, ErrorBox, Page, Rolling, Table, Title, ago, when } from '../ui';
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
      info="Config from says where an edge got the version it serves: admin, its cache file from an earlier run, or the bootstrap file it starts from when admin is unreachable. An edge on cache or bootstrap keeps serving; it switches to admin once it can reach it. Upstream is the edge's UPSTREAM_URL, the load balancer or gateway it forwards every request to. It is set in the edge's deployment, not here."
    >
      <p className="text-body">
        Edges that fetched config from this admin. Live means it reported in the last minute. Versions loaded are the live version and, during a canary, the canary version.
      </p>
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
}

export const sum = (rows: Row[], f: (r: Row) => number) => rows.reduce((n, r) => n + f(r), 0);
export const pct = (n: number, d: number) => (d ? `${((100 * n) / d).toFixed(2)}%` : '—');
export const count = (n: number) => n.toLocaleString();

// The ranges the time picker offers; each label finishes "in the …".
export const ranges = [
  [60, 'last hour'],
  [360, 'last 6 hours'],
  [1440, 'last day'],
  [10080, 'last week'],
] as const;

const minute = 60_000;

// clock formats a chart time, with the date once a range spans days.
export const clock = (t: number, days: boolean) =>
  new Date(t).toLocaleString([], days ? { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' } : { hour: 'numeric', minute: '2-digit' });

// useRange holds the picked range, refetched every 10 seconds, and a zoom
// dragged on the chart. rows are the minutes inside the window shown.
export function useRange(enabled = true) {
  const [minutes, setMinutes] = useState(60);
  const [zoom, setZoom] = useState<[number, number] | null>(null);
  const q = useQuery({ queryKey: ['stats', minutes], queryFn: () => api<Row[]>('GET', `/api/stats?minutes=${minutes}`), refetchInterval: 10_000, enabled });
  // Before the first fetch, the time the page opened.
  const [opened] = useState(Date.now);
  const now = q.dataUpdatedAt || opened;
  // The window ends after the minute in progress, which admin writes as it grows.
  const end = Math.floor(now / minute) * minute + minute;
  const [from, to] = zoom ?? [end - minutes * minute, end];
  // Memoized: a week is 10,000+ rows, and the page re-renders on every poll.
  const rows = useMemo(
    () =>
      (q.data ?? []).filter((r) => {
        const t = Date.parse(r.minute);
        return t >= from && t < to;
      }),
    [q.data, from, to],
  );
  const days = to - from >= 1440 * minute;
  const label = ranges.find(([m]) => m === minutes)?.[1] ?? 'last hour';
  return {
    q,
    rows,
    minutes,
    from,
    to,
    now,
    zoom,
    setZoom,
    pick: (m: number) => {
      setMinutes(m);
      setZoom(null);
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
        <span className="eyebrow flex items-center gap-1.5 text-body" title="Updates every 10 seconds">
          <span aria-hidden className={`size-1.5 rounded-full ${r.q.error ? 'bg-danger' : 'animate-pulse bg-success motion-reduce:animate-none'}`} />
          {r.q.error ? 'Not updating' : 'Live'}
        </span>
      )}
      <select aria-label="Time range" value={r.minutes} onChange={(e) => r.pick(Number(e.target.value))}>
        {ranges.map(([m, label]) => (
          <option key={m} value={m}>
            {label[0]!.toUpperCase() + label.slice(1)}
          </option>
        ))}
      </select>
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
export function Bars({ r }: { r: Range }) {
  const { rows, from, to, now } = r;
  const per = steps.find((s) => (to - from) / minute / s <= 180) ?? 1440;
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
        <span className="flex items-center gap-3">
          <Key className="bg-heading/75">Served</Key>
          <Key className="bg-warning">Rate limited</Key>
          <Key className="bg-danger">5xx</Key>
        </span>
      </div>
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

function Key({ className, children }: { className: string; children: string }) {
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
      . Each edge reports its 20 most limited clients across all rules, counted from 1 in 16 limited requests, so a rule whose limits are spread over many clients can have none listed.
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
  const role = useRole();
  // Clients of one rule; a rule that limits a few clients often would
  // otherwise hide every client of one that limits many a little.
  const [only, setOnly] = useState('');
  const { q, rows } = r;
  // Edges report every loaded version each minute; ones that served nothing are noise.
  const versions = [...new Set(rows.filter((x) => x.requests > 0).map((x) => x.version))];
  const rules = new Map<string, NonNullable<Row['rate_limit_rules']>[number]>();
  const top = new Map<string, NonNullable<Row['top_limited']>[number]>();
  for (const x of rows) {
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
  return (
    <Page title="Stats" actions={<RangePicker r={r} />}>
      <ErrorBox error={q.error} />
      <Card title={`Requests, ${r.title}`}>{q.data && sum(rows, (x) => x.requests) === 0 && !r.zoom ? <p className="text-body">{none}</p> : <Bars r={r} />}</Card>
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
              <td className="font-mono">{t.display}</td>
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
