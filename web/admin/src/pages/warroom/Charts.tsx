import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { type KeyboardEvent, type MouseEvent, useState } from 'react';
import { api, type Config } from '../../api';
import { ruleLink } from '../../phases';
import { Link } from '../../router';
import { type Anomaly, label as signalTitle } from '../Notifications';
import { type Mark, type Row, codeName, statusCodes } from '../Fleet';
import { Head, Widget, color, fmt, between, short } from './shared';

export const minute = 60_000;

// The edge's latency histogram bounds in ms; a last bucket holds everything above the final bound.
export const bounds = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

export type StatRow = Row & { latency_ms_buckets?: number[] };

export interface Bucket {
  t: number;
  requests: number;
  e5: number;
  u5: number;
  auth: number;
  failed: number;
  lat: number[];
  // Answers per outcome series, in the order of `series`.
  s: number[];
}

export const series = [
  { name: 'Passed on', color: color.passed },
  { name: 'Upstream 5xx', color: color.red },
  { name: 'Edge 429', color: color.amber },
  { name: 'Edge 403', color: color.e403 },
  { name: 'Edge 401', color: color.e401 },
  { name: 'Edge 5xx', color: color.edge5xx },
  { name: 'Other edge answers', color: color.other },
];
const OTHER = 6;

function seriesOf(origin: 'edge' | 'upstream', code: string) {
  const n = Number(code);
  const is5xx = n >= 500 && n <= 599;
  if (origin === 'upstream') return is5xx ? 1 : 0;
  return n === 429 ? 2 : n === 403 ? 3 : n === 401 ? 4 : is5xx ? 5 : OTHER;
}

const blank = (t: number): Bucket => ({ t, requests: 0, e5: 0, u5: 0, auth: 0, failed: 0, lat: Array<number>(bounds.length + 1).fill(0), s: Array<number>(series.length).fill(0) });

// fold sums the rows of every version into one bucket per time, and leaves
// a minute with no row as zeros so a gap shows as zero.
export function fold(rows: StatRow[], times: number[]) {
  const at = new Map(times.map((t) => [t, blank(t)]));
  for (const r of rows) {
    const b = at.get(Date.parse(r.minute));
    if (!b) continue;
    b.requests += r.requests;
    b.e5 += r.edge_5xx;
    b.u5 += r.upstream_5xx;
    b.auth += r.auth_failures;
    for (const c of r.rate_limit_rules ?? []) b.failed += c.failed;
    (r.latency_ms_buckets ?? []).forEach((n, i) => (b.lat[i] = (b.lat[i] ?? 0) + n));
    for (const origin of ['edge', 'upstream'] as const)
      for (const [code, n] of Object.entries(r.status_codes[origin] ?? {})) b.s[seriesOf(origin, code)]! += n;
  }
  return times.map((t) => at.get(t)!);
}

export const sumB = (bs: Bucket[], f: (b: Bucket) => number) => bs.reduce((n, b) => n + f(b), 0);
export const total = (b: Bucket) => b.s.reduce((n, v) => n + v, 0);
export const inRange = (rows: StatRow[], from: number, to: number) =>
  rows.filter((r) => {
    const t = Date.parse(r.minute);
    return t >= from && t < to;
  });

export const hist = (bs: Bucket[]) => Array.from({ length: bounds.length + 1 }, (_, i) => sumB(bs, (b) => b.lat[i] ?? 0));
// pctIdx is the index of the bucket holding the quantile, -1 with no data.
export function pctIdx(h: number[], q: number) {
  const n = h.reduce((a, b) => a + b, 0);
  if (!n) return -1;
  let c = 0;
  for (let i = 0; i < h.length; i++) {
    c += h[i]!;
    if (c >= q * n) return i;
  }
  return h.length - 1;
}
const msText = (v: number) => (v >= 1000 ? `${Math.round(v) / 1000} s` : `${Math.round(v * 100) / 100} ms`);
export const upTo = (i: number) => (i < 0 ? '—' : i >= bounds.length ? '> 10 s' : `≤ ${msText(bounds[i]!)}`);

// perMin keeps a small rate readable: 0.4 stays 0.4, 1,240 becomes 1.2k.
export const perMin = (n: number) => (n < 10 ? String(Math.round(n * 10) / 10) : short(n));

const p2 = (n: number) => String(n).padStart(2, '0');
export const hm = (t: number) => {
  const d = new Date(t);
  return `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`;
};

// stampOf names a chart time in UTC: HH:MM, or the date from a day-long range on, with the time below 6-hour steps.
export const stampOf = (t: number, days: boolean, step: number) =>
  days ? `${new Date(t).toLocaleString('en-US', { month: 'short', timeZone: 'UTC' })} ${new Date(t).getUTCDate()}${step < 360 ? ` ${hm(t)}` : ''}` : hm(t);

interface Band {
  at: number;
  label: string;
  color: string;
}

// bandsOf lists the fleet-wide anomalies firing inside the window, at most two.
export const bandsOf = (list: Anomaly[], from: number, to: number): Band[] =>
  list
    .filter((a) => a.state === 'firing' && a.rule === '' && a.fired_at && Date.parse(a.fired_at) >= from && Date.parse(a.fired_at) < to)
    .slice(0, 2)
    .map((a) => ({ at: Date.parse(a.fired_at!), label: `${signalTitle(a.signal)}, firing`, color: a.severity === 'critical' ? color.red : color.amber }));

const X0 = 56;
const X1 = 790;
const Y0 = 14;
const Y1 = 226;

interface WidgetProps {
  wall: boolean;
  expanded: string | null;
  onExpand: (name: string | null) => void;
}

export function OutcomeChart({
  view,
  win,
  step,
  days,
  live,
  cur,
  before,
  marks,
  bands,
  inView,
  zoomed,
  resetLabel,
  onReset,
  onZoom,
  ...w
}: WidgetProps & {
  view: Bucket[];
  win: Bucket[];
  step: number;
  days: boolean;
  live: boolean;
  cur: number;
  before: number | null;
  marks: Mark[];
  bands: Band[];
  inView: string;
  zoomed: boolean;
  resetLabel: string;
  onReset: () => void;
  onZoom: (from: number, to: number) => void;
}) {
  const [hidden, setHidden] = useState<Set<number>>(new Set());
  const [hover, setHover] = useState<number | null>(null);
  const [drag, setDrag] = useState<{ a: number; b: number } | null>(null);
  const [asShare, setAsShare] = useState(false);
  const [stacked, setStacked] = useState(true);
  const V = view.length;
  const stepMs = step * minute;
  const otherTotal = sumB(view, (b) => b.s[OTHER]!);
  const shown = series.map((s, k) => ({ ...s, k })).filter((s) => !hidden.has(s.k) && (s.k !== OTHER || otherTotal > 0));
  const val = (b: Bucket, k: number) => (asShare ? (total(b) ? (b.s[k]! / total(b)) * 100 : 0) : b.s[k]! / step);

  let peak = 0;
  for (const b of view) {
    if (stacked) peak = Math.max(peak, shown.reduce((n, s) => n + val(b, s.k), 0));
    else for (const s of shown) peak = Math.max(peak, val(b, s.k));
  }
  let ystep = asShare ? (peak > 50 ? 25 : peak > 20 ? 10 : peak > 10 ? 5 : peak > 5 ? 2 : 1) : peak > 40000 ? 20000 : peak > 8000 ? 5000 : peak > 2000 ? 1000 : peak > 400 ? 200 : 50;
  // Keeps the gridlines to a handful when traffic is far above the fixed steps.
  while (Math.ceil(peak / ystep) > 8) ystep *= 2;
  const yMax = Math.max(ystep, Math.ceil(peak / ystep) * ystep);
  const xAt = (i: number) => X0 + (i * (X1 - X0)) / Math.max(1, V - 1);
  const yAt = (v: number) => Y1 - (v / yMax) * (Y1 - Y0);
  const pt = (i: number, v: number) => `${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`;
  const pctX = (x: number) => (x / 800) * 100;
  const pctY = (y: number) => (y / 260) * 100;

  let areas: { d: string; fill: string; stroke: string; key: number }[];
  if (stacked) {
    const cum = view.map(() => 0);
    areas = shown.map((s) => {
      const lower = [...cum];
      cum.forEach((c, i) => (cum[i] = c + val(view[i]!, s.k)));
      const top = cum.map((c, i) => pt(i, c));
      const bottom = lower.map((c, i) => pt(i, c)).reverse();
      return { key: s.k, d: `M${top.join('L')}L${bottom.join('L')}Z`, fill: s.color, stroke: 'none' };
    });
  } else areas = shown.map((s) => ({ key: s.k, d: `M${view.map((b, i) => pt(i, val(b, s.k))).join('L')}`, fill: 'none', stroke: s.color }));

  const yTicks: number[] = [];
  for (let v = 0; v <= yMax + 1e-9; v += ystep) yTicks.push(v);
  const stamp = (t: number) => stampOf(t, days, step);
  // The last bucket holds the minute in progress in a period, and is "now" in Live too.
  const isNow = (i: number) => (live ? i === V - 1 : view[i]!.t + stepMs > cur);
  const xTicks = V ? [0, 1, 2, 3, 4, 5, 6].map((k) => Math.round((k * (V - 1)) / 6)) : [];

  const idxAt = (t: number) => {
    const i = Math.floor((t - view[0]!.t) / stepMs);
    return i >= 0 && i < V ? i : -1;
  };
  const shownMarks = V
    ? marks
        .map((m) => ({ m, i: idxAt(m.t) }))
        .filter((x) => x.i >= 0)
        .map(({ m, i }, n) => {
          const x = xAt(i);
          return { m, x, right: x > 640, top: 16 + (n % 2) * 20, text: m.name.replace(/^Version (\d+) /, 'v$1 ').split(',')[0]! };
        })
    : [];
  const shownBands = V
    ? bands
        .map((b) => ({ b, i: idxAt(b.at) }))
        .filter((x) => x.i >= 0)
        .map(({ b, i }) => ({ ...b, x: xAt(i) }))
    : [];

  const showBase = before !== null && !asShare && stacked && before > 0 && before < yMax;
  const baseY = before === null ? 0 : yAt(before);

  const hi = hover !== null && hover < V ? hover : null;
  const hb = hi === null ? null : view[hi]!;
  const idxFromEvent = (e: MouseEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * 800;
    return Math.max(0, Math.min(V - 1, Math.round(((px - X0) / (X1 - X0)) * (V - 1))));
  };
  const up = () => {
    if (drag && Math.abs(drag.b - drag.a) >= 2) {
      onZoom(view[Math.min(drag.a, drag.b)]!.t, view[Math.max(drag.a, drag.b)]!.t + stepMs);
      setHover(null);
    }
    setDrag(null);
  };
  const key = (e: KeyboardEvent) => {
    const h = hover === null ? V - 1 : hover;
    if (e.key === 'ArrowLeft') {
      e.preventDefault();
      setHover(Math.max(0, h - 1));
    }
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      setHover(Math.min(V - 1, h + 1));
    }
    if (e.key === 'Escape') {
      if (zoomed) onReset();
      else setHover(null);
    }
  };

  const wn = Math.max(1, win.length * step);
  const avg = (k: number) => sumB(win, (b) => b.s[k]!) / wn;
  const summary = `Requests by outcome, ${inView}. Average a minute: ${fmt(avg(0))} passed on, ${fmt(avg(2) + avg(3) + avg(4))} refused by the edge. Arrow keys step through each point.`;
  const pos = 'absolute whitespace-nowrap rounded-[3px] bg-[rgba(10,10,10,.75)] px-1';

  return (
    <Widget label="Requests by outcome" name="chart" {...w}>
      <Head title={`${asShare ? 'Share of requests by outcome' : 'Requests a minute by outcome'}, ${inView}`}>
        {!w.wall && (
          <div className="flex flex-wrap items-center gap-2">
            <div role="group" aria-label="Values" className="wr-segs">
              <button type="button" className="wr-seg" aria-pressed={!asShare} onClick={() => setAsShare(false)}>
                Requests
              </button>
              <button type="button" className="wr-seg" aria-pressed={asShare} onClick={() => setAsShare(true)}>
                Share %
              </button>
            </div>
            <div role="group" aria-label="Shape" className="wr-segs">
              <button type="button" className="wr-seg" aria-pressed={stacked} onClick={() => setStacked(true)}>
                Stacked
              </button>
              <button type="button" className="wr-seg" aria-pressed={!stacked} onClick={() => setStacked(false)}>
                Lines
              </button>
            </div>
            {zoomed && (
              <button type="button" className="wr-btn" onClick={onReset}>
                {resetLabel}
              </button>
            )}
          </div>
        )}
      </Head>
      {/* The chips are the legend, so the wall keeps them but they cannot be pressed. */}
      <div role="group" aria-label="Series" className="flex flex-wrap gap-1.5">
        {series.map((s, k) =>
          k === OTHER && otherTotal === 0 ? null : (
            <button key={k} type="button" className="wr-chip" disabled={w.wall} aria-pressed={!hidden.has(k)} onClick={() => setHidden((h) => { const n = new Set(h); if (!n.delete(k)) n.add(k); return n; })}>
              <span aria-hidden="true" style={{ width: 12, height: 12, borderRadius: 3, background: s.color }} />
              {s.name} <span className="wr-num" style={{ color: color.body }}>{perMin(avg(k))}</span>
            </button>
          ),
        )}
      </div>
      {/* The plot is a pointer and arrow-key surface; its text is the summary. */}
      <div
        className="wr-plot"
        tabIndex={0}
        role="img"
        aria-label={summary}
        style={{ position: 'relative', cursor: 'crosshair', userSelect: 'none' }}
        onMouseDown={(e) => V && !w.wall && setDrag({ a: idxFromEvent(e), b: idxFromEvent(e) })}
        onMouseMove={(e) => {
          if (!V) return;
          const i = idxFromEvent(e);
          setHover(i);
          setDrag((d) => d && { a: d.a, b: i });
        }}
        onMouseUp={up}
        onMouseLeave={() => {
          setHover(null);
          setDrag(null);
        }}
        onDoubleClick={() => zoomed && onReset()}
        onKeyDown={key}
      >
        <svg viewBox="0 0 800 260" style={{ display: 'block', width: '100%', height: 'auto' }}>
          {yTicks.map((v) => (
            <line key={v} x1={X0} x2={X1} y1={yAt(v)} y2={yAt(v)} stroke="#333333" />
          ))}
          <line x1={X0} x2={X1} y1={Y1} y2={Y1} stroke="#5c5c5c" />
          {shownBands.map((b) => (
            <rect key={b.at} x={b.x} y={Y0} width={Math.max(4, X1 - b.x)} height={Y1 - Y0} fill={b.color} fillOpacity=".12" />
          ))}
          {areas.map((a) => (
            <path key={a.key} d={a.d} fill={a.fill} fillOpacity=".9" stroke={a.stroke} strokeWidth="2" strokeLinejoin="round" />
          ))}
          {showBase && <line x1={X0} x2={X1} y1={baseY} y2={baseY} stroke="#ededed" strokeDasharray="6 5" strokeOpacity=".7" />}
          {shownMarks.map(({ m, x }) => (
            <g key={m.seq}>
              <line x1={x} x2={x} y1={Y0} y2={Y1} stroke={m.kill ? color.red : color.blue} strokeDasharray="3 4" />
              <rect x={x - 5} y={221} width="10" height="10" transform={`rotate(45 ${x} 226)`} fill={m.kill ? color.red : color.blue} />
            </g>
          ))}
          {drag && <rect x={xAt(Math.min(drag.a, drag.b))} y={Y0} width={Math.max(1, xAt(Math.max(drag.a, drag.b)) - xAt(Math.min(drag.a, drag.b)))} height={Y1 - Y0} fill={color.blue} fillOpacity=".18" stroke={color.blue} />}
          {hi !== null && <line x1={xAt(hi)} x2={xAt(hi)} y1={Y0} y2={Y1} stroke="#ededed" />}
        </svg>
        <div aria-hidden="true" style={{ position: 'absolute', inset: 0, pointerEvents: 'none', fontSize: 13 }}>
          {yTicks.map((v) => (
            <span key={v} className="wr-mono wr-num" style={{ position: 'absolute', left: 0, width: '6%', textAlign: 'right', top: `${pctY(yAt(v))}%`, transform: 'translateY(-50%)', color: color.body }}>
              {asShare ? `${v}%` : short(v)}
            </span>
          ))}
          {xTicks.map((i, k) => (
            <span key={k} className="wr-mono" style={{ position: 'absolute', left: `${pctX(xAt(i))}%`, bottom: 0, transform: `translateX(${k === 0 ? '0' : k === 6 ? '-100%' : '-50%'})`, color: color.body, whiteSpace: 'nowrap' }}>
              {isNow(i) ? 'now' : stamp(view[i]!.t)}
            </span>
          ))}
          {shownMarks.map(({ m, x, right, top, text }) => (
            <span key={m.seq} className={pos} style={{ left: `${pctX(right ? x - 4 : x + 4)}%`, top: `${pctY(top)}%`, transform: `translateX(${right ? '-100%' : '0'})`, color: m.kill ? color.red : '#9cc7ff' }}>
              {text}
            </span>
          ))}
          {showBase && (
            <span className={pos} style={{ left: '7.5%', top: `${pctY(baseY)}%`, transform: `translateY(${baseY < 70 ? '20%' : '-120%'})`, color: color.heading }}>
              Hour before: {short(before)} a minute
            </span>
          )}
          {shownBands.map((b, n) => (
            <span key={b.at} className={pos} style={{ right: '1.5%', top: `${76 - n * 8}%`, color: b.color, fontWeight: 600 }}>
              {b.label}
            </span>
          ))}
        </div>
        {hb && hi !== null && (
          <div
            style={{
              position: 'absolute',
              top: 8,
              left: `${pctX(xAt(hi))}%`,
              transform: `translateX(${xAt(hi) > 500 ? 'calc(-100% - 12px)' : '12px'})`,
              pointerEvents: 'none',
              background: '#1f1f1f',
              color: color.heading,
              borderRadius: 8,
              boxShadow: '0 0 0 1px rgba(255,255,255,.2), 0 8px 30px rgba(0,0,0,.5)',
              padding: '10px 12px',
              fontSize: 14,
              minWidth: 240,
              display: 'flex',
              flexDirection: 'column',
              gap: 4,
            }}
          >
            <span className="wr-mono" style={{ color: color.body }}>
              {stamp(hb.t)} UTC{step > 1 ? `, ${step}-minute average` : ''}
            </span>
            {[...shown].reverse().map((s) => (
              <span key={s.k} style={{ display: 'flex', justifyContent: 'space-between', gap: 16 }}>
                <span>
                  <span aria-hidden="true" style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 2, marginRight: 6, background: s.color }} />
                  {s.name}
                </span>
                <span className="wr-num">{asShare ? `${val(hb, s.k).toFixed(2)}%` : `${fmt(hb.s[s.k]! / step)} a minute`}</span>
              </span>
            ))}
            <span style={{ display: 'flex', justifyContent: 'space-between', gap: 16, borderTop: '1px solid #333', paddingTop: 4, fontWeight: 600 }}>
              <span>Total</span>
              <span className="wr-num">{fmt(total(hb) / step)} a minute</span>
            </span>
          </div>
        )}
      </div>
    </Widget>
  );
}

export function ResponseTime({ view, inView, ...w }: WidgetProps & { view: Bucket[]; inView: string }) {
  // An overflow bucket has no bound, so it is drawn at twice the last one.
  const at = (h: number[], q: number) => {
    const i = pctIdx(h, q);
    return i < 0 ? 0 : i >= bounds.length ? bounds[bounds.length - 1]! * 2 : bounds[i]!;
  };
  const p50 = view.map((b) => at(b.lat, 0.5));
  const p99 = view.map((b) => at(b.lat, 0.99));
  const yMax = Math.max(1, ...p99);
  const y = (v: number) => 110 - (v / yMax) * 100;
  const line = (vs: number[]) => vs.map((v, i) => `${(52 + (i * 304) / Math.max(1, vs.length - 1)).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const all = hist(view);
  const ticks = [0, yMax / 2, yMax];
  const summary = `Response time, ${inView}. Over the whole view p50 ${upTo(pctIdx(all, 0.5))}, p99 ${upTo(pctIdx(all, 0.99))}.`;
  return (
    <Widget label="Response time" name="lat" {...w}>
      <Head title="Response time" />
      <span style={{ fontSize: 14 }}>
        <span style={{ color: color.muted }}>━</span> p50 <span style={{ color: color.heading, marginLeft: 10 }}>━</span> p99
      </span>
      <div role="img" aria-label={summary} style={{ position: 'relative' }}>
        <svg viewBox="0 0 360 120" style={{ display: 'block', width: '100%', height: 'auto' }}>
          {ticks.map((v) => (
            <line key={v} x1="52" x2="356" y1={y(v)} y2={y(v)} stroke="#333333" />
          ))}
          <polyline points={line(p50)} fill="none" stroke={color.muted} strokeWidth="2" vectorEffect="non-scaling-stroke" />
          <polyline points={line(p99)} fill="none" stroke={color.heading} strokeWidth="2" vectorEffect="non-scaling-stroke" />
        </svg>
        <div aria-hidden="true" style={{ position: 'absolute', inset: 0, pointerEvents: 'none', fontSize: 12 }}>
          {ticks.map((v) => (
            <span key={v} className="wr-mono wr-num" style={{ position: 'absolute', left: 0, width: '13%', textAlign: 'right', whiteSpace: 'nowrap', top: `${(y(v) / 120) * 100}%`, transform: 'translateY(-50%)', color: color.body }}>
              {v > 10000 ? '> 10 s' : msText(v)}
            </span>
          ))}
        </div>
      </div>
    </Widget>
  );
}

const codeColor = (origin: string, code: string) => {
  const n = Number(code);
  if (origin === 'edge') return code === '429' ? color.amber : code === '403' ? color.e403 : code === '401' ? color.e401 : n >= 500 && n <= 599 ? color.edge5xx : color.passed;
  return n >= 500 && n <= 599 ? color.red : color.passed;
};

export function Codes({ rows, live, inView, ...w }: WidgetProps & { rows: StatRow[]; live: boolean; inView: string }) {
  const list = statusCodes(rows).slice(0, 6);
  const top = list[0]?.n ?? 1;
  return (
    <Widget label="Answers by status code" name="codes" {...w}>
      <Head title={live ? 'Answers by status, a minute' : `Answers by status, ${inView}`} />
      {list.map((c) => (
        <div key={c.origin + c.code} style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 15 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'baseline' }}>
            <span>
              <span className="wr-mono" style={{ color: color.heading }}>
                {codeName(c.code)}
              </span>{' '}
              <span style={{ fontSize: 13, marginLeft: 6 }}>from the {c.origin === 'edge' ? 'edge' : 'upstream'}</span>
            </span>
            <span className="wr-num" style={{ color: color.heading }}>
              {live ? perMin(c.n / 5) : short(c.n)}
            </span>
          </div>
          <div style={{ height: 8, background: '#1a1a1a', borderRadius: 4 }}>
            <div style={{ height: 8, width: `${Math.max(1, Math.round(Math.sqrt(c.n / top) * 100))}%`, background: codeColor(c.origin, c.code), borderRadius: 4 }} />
          </div>
        </div>
      ))}
    </Widget>
  );
}

interface ObservedRoute {
  id: number;
  host: string;
  method: string;
  template: string;
  requests: number;
  estimated: number;
  actions: Record<string, number>;
}

// Actions where the edge did not refuse the request, as admin's traffic count reads them; any other action is a refusal.
const notRefused = new Set(['allow', 'upstream_timeout', 'upstream_error', 'upstream_tls', 'client_gone']);

export function RoutesHit({ live, from, to, inView, ...w }: WidgetProps & { live: boolean; from: number; to: number; inView: string }) {
  // Routes are counted by the hour: Live shows the current hour, a period the span, which admin rounds out to whole hours.
  const span = live ? 'hours=1' : `from=${new Date(from).toISOString()}&to=${new Date(to).toISOString()}`;
  const q = useQuery({
    queryKey: ['routes', span],
    queryFn: () => api<{ since: string; until: string; routes: ObservedRoute[] }>('GET', `/api/observed-routes?${span}`),
    refetchInterval: 15_000,
    placeholderData: keepPreviousData,
  });
  const list = [...(q.data?.routes ?? [])].sort((a, b) => b.requests - a.requests).slice(0, 4);
  const top = list[0]?.requests ?? 1;
  return (
    <Widget label="Routes hit hardest" name="routes" {...w}>
      <Head title={live ? 'Routes hit hardest, this hour' : `Routes hit hardest, ${q.data ? between(q.data.since, q.data.until) : inView}`} />
      <div className="wr-eyebrow" style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
        <span>Route</span>
        <span>Requests · refused</span>
      </div>
      {list.map((r) => {
        const refused = Object.entries(r.actions ?? {}).reduce((n, [d, c]) => (notRefused.has(d) ? n : n + c), 0);
        const rate = r.requests ? Math.min(1, refused / r.requests) : 0;
        const width = (r.requests / top) * 100;
        return (
          <div key={r.id} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'baseline', whiteSpace: 'nowrap' }}>
              <Link to={`/routes/${r.id}`} title={r.host} className="wr-mono min-w-0 overflow-hidden text-ellipsis">
                {r.method} {r.template}
              </Link>
              <span className="wr-num">
                <span style={{ color: color.heading }}>
                  {r.estimated > 0 ? '≈ ' : ''}
                  {fmt(r.requests)}
                </span>{' '}
                · <span style={{ color: rate > 0.05 ? color.amber : color.body }}>{(rate * 100).toFixed(1)}%</span>
              </span>
            </div>
            <div style={{ height: 8, background: '#1a1a1a', borderRadius: 4, display: 'flex', overflow: 'hidden' }}>
              <div style={{ width: `${width * (1 - rate)}%`, background: color.passed }} />
              <div style={{ width: `${width * rate}%`, background: color.amber }} />
            </div>
          </div>
        );
      })}
    </Widget>
  );
}

export function RulesRefusing({ rows, live, inView, cfg, ...w }: WidgetProps & { rows: StatRow[]; live: boolean; inView: string; cfg: Config | undefined }) {
  const m = new Map<string, { refused: number; log: number }>();
  const add = (id: string, refused: number, log: number) => {
    const e = m.get(id) ?? { refused: 0, log: 0 };
    e.refused += refused;
    e.log += log;
    m.set(id, e);
  };
  for (const r of rows) {
    for (const x of r.rules ?? []) add(x.id, x.blocked, x.logged);
    for (const x of r.rate_limit_rules ?? []) add(x.id, x.limited, x.logged);
  }
  const div = live ? 5 : 1;
  const list = [...m.entries()]
    .map(([id, e]) => ({ id, refused: e.refused / div, log: e.log / div }))
    .filter((r) => r.refused + r.log > 0)
    .sort((a, b) => b.refused + b.log - (a.refused + a.log))
    .slice(0, 4);
  const value = (r: { refused: number; log: number }) => (r.refused > 0 ? r.refused : r.log);
  const top = list.length ? Math.max(...list.map(value)) : 1;
  return (
    <Widget label="Rules refusing most" name="rules" {...w}>
      <Head title={live ? 'Rules refusing most, a minute' : `Rules refusing most, ${inView}`} />
      {list.length === 0 && <p style={{ margin: 0 }}>No rule refused anything.</p>}
      {list.map((r) => {
        const to = ruleLink(cfg, r.id);
        return (
          <div key={r.id} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'baseline' }}>
              <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
                {to ? (
                  <Link to={to} className="wr-mono">
                    {r.id}
                  </Link>
                ) : (
                  <span className="wr-mono" style={{ color: color.heading }}>
                    {r.id}
                  </span>
                )}{' '}
                <span style={{ fontSize: 13, marginLeft: 6, padding: '1px 6px', borderRadius: 4, background: '#1a1a1a', boxShadow: '0 0 0 1px rgba(255,255,255,.14)' }}>{r.refused > 0 ? 'blocks' : 'log only'}</span>
              </span>
              <span className="wr-num" style={{ color: color.heading }}>
                {live ? perMin(value(r)) : short(value(r))}
              </span>
            </div>
            <div style={{ height: 8, background: '#1a1a1a', borderRadius: 4 }}>
              <div style={{ height: 8, width: `${Math.round((value(r) / top) * 100)}%`, background: r.refused > 0 ? color.amber : color.muted, borderRadius: 4 }} />
            </div>
          </div>
        );
      })}
    </Widget>
  );
}
