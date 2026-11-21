import { keepPreviousData, useMutation, useQuery } from '@tanstack/react-query';
import { type GeoProjection, geoEqualEarth, geoMercator, geoPath } from 'd3-geo';
import { type MouseEvent as ReactMouseEvent, type PointerEvent, useCallback, useState } from 'react';
import { api, useCan } from '../../api';
import { useLogSearch } from '../../logSearch';
import { Link } from '../../router';
import { ShipperHint } from '../Routes';
import { labels, outlines, unnamed } from '../world';
import { color, fmt, Head, between, short, share, type View, Widget } from './shared';

interface Country {
  country: string;
  requests: number;
  blocked: number;
  estimated: number;
}
interface Traffic {
  from: string;
  to: string;
  countries: Country[];
  edge: { lat: number; long: number; name?: string } | null;
  series?: { at: string; requests: number; blocked: number; estimated: number }[];
}

// unknown and * hold lines with no usable country and counts past admin's
// cap, so neither is a place.
const unknown = 'unknown';
const other = '*';
const isPlace = (c: string) => c !== unknown && c !== other;
const placed = (c: string) => isPlace(c) && c in labels;

let names: Intl.DisplayNames | undefined;
// nameOf is the country's name in the browser's language, or its code where
// the browser does not know it.
function nameOf(code: string) {
  if (code === unknown) return 'Country not known';
  if (code === other) return 'Other countries';
  try {
    names ??= new Intl.DisplayNames(undefined, { type: 'region' });
    return names.of(code) ?? code;
  } catch {
    return code;
  }
}

const W = 800;
const H = 360;

// A shortest route that crosses the map's edge would draw as two cut pieces, so it becomes one arc across the map. Other routes stay great circles.
function lineTo(projection: GeoProjection, from: [number, number], to: [number, number]): string | null {
  const d = geoPath(projection)({ type: 'LineString', coordinates: [from, to] });
  const a = projection(from);
  const b = projection(to);
  if (!d || (d.match(/M/g) ?? []).length < 2 || !a || !b) return d;
  const [dx, dy] = [b[0] - a[0], b[1] - a[1]];
  const k = dx > 0 ? 0.2 : -0.2; // the chord's normal that points toward smaller y
  const cx = (a[0] + b[0]) / 2 + k * dy;
  const cy = Math.max(8, (a[1] + b[1]) / 2 - k * dx);
  return `M${a[0]},${a[1]}Q${cx},${cy} ${b[0]},${b[1]}`;
}
// The Europe inset: a framed box at the bottom left, and the extent it shows.
const box: [[number, number], [number, number]] = [
  [8, 200],
  [200, 352],
];
const lon0 = -11;
const lon1 = 31;
const lat0 = 35;
const lat1 = 61;
const inEurope = (at: readonly [number, number]) => at[0] >= lon0 && at[0] <= lon1 && at[1] >= lat0 && at[1] <= lat1;

const shapes = Object.entries(outlines).map(([code, coordinates]) => [code, { type: 'MultiPolygon' as const, coordinates }] as const);
const plain = { type: 'MultiPolygon' as const, coordinates: unnamed };
// Fitted to the outlines, so the whole land fills the box.
const world = geoEqualEarth().fitSize([W, H], { type: 'GeometryCollection', geometries: [...shapes.map((s) => s[1]), plain] });
const europe = geoMercator()
  .fitExtent(box, {
    type: 'MultiPoint',
    coordinates: [
      [lon0, lat0],
      [lon1, lat1],
    ],
  })
  // Clipped, so the inset shows only its box.
  .clipExtent(box);
// Computed once: the outlines never change and there are about 175 of them.
const worldPath = geoPath(world);
const europePath = geoPath(europe);
const landPaths = shapes.map(([code, s]) => ({ code, world: worldPath(s) ?? '', europe: europePath(s) ?? '' }));
const plainPaths = { world: worldPath(plain) ?? '', europe: europePath(plain) ?? '' };

const amberAt = 0.05;
const k = { min: 1, max: 8 };
type Zoom = { k: number; tx: number; ty: number };
const fit: Zoom = { k: 1, tx: 0, ty: 0 };
// clampZoom keeps the map covering its box: tx and ty are fractions of it.
const clampZoom = (z: Zoom): Zoom => {
  const kk = Math.max(k.min, Math.min(k.max, z.k));
  return { k: kk, tx: Math.max(1 - kk, Math.min(0, z.tx)), ty: Math.max(1 - kk, Math.min(0, z.ty)) };
};
// zoomAt keeps the point at fractions (px, py) of the box where it is.
const zoomAt = (m: Zoom, factor: number, px: number, py: number) => {
  const k2 = Math.max(k.min, Math.min(k.max, m.k * factor));
  return clampZoom({ k: k2, tx: px - ((px - m.tx) / m.k) * k2, ty: py - ((py - m.ty) / m.k) * k2 });
};

function useTraffic(params: string | null, live: boolean) {
  return useQuery({
    queryKey: ['traffic', params],
    queryFn: () => api<Traffic>('GET', `/api/traffic?${params}`),
    enabled: params !== null,
    refetchInterval: live ? 10_000 : 30_000,
    // Keeps the map on screen while another window loads.
    placeholderData: keepPreviousData,
  });
}

// kept is whether admin still holds counts from t, which it keeps for 30 days.
const kept = (t: number) => t >= Date.now() - 30 * 86_400_000;

const minutesOf = (t: Traffic) => (Date.parse(t.to) - Date.parse(t.from)) / 60_000;

export function WarMap({ view, wall, expanded, onExpand }: { view: View; wall: boolean; expanded: string | null; onExpand: (name: string | null) => void }) {
  const [picked, setPicked] = useState<string | null>(null);
  const [zoom, setZoom] = useState<Zoom>(fit);
  const [pan, setPan] = useState<{ x: number; y: number; tx: number; ty: number } | null>(null);

  const iso = (t: number) => new Date(t).toISOString();
  const win = `from=${iso(view.from)}&to=${iso(view.to)}`;
  const now = view.live ? 'minutes=5' : win;
  const q = useTraffic(now, view.live);
  // Admin rounds each request outward on its own, so the window before is built
  // from the window it answered for the shown span, not from the view; past the
  // longest period admin keeps there is none.
  const shown = q.data && !q.isPlaceholderData ? q.data : null;
  const shownFrom = shown ? Date.parse(shown.from) : 0;
  const start = shown ? shownFrom - (Date.parse(shown.to) - shownFrom) : 0;
  const before = view.live ? 'minutes=60' : shown && kept(start) ? `from=${iso(start)}&to=${iso(shownFrom)}` : null;
  const qBefore = useTraffic(before, view.live);
  const qSeries = useTraffic(picked ? `${view.live ? 'minutes=60' : win}&country=${picked}` : null, view.live);

  // The wheel must not scroll the page, which React's passive onWheel cannot stop.
  // A callback ref follows the box, which mounts only once countries arrive.
  const boxRef = useCallback(
    (el: HTMLDivElement | null) => {
      if (!el || wall) return;
      const onWheel = (e: WheelEvent) => {
        e.preventDefault();
        const b = el.getBoundingClientRect();
        setZoom((m) => zoomAt(m, Math.pow(1.0015, -e.deltaY), (e.clientX - b.left) / b.width, (e.clientY - b.top) / b.height));
      };
      el.addEventListener('wheel', onWheel, { passive: false });
      return () => el.removeEventListener('wheel', onWheel);
    },
    [wall],
  );

  const d = q.data;
  const label = 'Where requests come from';
  const style = { flex: '1.1 1 440px' };
  // Admin rounds a period outward, so it names the window it answered.
  const when = q.data ? between(q.data.from, q.data.to) : null;
  const span = view.live ? 'in the last 5 minutes' : when ? `from ${when}` : `in the ${view.inView}`;
  const title = view.live ? 'Requests flowing to the edges' : `Where requests came from, ${when ?? span}`;
  if (!d)
    return (
      <Widget label={label} name="map" expanded={expanded} onExpand={onExpand} wall={wall} style={style}>
        <Head title={title} />
        <p role={q.error ? 'alert' : 'status'}>{q.error ? `Could not load traffic: ${q.error.message}` : 'Loading…'}</p>
      </Widget>
    );

  const countries = [...d.countries].sort((a, b) => b.requests - a.requests);
  const total = countries.reduce((n, c) => n + c.requests, 0);
  const mins = minutesOf(d);
  const prior = qBefore.isPlaceholderData ? undefined : qBefore.data;
  // Live's hour includes the 5 minutes shown, so they are taken out; a period's
  // window before is its own, and may come from coarser rows, so only rates compare.
  const overlap = view.live ? 1 : 0;
  const priorMins = prior ? minutesOf(prior) - overlap * mins : 0;
  const priorBy = new Map(prior?.countries.map((c) => [c.country, c.requests]));
  const rate = (c: Country) => (mins > 0 ? c.requests / mins : 0);
  // How much faster than the time before, or undefined where there is nothing to compare.
  const vsOf = (c: Country) => {
    // Windows that still overlap after rounding would compare a span with itself.
    if (!view.live && prior && Date.parse(prior.to) > Date.parse(d.from)) return undefined;
    const was = prior && priorMins > 0 ? ((priorBy.get(c.country) ?? 0) - overlap * c.requests) / priorMins : 0;
    return was > 0 ? rate(c) / was : undefined;
  };
  const amountOf = (c: Country) => (view.live ? fmt(rate(c)) : short(c.requests));
  const refusedOf = (c: Country) => (c.requests > 0 ? c.blocked / c.requests : 0);
  const vsText = (c: Country) => {
    const v = vsOf(c);
    return v === undefined ? '—' : `${v.toFixed(1)}×`;
  };
  const places = countries.filter((c) => placed(c.country));
  const edge = d.edge;
  const edgeAt: [number, number] | null = edge ? [edge.long, edge.lat] : null;
  const edgeInEurope = !!edgeAt && inEurope(edgeAt);
  const pickedRow = picked ? countries.find((c) => c.country === picked) : undefined;
  const shareOf = new Map(countries.map((c) => [c.country, c.requests / Math.max(1, total)]));
  const tip = (c: Country) => `${nameOf(c.country)}: ${amountOf(c)} ${view.live ? 'a minute' : 'requests'}, ${(refusedOf(c) * 100).toFixed(1)}% refused. Select for detail.`;
  const flows = places.slice(0, 14).map((c) => {
    const at = labels[c.country]!;
    const inset = inEurope(at);
    const s = Math.sqrt(shareOf.get(c.country) ?? 0);
    // The line is drawn in the inset only when both its ends are in it.
    const inLine = inset && edgeInEurope;
    const projection = inLine ? europe : world;
    const p = (inset ? europe : world)(at) ?? [0, 0];
    return {
      c,
      inLine,
      // A pin in the inset whose line runs on the world map needs a mark where the line starts.
      start: inset && !inLine ? world(at) : null,
      x: p[0],
      y: p[1],
      s,
      w: 0.8 + 5 * s,
      d: edgeAt ? lineTo(projection, at, edgeAt) : null,
    };
  });
  // The busiest is drawn last, so it is on top and its pin is the one a click reaches.
  const drawn = [...flows].reverse();
  const pick = (code: string) => setPicked((p) => (p === code ? null : code));

  const onDown = (e: PointerEvent) => {
    if (zoom.k <= 1 || e.button !== 0) return;
    setPan({ x: e.clientX, y: e.clientY, tx: zoom.tx, ty: zoom.ty });
  };
  const onMove = (e: PointerEvent) => {
    if (!pan) return;
    const b = e.currentTarget.getBoundingClientRect();
    setZoom((m) => clampZoom({ k: m.k, tx: pan.tx + (e.clientX - pan.x) / b.width, ty: pan.ty + (e.clientY - pan.y) / b.height }));
  };
  const onDouble = (e: ReactMouseEvent) => {
    const b = e.currentTarget.getBoundingClientRect();
    setZoom((m) => zoomAt(m, e.shiftKey ? 0.5 : 2, (e.clientX - b.left) / b.width, (e.clientY - b.top) / b.height));
  };
  const rows = countries.slice(0, wall ? 5 : 8);
  const dot = (c: Country) => (refusedOf(c) > amberAt ? color.amber : color.heading);
  // Square root: a country with 1% of requests still stands out from bare land.
  const landFill = (code: string) => {
    const s = shareOf.get(code);
    const g = s === undefined ? 38 : Math.round(38 + 90 * Math.sqrt(s));
    return `rgb(${g} ${g} ${g})`;
  };
  const diamond = (at: [number, number] | null) => at && <rect x={-4.5} y={-4.5} width={9} height={9} transform={`translate(${at[0]} ${at[1]}) rotate(45)`} fill="#0a0a0a" stroke={color.heading} strokeWidth={2} />;

  // Lines with a world start paint under the inset, so it covers any that cross it.
  const flowsOf = (inLine: boolean) =>
    drawn.map(({ c, d: path, w, s, inLine: own }) => {
      if (!path || own !== inLine) return null;
      const bad = refusedOf(c) > amberAt;
      return (
        <g key={c.country}>
          <path d={path} fill="none" stroke={color.heading} strokeOpacity={view.live ? 0.18 : 0.55} strokeWidth={w} strokeLinecap="round" vectorEffect="non-scaling-stroke" />
          {view.live && <path className="wr-flow" d={path} fill="none" stroke={color.heading} strokeWidth={w} strokeLinecap="round" style={{ animationDuration: `${2.6 - 1.8 * s}s` }} />}
          {bad && (
            <path
              className={view.live ? 'wr-flow-warn' : undefined}
              d={path}
              fill="none"
              stroke={color.amber}
              strokeWidth={Math.max(1.5, w * 0.8)}
              strokeLinecap="round"
              strokeDasharray={view.live ? undefined : '3 6'}
              vectorEffect="non-scaling-stroke"
              style={view.live ? { animationDuration: `${2.6 - 1.8 * s}s` } : undefined}
            />
          )}
        </g>
      );
    });

  return (
    <Widget label={label} name="map" expanded={expanded} onExpand={onExpand} wall={wall} style={style}>
      <Head title={title}>{edge?.name && <span style={{ fontSize: 14 }}>Edges in {edge.name}</span>}</Head>
      {countries.length === 0 ? (
        <>
          <p className="wr-h2">No access logs {span}</p>
          <p>
            <ShipperHint />
          </p>
        </>
      ) : (
        <>
          {places.length === 0 && (
            <p style={{ color: color.amber }}>
              No request {span} carries a country, so none can be placed on the map. The edge logs a country only from a trusted viewer header: set <code>CLIENT_IP_SOURCE</code> to a CDN that sends one, or name the header in <code>VIEWER_HEADERS</code>.
            </p>
          )}
          <div style={{ position: 'relative' }}>
            <div
              ref={boxRef}
              role="group"
              aria-label="Map, scroll to zoom"
              onPointerDown={onDown}
              onPointerMove={onMove}
              onPointerUp={() => setPan(null)}
              onPointerLeave={() => setPan(null)}
              onDoubleClick={onDouble}
              style={{ position: 'relative', width: '100%', overflow: 'hidden', borderRadius: 6, userSelect: 'none', touchAction: zoom.k > 1 ? 'none' : undefined, cursor: pan ? 'grabbing' : zoom.k > 1 ? 'grab' : 'default' }}
            >
              <div style={{ position: 'relative', width: '100%', transformOrigin: '0 0', transform: `translate(${zoom.tx * 100}%, ${zoom.ty * 100}%) scale(${zoom.k})` }}>
                <svg viewBox={`0 0 ${W} ${H}`} style={{ display: 'block', width: '100%', height: 'auto', background: '#000' }}>
                  <g stroke="#0a0a0a" strokeWidth={0.5}>
                    <path d={plainPaths.world} fill="#262626" />
                    {landPaths.map((l) => (
                      <path key={l.code} d={l.world} fill={landFill(l.code)} />
                    ))}
                  </g>
                  {flowsOf(false)}
                  <rect x={box[0][0]} y={box[0][1]} width={box[1][0] - box[0][0]} height={box[1][1] - box[0][1]} fill="#0a0a0a" stroke="rgba(255,255,255,.3)" />
                  <g stroke="#0a0a0a" strokeWidth={0.5}>
                    <path d={plainPaths.europe} fill="#262626" />
                    {landPaths.map((l) => l.europe && <path key={l.code} d={l.europe} fill={landFill(l.code)} />)}
                  </g>
                  <text x={box[0][0] + 8} y={box[0][1] + 14} fontSize={13} fill={color.body} fontFamily="var(--font-mono)">
                    EUROPE
                  </text>
                  {flowsOf(true)}
                  {drawn.map(({ c, start }) => start && <circle key={c.country} cx={start[0]} cy={start[1]} r={2} fill={dot(c)} aria-hidden="true" />)}
                  {drawn.map(({ c, x, y, s }) => (
                    <g key={c.country}>
                      {c.country === picked && <circle cx={x} cy={y} r={2.5 + 4 * s + 4} fill="none" stroke={color.blue} strokeWidth={3} />}
                      <circle cx={x} cy={y} r={2.5 + 4 * s} fill={dot(c)} stroke="#0a0a0a" strokeWidth={1.5} />
                    </g>
                  ))}
                  {edgeAt && diamond(world(edgeAt))}
                  {edgeAt && edgeInEurope && diamond(europe(edgeAt))}
                </svg>
                {drawn.map(({ c, x, y }) => (
                  <button
                    key={c.country}
                    type="button"
                    className="wr-pin"
                    aria-label={tip(c)}
                    title={tip(c)}
                    aria-pressed={c.country === picked}
                    onClick={() => pick(c.country)}
                    style={{ position: 'absolute', left: `${(x / W) * 100}%`, top: `${(y / H) * 100}%`, width: 26, height: 26, transform: `translate(-50%, -50%) scale(${1 / zoom.k})`, borderRadius: '50%', border: 0, padding: 0, background: 'transparent', cursor: 'pointer' }}
                  />
                ))}
              </div>
            </div>
            {!wall && (
              <div role="group" aria-label="Map zoom" style={{ position: 'absolute', top: 8, right: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
                <button type="button" className="wr-btn wr-zbtn" aria-label="Zoom in" onClick={() => setZoom((m) => zoomAt(m, 1.6, 0.5, 0.5))}>
                  +
                </button>
                <button type="button" className="wr-btn wr-zbtn" aria-label="Zoom out" disabled={zoom.k <= 1} onClick={() => setZoom((m) => zoomAt(m, 1 / 1.6, 0.5, 0.5))}>
                  −
                </button>
                <button type="button" className="wr-btn wr-zbtn" aria-label="Fit the whole map" style={{ fontSize: 11 }} onClick={() => setZoom(fit)}>
                  Fit
                </button>
              </div>
            )}
            {zoom.k > 1 && (
              <span className="wr-mono" style={{ position: 'absolute', right: 56, top: 8, fontSize: 12, color: color.body, background: 'rgba(10,10,10,.75)', padding: '0 4px', borderRadius: 3 }}>
                {zoom.k.toFixed(1)}×
              </span>
            )}
          </div>
          {!edge && (
            <p style={{ fontSize: 14 }}>
              <Link to="/settings#edge-place">Set where the edges are in Settings to draw the flows.</Link>
            </p>
          )}
          {!wall && pickedRow && (
            <CountryPanel
              key={pickedRow.country}
              c={pickedRow}
              name={nameOf(pickedRow.country)}
              view={view}
              range={[Date.parse(d.from), Date.parse(d.to)]}
              span={span}
              figures={{ amount: amountOf(pickedRow), share: share(pickedRow.requests, total), refused: share(pickedRow.blocked, pickedRow.requests), vs: vsText(pickedRow), bad: refusedOf(pickedRow) > amberAt, surge: (vsOf(pickedRow) ?? 0) >= 2 }}
              series={qSeries.isPlaceholderData ? undefined : qSeries.data?.series}
              seriesSpan={qSeries.isPlaceholderData || !qSeries.data ? undefined : [Date.parse(qSeries.data.from), Date.parse(qSeries.data.to)]}
              onClose={() => setPicked(null)}
            />
          )}
          <div role="table" aria-label="Countries" style={{ display: 'flex', flexDirection: 'column', fontSize: 15 }}>
            <div role="row" className="wr-eyebrow wr-row" style={{ cursor: 'default', borderTop: 0 }}>
              <span role="columnheader">Country</span>
              <span role="columnheader" style={{ textAlign: 'right' }}>
                {view.live ? 'A minute' : 'Requests'}
              </span>
              <span role="columnheader" style={{ textAlign: 'right' }}>
                Refused
              </span>
              <span role="columnheader" style={{ textAlign: 'right' }}>
                Vs before
              </span>
            </div>
            {rows.map((c) => (
              // A button cannot be a row, so the name cell holds it and it covers the row.
              <div key={c.country} role="row" className="wr-row">
                <span role="cell" style={{ color: color.heading }}>
                  <button type="button" className="wr-rowbtn" aria-pressed={c.country === picked} onClick={() => pick(c.country)}>
                    {nameOf(c.country)}
                  </button>
                  {isPlace(c.country) && !placed(c.country) && <span style={{ color: color.muted }}> · not on the map</span>}
                </span>
                <span role="cell" className="wr-num" style={{ textAlign: 'right' }}>
                  {c.estimated > 0 && <span title="Estimated from sampled access logs">≈ </span>}
                  {amountOf(c)}
                </span>
                <span role="cell" className="wr-num" style={{ textAlign: 'right', color: refusedOf(c) > amberAt ? color.amber : color.body }}>
                  {share(c.blocked, c.requests)}
                </span>
                <span role="cell" className="wr-num" style={{ textAlign: 'right', fontWeight: 600, color: (vsOf(c) ?? 0) >= 2 ? color.amber : color.body }}>
                  {vsText(c)}
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </Widget>
  );
}

// CountryPanel is the picked country's figures, its trend and what to do about it.
// It is keyed by country, so a case opened for one is not shown for another.
function CountryPanel({
  c,
  name,
  view,
  range,
  span,
  figures,
  series,
  seriesSpan: win,
  onClose,
}: {
  c: Country;
  name: string;
  view: View;
  range: [number, number];
  span: string;
  figures: { amount: string; share: string; refused: string; vs: string; bad: boolean; surge: boolean };
  series: Traffic['series'];
  seriesSpan: [number, number] | undefined;
  onClose: () => void;
}) {
  const can = useCan();
  const logs = useLogSearch()({ from: range[0], to: range[1], country: isPlace(c.country) ? c.country : undefined });
  const ask = useMutation({
    mutationFn: () =>
      api<{ id: number }>('POST', '/api/autopilot/cases', {
        question: `Look at traffic from ${name} (${c.country}) ${span}: ${figures.amount} ${view.live ? 'a minute' : 'requests'}, ${figures.refused} refused, ${figures.vs} against the time before. Is any of it an attack, and what should the edge do?`,
      }),
  });
  const points = (f: (p: NonNullable<Traffic['series']>[number]) => number) => {
    const max = Math.max(1, ...(series ?? []).map((p) => p.requests));
    const [t0, t1] = win ?? [0, 1];
    // Buckets without rows are omitted, so x comes from the time, not the index.
    return (series ?? []).map((p) => `${(((Date.parse(p.at) - t0) / Math.max(1, t1 - t0)) * 400).toFixed(1)},${(56 - (f(p) / max) * 52).toFixed(1)}`).join(' ');
  };
  const fig = (name: string, value: string, c?: string) => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span className="wr-eyebrow">{name}</span>
      <span className="wr-num" style={{ color: c ?? color.heading, fontSize: 22, fontWeight: 600 }}>
        {value}
      </span>
    </div>
  );
  return (
    <div style={{ borderRadius: 8, padding: 14, background: '#0f1520', boxShadow: '0 0 0 1px rgba(76,157,255,.5)', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
        <span style={{ color: color.heading, fontSize: 18, fontWeight: 600 }}>{name}</span>
        <button type="button" className="wr-btn" aria-label="Close country detail" onClick={onClose}>
          Close
        </button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 10 }}>
        {fig(view.live ? 'A minute' : 'Requests', figures.amount)}
        {fig('Share', figures.share)}
        {fig('Refused', figures.refused, figures.bad ? color.amber : undefined)}
        {fig('Vs before', figures.vs, figures.surge ? color.amber : undefined)}
      </div>
      {series && series.length > 0 && (
        <svg role="img" aria-label={`Requests from ${name} (blue) and the part refused (amber), ${view.live ? 'in the last hour' : span}.`} viewBox="0 0 400 60" preserveAspectRatio="none" style={{ display: 'block', width: '100%', height: 60 }}>
          <polyline points={points((p) => p.requests)} fill="none" stroke={color.blue} strokeWidth={2} />
          <polyline points={points((p) => p.blocked)} fill="none" stroke={color.amber} strokeWidth={2} />
        </svg>
      )}
      <span style={{ fontSize: 13 }}>
        <span style={{ color: color.blue }}>━</span> requests <span style={{ color: color.amber, marginLeft: 10 }}>━</span> refused
      </span>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {can('autopilot.manage') && (
          <button type="button" className="wr-btn wr-btn-primary" disabled={ask.isPending || ask.isSuccess} onClick={() => ask.mutate()}>
            Ask autopilot about {name}
          </button>
        )}
        {logs && (
          <a className="wr-btn" href={logs} target="_blank" rel="noreferrer">
            Search its access logs
          </a>
        )}
      </div>
      <div role="status">
        {ask.isSuccess && (
          <span style={{ color: color.green }}>
            Case {ask.data.id} opened: the autopilot is looking at traffic from {name}.{' '}
            <Link to={`/autopilot/cases/${ask.data.id}`}>Open case {ask.data.id}</Link>
          </span>
        )}
        {ask.isError && <span style={{ color: color.red }}>{ask.error.message}</span>}
      </div>
    </div>
  );
}
