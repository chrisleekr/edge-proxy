import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { geoDistance, geoOrthographic, geoPath } from 'd3-geo';
import { type FormEvent, type KeyboardEvent, type PointerEvent, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { api, useCan } from '../api';
import { useSearch } from '../router';
import { Badge, Button, Card, ErrorBox, Input, Notice, Page, Pending, Table } from '../ui';
import { count, pct, RangeSelect } from './Fleet';
import { ShipperHint, useHours } from './Routes';
import { labels, outlines, unnamed } from './world';

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
  edge: { lat: number; long: number } | null;
}

// unknown and * hold lines with no usable country and counts past admin's
// cap, so neither is a place.
const unknown = 'unknown';
const other = '*';
const isPlace = (c: string) => c !== unknown && c !== other;

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

const size = 400;
const radius = 190;
// Degrees a live globe turns in a second.
const spin = 3;

const shapes = Object.entries(outlines).map(([code, coordinates]) => [code, { type: 'MultiPolygon' as const, coordinates }] as const);
const plain = { type: 'MultiPolygon' as const, coordinates: unnamed };
// land is the fill of a place with no traffic.
const land = 'color-mix(in srgb, var(--color-muted) 22%, var(--color-soft))';

// At module scope so React keeps one subscription instead of resubscribing
// on every render.
const reducedQuery = '(prefers-reduced-motion: reduce)';
function subscribeReduced(notify: () => void) {
  const m = matchMedia(reducedQuery);
  m.addEventListener('change', notify);
  return () => m.removeEventListener('change', notify);
}
const reducedNow = () => matchMedia(reducedQuery).matches;
const useReducedMotion = () => useSyncExternalStore(subscribeReduced, reducedNow);

const wrap = (lon: number) => ((((lon + 180) % 360) + 360) % 360) - 180;
const clampLat = (lat: number) => Math.max(-85, Math.min(85, lat));

// Globe draws countries on an orthographic globe: shaded by their share of
// requests, with a circle sized by the same share (so a period reads like the
// live view), a triangle beside it sized by the part the edge refused, and an
// arc to the edges when their place is set.
// A live globe turns; drag it or press the arrow keys to turn it by hand.
function Globe({ data, live, summary }: { data: Traffic; live: boolean; summary: string }) {
  const total = data.countries.reduce((n, c) => n + c.requests, 0);
  const [view, setView] = useState<[number, number]>(() => {
    // Facing the edges, else the busiest country.
    const busiest = data.countries.find((c) => c.country in labels);
    const at: readonly [number, number] = data.edge ? [data.edge.long, data.edge.lat] : busiest ? labels[busiest.country]! : [0, 20];
    return [at[0], clampLat(at[1])];
  });
  const reduced = useReducedMotion();
  const held = useRef<[number, number] | null>(null);
  useEffect(() => {
    if (!live || reduced) return;
    let last = performance.now();
    let frame = requestAnimationFrame(function tick(t) {
      // 20 frames a second is enough for a slow turn and spares the paths.
      if (t - last >= 50) {
        // Capped, and time held counts too, so the globe does not jump after a
        // drag or a hidden tab.
        const dt = Math.min(t - last, 100) / 1000;
        if (!held.current) setView(([lon, lat]) => [wrap(lon + spin * dt), lat]);
        last = t;
      }
      frame = requestAnimationFrame(tick);
    });
    return () => cancelAnimationFrame(frame);
  }, [live, reduced]);

  const [lon, lat] = view;
  const projection = geoOrthographic().scale(radius).translate([size / 2, size / 2]).rotate([-lon, -lat]);
  const path = geoPath(projection);
  const facing = (at: [number, number]) => geoDistance(at, [lon, lat]) <= Math.PI / 2;
  const share = new Map(data.countries.map((c) => [c.country, c.requests / Math.max(1, total)]));
  const byCode = new Map(data.countries.map((c) => [c.country, c]));
  // tip is the hover text: the name, and the counts when the country has traffic.
  const tip = (code: string) => {
    const c = byCode.get(code);
    return c ? `${nameOf(code)}: ${count(c.requests)} requests, ${count(c.blocked)} blocked` : nameOf(code);
  };
  const marks = data.countries.filter((c) => isPlace(c.country) && c.country in labels && facing(labels[c.country]!));
  const edge = data.edge;
  const turn = (dLon: number, dLat: number) => setView(([a, b]) => [wrap(a + dLon), clampLat(b + dLat)]);
  const onKey = (e: KeyboardEvent) => {
    const by: Record<string, [number, number]> = { ArrowLeft: [-10, 0], ArrowRight: [10, 0], ArrowUp: [0, 10], ArrowDown: [0, -10] };
    const d = by[e.key];
    if (!d) return;
    e.preventDefault();
    turn(...d);
  };
  const onMove = (e: PointerEvent) => {
    if (!held.current) return;
    const [x, y] = held.current;
    held.current = [e.clientX, e.clientY];
    // The globe is drawn at most its viewBox's size: scale pixels to degrees.
    const k = 60 / (e.currentTarget.getBoundingClientRect().width / 2);
    turn(-(e.clientX - x) * k, (e.clientY - y) * k);
  };
  return (
    <svg
      role="img"
      aria-label={summary}
      tabIndex={0}
      data-live={live || undefined}
      viewBox={`0 0 ${size} ${size}`}
      className="mx-auto w-full max-w-lg cursor-grab touch-none select-none rounded-card focus-visible:outline-2"
      onKeyDown={onKey}
      onPointerDown={(e) => {
        e.currentTarget.setPointerCapture(e.pointerId);
        held.current = [e.clientX, e.clientY];
      }}
      onPointerMove={onMove}
      onPointerUp={() => (held.current = null)}
      onPointerCancel={() => (held.current = null)}
    >
      <circle cx={size / 2} cy={size / 2} r={radius} fill="var(--color-soft)" stroke="var(--color-line)" />
      <g stroke="var(--color-panel)" strokeWidth={0.5}>
        <path d={path(plain) ?? ''} fill={land} />
        {shapes.map(([code, shape]) => {
          const s = share.get(code);
          // Square root: a country with 1% of requests still stands out from bare land.
          const fill = s === undefined ? land : `color-mix(in srgb, var(--color-brand) ${Math.round(25 + 60 * Math.sqrt(s))}%, var(--color-soft))`;
          return (
            <path key={code} data-country={code} d={path(shape) ?? ''} fill={fill}>
              <title>{tip(code)}</title>
            </path>
          );
        })}
      </g>
      {edge &&
        marks.slice(0, 30).map((c) => {
          const d = path({ type: 'LineString', coordinates: [labels[c.country]!, [edge.long, edge.lat]] });
          return d ? <path key={c.country} className="arc" d={d} fill="none" stroke="var(--color-heading)" strokeOpacity={0.55} strokeWidth={1} /> : null;
        })}
      {marks.map((c) => {
        const at = projection(labels[c.country]!);
        if (!at) return null;
        // Square roots so area, not radius, follows the share.
        const r = 3 + 13 * Math.sqrt(share.get(c.country) ?? 0);
        const t = 3 + 4 * Math.sqrt(c.blocked / Math.max(1, c.requests));
        return (
          <g key={c.country} data-mark={c.country} transform={`translate(${at[0]} ${at[1]})`}>
            <title>{tip(c.country)}</title>
            {live && <circle className="pulse" r={r} fill="var(--color-heading)" fillOpacity={0.35} />}
            <circle r={r} fill="var(--color-heading)" fillOpacity={0.8} stroke="var(--color-panel)" strokeWidth={1} />
            {c.blocked > 0 && <path transform={`translate(${r + t + 1} 0)`} d={`M0 ${-t}L${t} ${t * 0.8}L${-t} ${t * 0.8}Z`} fill="var(--color-danger)" stroke="var(--color-panel)" strokeWidth={1} />}
          </g>
        );
      })}
      {edge && facing([edge.long, edge.lat]) && (
        <g transform={`translate(${projection([edge.long, edge.lat])!.join(' ')})`}>
          <rect x={-5} y={-5} width={10} height={10} transform="rotate(45)" fill="var(--color-panel)" stroke="var(--color-heading)" strokeWidth={2} />
        </g>
      )}
    </svg>
  );
}

// EdgePlace sets where the edges are, which the map shows as the diamond and
// the lines to it. It applies at once and is audited.
function EdgePlace({ edge }: { edge: Traffic['edge'] }) {
  const qc = useQueryClient();
  const [lat, setLat] = useState(edge ? String(edge.lat) : '');
  const [long, setLong] = useState(edge ? String(edge.long) : '');
  const save = useMutation({
    mutationFn: (place: Traffic['edge']) => api('PUT', '/api/settings/traffic-map', { edge: place }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['traffic'] }),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate({ lat: Number(lat), long: Number(long) });
  };
  const filled = lat.trim() !== '' && long.trim() !== '';
  return (
    <Card title="Where the edges are" intro="Shown as the diamond and the lines to it. Give latitude and longitude in decimal degrees, such as 50.11 and 8.68 for Frankfurt. It applies at once and is audited.">
      <form onSubmit={submit} className="flex flex-col items-start gap-3">
        <div className="flex flex-wrap gap-3">
          <Input label="Latitude" type="number" step="any" value={lat} onChange={(e) => setLat(e.target.value)} />
          <Input label="Longitude" type="number" step="any" value={long} onChange={(e) => setLong(e.target.value)} />
        </div>
        <ErrorBox error={save.error} />
        {save.isSuccess && <Notice>Saved.</Notice>}
        <div className="flex gap-2">
          <Button type="submit" variant="primary" disabled={!filled || save.isPending}>
            Save
          </Button>
          <Button
            disabled={!edge || save.isPending}
            onClick={() => {
              setLat('');
              setLong('');
              save.mutate(null);
            }}
          >
            Clear
          </Button>
        </div>
      </form>
    </Card>
  );
}

export function TrafficMap() {
  const can = useCan();
  const [params, set] = useSearch();
  const live = params.get('view') !== 'period';
  const range = useHours();
  const q = useQuery({
    queryKey: ['traffic', live ? 'live' : range.hours],
    queryFn: () => api<Traffic>('GET', `/api/traffic?${live ? 'minutes=5' : `hours=${range.hours}`}`),
    refetchInterval: live ? 10_000 : 30_000,
    // Keeps the page, and the edge place form's typed values, mounted while
    // another view or range loads.
    placeholderData: keepPreviousData,
  });
  const d = q.data;
  const total = d?.countries.reduce((n, c) => n + c.requests, 0) ?? 0;
  const places = d?.countries.filter((c) => isPlace(c.country)) ?? [];
  const summary = `Globe of requests by country. ${places.slice(0, 5).map((c) => `${nameOf(c.country)}: ${count(c.requests)}`).join(', ') || 'No country to show.'}`;
  const phrase = live ? 'in the last 5 minutes' : `in the ${range.label}`;
  return (
    <Page
      title="Traffic map"
      info="Where requests come from, counted from the access logs by the viewer's country. Only counts are kept, never client addresses."
      actions={
        <>
          <div role="group" aria-label="View" className="flex gap-1">
            <Button aria-pressed={live} variant={live ? 'primary' : 'default'} onClick={() => set({ view: '' })}>
              Live
            </Button>
            <Button aria-pressed={!live} variant={live ? 'default' : 'primary'} onClick={() => set({ view: 'period' })}>
              Period
            </Button>
          </div>
          {!live && <RangeSelect value={range.key} onChange={range.pick} />}
        </>
      }
    >
      {!d ? (
        <Pending error={q.error} />
      ) : d.countries.length === 0 ? (
        <Card title={`No access logs ${phrase}`}>
          <p className="max-w-prose text-body">
            <ShipperHint />
          </p>
        </Card>
      ) : (
        <>
          {places.length === 0 && (
            <Notice tone="amber">
              No request {phrase} carries a country, so none can be placed on the map. The edge logs a country only from a trusted viewer header: set <code>CLIENT_IP_SOURCE</code> to a CDN that sends
              one, or name the header in <code>VIEWER_HEADERS</code>.
            </Notice>
          )}
          <Card>
            <Globe key={live ? 'live' : 'period'} data={d} live={live} summary={summary} />
            <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-sm text-body">
              <li>
                <span aria-hidden className="mr-1.5 inline-block size-2.5 rounded-full bg-heading/80 align-middle" />
                Circle: the country's share of requests
              </li>
              <li>
                <span aria-hidden className="mr-1.5 inline-block align-middle text-danger">
                  ▲
                </span>
                Triangle: the part of them the edge refused
              </li>
              {d.edge && (
                <li>
                  <span aria-hidden className="mr-1.5 inline-block size-2 rotate-45 border-2 border-heading align-middle" />
                  Diamond and lines: the edges
                </li>
              )}
            </ul>
          </Card>
          <Table head={['Country', 'Requests', 'Blocked', 'Share']} num={[1, 2, 3]}>
            {d.countries.map((c) => (
              <tr key={c.country}>
                <td>
                  {nameOf(c.country)}
                  {isPlace(c.country) && !(c.country in labels) && (
                    <span className="ml-2">
                      <Badge>Not on the map</Badge>
                    </span>
                  )}
                </td>
                <td className="text-right tabular-nums">
                  {c.estimated > 0 && <span title="Estimated from sampled access logs">≈ </span>}
                  {count(c.requests)}
                </td>
                <td className="text-right tabular-nums">{c.blocked > 0 ? count(c.blocked) : '—'}</td>
                <td className="text-right tabular-nums">{pct(c.requests, total)}</td>
              </tr>
            ))}
          </Table>
          <p className="text-sm text-body">
            Counted from the access logs {phrase}: {count(total)} requests.{' '}
            {d.countries.some((c) => c.estimated > 0)
              ? 'Counts marked ≈ are estimates: the edges log only a share of allowed requests (LOG_SAMPLE_RATE), and each logged one counts for the requests it stands for. Blocked requests are exact.'
              : 'Counts are exact for what was logged.'}{' '}
            Blocked means the edge refused the request instead of passing it on, for example a rate limit, an access rule or an overloaded edge. Log-only matches and upstream errors are not counted.
          </p>
        </>
      )}
      {d && can('settings.manage') && <EdgePlace edge={d.edge} />}
    </Page>
  );
}
