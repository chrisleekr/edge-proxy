import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type ReactNode, useMemo, useState } from 'react';
import { api, type Config, type Draft, type Rule, type VersionDetail } from '../api';
import { Link, navigate } from '../router';
import { Badge, Button, Card, ConfirmButton, ErrorBox, Input, Modal, Notice, Page, Pending, Table, Title, ago, when } from '../ui';
import { count } from './Fleet';
import { summary } from './Rules';
import { useVersions } from './Publish';

// Types mirror internal/admin/observed.go and routeflow.go.
export interface RouteStats {
  id: number;
  host: string;
  method: string;
  template: string;
  first_seen: string;
  last_seen: string;
  requests: number;
  // The part of requests counted from sampled access lines.
  estimated: number;
  // Set while every answer to the route has been an error.
  errors_only: boolean;
  status: number[];
  latency_ms_buckets: number[];
  decisions: Record<string, number>;
  config_rules: Record<string, number>;
  rate_limit_rules: Record<string, number>;
  query_shapes: Record<string, number>;
  p50_ms: number;
  p95_ms: number;
}

interface RouteList {
  since: string;
  routes: RouteStats[];
  not_grouped: number;
  logged_requests: number;
  estimated_requests: number;
  reported_requests: number;
  suggestions: { host: string; pattern: string; routes: number }[];
  max_routes: number;
  max_error_routes: number;
}

interface RoutePattern {
  id: number;
  host: string;
  pattern: string;
  created_at: string;
}

interface RouteDetailData extends RouteStats {
  since: string;
  series: {
    hour: string;
    requests: number;
    status: number[];
    decisions: Record<string, number>;
  }[];
}

interface RuleMatch {
  id: string;
  match: 'always' | 'never' | 'depends';
  depends_on?: string[];
}

interface Flow {
  version: number | null;
  draft: boolean;
  sample: { method?: string; host: string; path: string };
  result: {
    rejected?: string;
    config_rules: string[];
    rate_limit_rules: string[];
    rate_limit_capped: boolean;
    preflight: boolean;
    settings: {
      auth_mode: string;
      accepted: string[];
      cors_policy: string;
      locale: boolean;
      responses: Record<string, string>;
      body_limit: number;
      upstream_timeout: string;
      ratelimit_headers: boolean;
    };
  };
  rules: {
    config: RuleMatch[];
    rate_limit: RuleMatch[];
    request_headers: RuleMatch[];
  };
}

// "*" is where the server sums keys past its caps.
const OTHER = '*';

// What each edge decision did to the request, in an operator's words.
const decisionWords: Record<string, string> = {
  allow: 'Forwarded to the upstream',
  rate_limited: 'Blocked by a rate limit rule',
  backstop: 'Blocked by the per-edge backstop',
  auth: 'Refused: missing or invalid token',
  rate_limit_key: 'Refused: a rate limit key was missing',
  rate_limit_unavailable: 'Refused: rate limits could not be checked',
  payload_too_large: 'Refused: body too large',
  body_timeout: 'Refused: body sent too slowly',
  overloaded: 'Shed: the edge was at capacity',
  streams_overloaded: 'Shed: too many open streams',
  upstream_timeout: 'Upstream did not answer in time',
  upstream_error: 'Upstream could not be reached',
  client_gone: 'Client left before the answer',
  panic: 'Edge error',
  untrusted_peer: 'Refused: not from a trusted proxy',
  ingress_secret: 'Refused: missing ingress secret',
  client_ip: 'Refused: no client IP',
  no_snapshot: 'Refused: the edge had no policy loaded',
  [OTHER]: 'Other',
};
const decisionName = (d: string) => decisionWords[d] ?? d;

// rate is a share for reading at a glance: one decimal below 10%, none above.
const rate = (n: number, d: number) => {
  if (!d) return '—';
  const p = (100 * n) / d;
  return n === 0 ? '0%' : p < 0.1 ? '<0.1%' : `${p.toFixed(p < 10 ? 1 : 0)}%`;
};

// page is how many routes the table shows at a time; thousands of rows at
// once would make every filter keystroke slow.
const page = 100;

const ranges = [
  [24, 'last 24 hours'],
  [168, 'last 7 days'],
  [720, 'last 30 days'],
] as const;

// Derived figures for one route, shared by the list and the detail page.
function figures(r: RouteStats) {
  const limited = r.decisions.rate_limited ?? 0;
  const rejected = Object.entries(r.decisions).reduce((n, [d, c]) => (d === 'allow' || d === 'rate_limited' ? n : n + c), 0);
  return {
    errors: r.status[5] ?? 0,
    limited,
    rejected,
    rules: Object.keys(r.config_rules).filter((k) => k !== OTHER),
  };
}

const shapeKeys = (shape: string) => (shape === '' ? [] : shape.split('&'));

// useSearchState keeps a page's filters in the address, so a filtered view
// can be bookmarked and shared. It replaces the entry: filtering is not a
// step back should undo.
function useSearchState() {
  const [params, setParams] = useState(() => new URLSearchParams(window.location.search));
  const set = (changes: Record<string, string>) => {
    const p = new URLSearchParams(params);
    for (const [k, v] of Object.entries(changes)) {
      if (v) p.set(k, v);
      else p.delete(k);
    }
    setParams(p);
    window.history.replaceState(null, '', `${window.location.pathname}${p.size ? `?${p}` : ''}`);
  };
  return [params, set] as const;
}

function RangeSelect({ hours, onChange }: { hours: number; onChange: (h: number) => void }) {
  return (
    <select aria-label="Time range" value={hours} onChange={(e) => onChange(Number(e.target.value))}>
      {ranges.map(([h, label]) => (
        <option key={h} value={h}>
          {label[0]!.toUpperCase() + label.slice(1)}
        </option>
      ))}
    </select>
  );
}

const phraseOf = (hours: number) => `in the ${ranges.find(([h]) => h === hours)?.[1] ?? `last ${hours} hours`}`;

// RouteName shows a route the way people say it: method, then host and path.
// Placeholders are styled so "{id}" reads as "any ID", not literal text.
function RouteName({ r, link }: { r: Pick<RouteStats, 'id' | 'method' | 'host' | 'template'>; link?: boolean }) {
  const path = r.template.split(/(\{[a-z*]+\})/).map((part, i) =>
    /^\{[a-z*]+\}$/.test(part) ? (
      <span key={i} className="rounded-xs bg-soft px-0.5 text-muted">
        {part}
      </span>
    ) : (
      part
    ),
  );
  const body = (
    <span className="font-mono break-all">
      <span className="mr-1.5 inline-block min-w-12 font-sans text-xs font-semibold text-heading">{r.method}</span>
      {path}
    </span>
  );
  return link ? (
    <Link to={`/routes/${r.id}`} className="hover:underline">
      {body}
    </Link>
  ) : (
    body
  );
}

const flags = [
  ['errors', 'Has 5xx'],
  ['limited', 'Rate limited'],
  ['rejected', 'Refused or shed'],
  ['norule', 'No config rule matched'],
  ['recent', 'Seen in the last hour'],
] as const;

// Columns of the routes table; sortable ones name the figure they sort by.
const columns = ['Route', 'Host', 'Query shapes', 'Requests', '5xx', 'Rate limited', 'Refused or shed', 'p95', 'Config rules', 'Last seen'];
const sortKeys: Record<number, string> = {
  0: 'route',
  1: 'host',
  3: 'requests',
  4: 'errors',
  5: 'limited',
  6: 'rejected',
  7: 'p95',
  9: 'last',
};

export function Routes({ can }: { can: (p: string) => boolean }) {
  const qc = useQueryClient();
  const [params, set] = useSearchState();
  const hours = Number(params.get('hours')) || 24;
  const search = params.get('q') ?? '';
  const host = params.get('host') ?? '';
  const method = params.get('method') ?? '';
  const show = params.get('show') ?? '';
  const on = useMemo(() => new Set(show.split(',').filter(Boolean)), [show]);
  const sortBy = params.get('sort') ?? 'requests';
  const asc = params.get('dir') === 'asc';
  const q = useQuery({
    queryKey: ['routes', hours],
    queryFn: () => api<RouteList>('GET', `/api/observed-routes?hours=${hours}`),
    refetchInterval: 15_000,
  });
  const routes = q.data?.routes;
  // "Seen in the last hour" is relative to the data's fetch, not to render.
  const asOf = q.dataUpdatedAt;
  const phrase = phraseOf(hours);

  const hosts = useMemo(() => [...new Set(routes?.map((r) => r.host))].sort(), [routes]);
  const methods = useMemo(() => [...new Set(routes?.map((r) => r.method))].sort(), [routes]);
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const hourAgo = asOf - 3600_000;
    const list = (routes ?? [])
      .map((r) => ({ r, f: figures(r) }))
      .filter(({ r, f }) => {
        if (host && r.host !== host) return false;
        if (method && r.method !== method) return false;
        if (on.has('errors') && f.errors === 0) return false;
        if (on.has('limited') && f.limited === 0) return false;
        if (on.has('rejected') && f.rejected === 0) return false;
        if (on.has('norule') && f.rules.length > 0) return false;
        if (on.has('recent') && Date.parse(r.last_seen) < hourAgo) return false;
        if (!needle) return true;
        const text = [r.method, r.host, r.template, ...Object.keys(r.query_shapes), ...f.rules, ...Object.keys(r.rate_limit_rules)].join(' ').toLowerCase();
        return needle.split(/\s+/).every((w) => text.includes(w));
      });
    const key = ({ r, f }: (typeof list)[number]): number | string =>
      ({
        route: r.template,
        host: r.host,
        requests: r.requests,
        errors: f.errors / r.requests,
        limited: f.limited / r.requests,
        rejected: f.rejected / r.requests,
        p95: r.p95_ms,
        last: Date.parse(r.last_seen),
      })[sortBy] ?? r.requests;
    return list.sort((a, b) => {
      const x = key(a);
      const y = key(b);
      const c = typeof x === 'string' ? x.localeCompare(String(y)) : x - Number(y);
      return asc ? c : -c;
    });
  }, [routes, search, host, method, on, sortBy, asc, asOf]);

  const toggle = (k: string) => {
    const next = new Set(on);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    set({ show: [...next].join(',') });
  };
  const sortCol = Number(Object.entries(sortKeys).find(([, k]) => k === sortBy)?.[0] ?? 3);
  const onSort = (col: number) => {
    const k = sortKeys[col]!;
    // Names sort A to Z first; figures largest first.
    const firstAsc = k === 'route' || k === 'host';
    set({
      sort: k === 'requests' ? '' : k,
      dir: k === sortBy ? (asc ? '' : 'asc') : firstAsc ? 'asc' : '',
    });
  };
  const filtered = search || host || method || on.size > 0;
  const [shown, setShown] = useState(page);

  const deleteAll = useMutation({
    mutationFn: () => api('DELETE', '/api/observed-routes'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['routes'] }),
  });
  const group = useMutation({
    mutationFn: (s: { host: string; pattern: string }) => api('POST', '/api/route-patterns', s),
    onSuccess: () => (qc.invalidateQueries({ queryKey: ['routes'] }), qc.invalidateQueries({ queryKey: ['route-patterns'] })),
  });

  return (
    <Page
      title="Routes"
      info="Built from the edges' access logs, which the log shipper posts to admin, so the edge does no extra work for this page. A route is a host, a method and a path where IDs, UUIDs and tokens are replaced by placeholders such as {id}."
      actions={
        <>
          <RangeSelect hours={hours} onChange={(h) => set({ hours: h === 24 ? '' : String(h) })} />
          {can('routes.manage') && routes && routes.length > 0 && (
            <ConfirmButton
              variant="danger"
              title="Delete every route?"
              action="Delete all routes"
              disabled={deleteAll.isPending}
              onConfirm={() => deleteAll.mutate()}
              confirm="Their counts and history are deleted. Routes are collected again from new traffic, so live routes reappear within a minute."
            >
              Delete all
            </ConfirmButton>
          )}
        </>
      }
    >
      <ErrorBox error={q.error ?? deleteAll.error ?? group.error} />
      {q.data && <Coverage d={q.data} phrase={phrase} />}
      {q.data && q.data.suggestions.length > 0 && (
        <Card
          title="Similar routes"
          info="These paths differ only in their last segment, such as article names. Grouping them makes one route whose counts are their sum, and new paths like them join it. Existing history moves with them."
        >
          <ul className="flex flex-col gap-2">
            {q.data.suggestions.map((s) => (
              <li key={s.host + s.pattern} className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-body">
                  <span className="font-mono text-heading">
                    {s.host}
                    {s.pattern.replace(/\*$/, '')}
                    <span className="rounded-xs bg-soft px-0.5 text-muted">{'{*}'}</span>
                  </span>
                  : {s.routes} routes
                </span>
                {can('routes.manage') && (
                  <Button disabled={group.isPending} onClick={() => group.mutate({ host: s.host, pattern: s.pattern })}>
                    Group as one route
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-end gap-3">
          <Input label="Search" type="search" className="min-w-56 flex-1" placeholder="Path, host, query key or rule" value={search} onChange={(e) => set({ q: e.target.value })} />
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-heading">Host</span>
            <select value={host} onChange={(e) => set({ host: e.target.value })}>
              <option value="">All hosts</option>
              {hosts.map((h) => (
                <option key={h}>{h}</option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-heading">Method</span>
            <select value={method} onChange={(e) => set({ method: e.target.value })}>
              <option value="">All methods</option>
              {methods.map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
          </label>
        </div>
        <div role="group" aria-label="Show only" className="flex flex-wrap items-center gap-2">
          <span className="eyebrow text-body">Show only</span>
          {flags.map(([k, label]) => (
            <button
              key={k}
              type="button"
              aria-pressed={on.has(k)}
              onClick={() => toggle(k)}
              className="rounded-full px-3 py-1 text-sm shadow-field hover:bg-soft aria-pressed:bg-brand aria-pressed:text-on-brand"
            >
              {label}
            </button>
          ))}
          {filtered && (
            <button type="button" className="text-sm text-body underline" onClick={() => set({ q: '', host: '', method: '', show: '' })}>
              Clear filters
            </button>
          )}
        </div>
        {routes && (
          <p role="status" className="text-sm text-body">
            {filtered ? `${count(rows.length)} of ${count(routes.length)} routes match.` : `${count(routes.length)} routes ${phrase}.`}
          </p>
        )}
      </div>
      {!q.data ? (
        <Pending error={q.error} />
      ) : (
        <Table
          head={columns}
          num={[3, 4, 5, 6, 7]}
          sort={{
            by: sortCol,
            desc: !asc,
            cols: Object.keys(sortKeys).map(Number),
            onSort,
          }}
          empty={filtered ? 'No route matches these filters.' : `No route had traffic ${phrase}.`}
        >
          {rows.slice(0, shown).map(({ r, f }) => {
            const shapes = Object.entries(r.query_shapes).sort((a, b) => b[1] - a[1]);
            return (
              <tr key={r.id}>
                <td className="min-w-64">
                  <RouteName r={r} link />
                  {r.errors_only && (
                    <span className="ml-2">
                      <Badge tone="amber">only errors so far</Badge>
                    </span>
                  )}
                </td>
                <td className="break-all">{r.host}</td>
                <td>
                  <Shapes shapes={shapes} total={r.requests} max={2} />
                </td>
                <td className="text-right tabular-nums">
                  {r.estimated > 0 && <span title="Estimated from sampled access logs">≈ </span>}
                  {count(r.requests)}
                </td>
                <td className={`text-right tabular-nums ${f.errors ? 'text-danger' : ''}`}>{rate(f.errors, r.requests)}</td>
                <td className={`text-right tabular-nums ${f.limited ? 'text-warning' : ''}`}>{rate(f.limited, r.requests)}</td>
                <td className="text-right tabular-nums">{rate(f.rejected, r.requests)}</td>
                <td className="text-right tabular-nums">{ms(r.p95_ms)}</td>
                <td>
                  {f.rules.length ? (
                    <span className="flex flex-wrap gap-1">
                      {f.rules.map((id) => (
                        <code key={id} className="text-heading">
                          {id}
                        </code>
                      ))}
                    </span>
                  ) : (
                    <span className="text-muted">None</span>
                  )}
                </td>
                <td>
                  <time dateTime={r.last_seen} title={when(r.last_seen)}>
                    {ago(r.last_seen)}
                  </time>
                </td>
              </tr>
            );
          })}
        </Table>
      )}
      {rows.length > shown && (
        <Button className="self-start" onClick={() => setShown(shown + page)}>
          Show {count(Math.min(page, rows.length - shown))} more of {count(rows.length - shown)}
        </Button>
      )}
      <Groupings can={can} />
    </Page>
  );
}

// ms shows a latency bucket's upper bound: the true figure is at most this.
const ms = (v: number) => (v === 0 ? '—' : v >= 1000 ? `≤ ${v / 1000} s` : `≤ ${v} ms`);

// Coverage says how complete the counts are: the access lines admin
// received, against the requests the edges counted themselves.
function Coverage({ d, phrase }: { d: RouteList; phrase: string }) {
  if (d.logged_requests === 0 && d.routes.length === 0)
    return (
      <Card title={`No access logs ${phrase}`}>
        <p className="max-w-prose text-body">
          After Delete all, routes come back within a minute of new traffic. If none come back, check the log shipper: routes are built from the edges' access logs, which it posts to admin. The Helm
          chart runs one by default (<code>logShipper.enabled</code>). Elsewhere, send each edge container's output to <code>/v1/logs/access</code> with the token in admin's{' '}
          <code>LOG_INGEST_TOKEN_FILE</code>.
        </p>
      </Card>
    );
  const share = d.reported_requests ? Math.min(1, d.logged_requests / d.reported_requests) : 1;
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm text-body">
        Counted from the access logs: {count(d.logged_requests)} requests
        {d.reported_requests > 0 && `, ${rate(Math.min(d.logged_requests, d.reported_requests), d.reported_requests)} of the ${count(d.reported_requests)} the edges served ${phrase}`}.{' '}
        {d.estimated_requests > 0
          ? `${count(d.estimated_requests)} of them are estimated, marked ≈: the edges log only a share of allowed requests (LOG_SAMPLE_RATE), and each logged one counts for the requests it stands for. Refused requests and 5xx are logged every time, so they are exact.`
          : 'Counts are exact for what was logged.'}
      </p>
      {share < 0.9 && (
        <Notice tone="amber">
          Fewer requests were logged than the edges served, so the counts here are low. Lines are dropped when an edge's log buffer or the shipper falls behind, and an edge that does not say its
          sample rate in its access lines has each sampled line counted once.
        </Notice>
      )}
      {d.not_grouped > 0 && (
        <Notice tone="amber">
          {count(d.not_grouped)} requests are not grouped into a route: they went to paths too long to group, or to new routes past the limit of {count(d.max_routes)} routes, or of{' '}
          {count(d.max_error_routes)} routes answered only with errors. Delete routes you no longer need, or group similar ones.
        </Notice>
      )}
    </div>
  );
}

// Shapes lists a route's query shapes, the commonest first.
function Shapes({ shapes, total, max }: { shapes: [string, number][]; total: number; max: number }) {
  if (shapes.length === 1 && shapes[0]![0] === '') return <span className="text-muted">No query</span>;
  return (
    <span className="flex flex-col gap-0.5">
      {shapes.slice(0, max).map(([s, n]) => (
        <span key={s} className="flex flex-wrap items-center gap-1">
          <QueryKeys shape={s} />
          <span className="text-xs text-muted">{rate(n, total)}</span>
        </span>
      ))}
      {shapes.length > max && <span className="text-xs text-muted">and {shapes.length - max} more</span>}
    </span>
  );
}

function QueryKeys({ shape }: { shape: string }) {
  if (shape === OTHER) return <span className="text-body">Other shapes</span>;
  const keys = shapeKeys(shape);
  if (keys.length === 0) return <span className="text-body">No query</span>;
  return (
    <>
      {keys.map((k) => (
        <code key={k} className="rounded-xs bg-soft px-1 text-xs text-heading">
          {k}
        </code>
      ))}
    </>
  );
}

// Groupings lists the patterns that group paths into routes, and adds them.
function Groupings({ can }: { can: (p: string) => boolean }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ['route-patterns'],
    queryFn: () => api<RoutePattern[]>('GET', '/api/route-patterns'),
  });
  const [host, setHost] = useState('');
  const [pattern, setPattern] = useState('');
  const done = () => (qc.invalidateQueries({ queryKey: ['routes'] }), qc.invalidateQueries({ queryKey: ['route-patterns'] }));
  const add = useMutation({
    mutationFn: () =>
      api('POST', '/api/route-patterns', {
        host: host.trim().toLowerCase(),
        pattern: pattern.trim(),
      }),
    onSuccess: () => (setPattern(''), done()),
  });
  const remove = useMutation({
    mutationFn: (id: number) => api('DELETE', `/api/route-patterns/${id}`),
    onSuccess: done,
  });
  return (
    <details className="rounded-card bg-panel shadow-card">
      <summary className="cursor-pointer px-6 py-4 font-medium text-heading">Groupings ({q.data?.length ?? 0})</summary>
      <div className="flex flex-col gap-4 border-t border-line px-6 py-4">
        <p className="max-w-prose text-body">
          A grouping makes every path that fits it one route. A <code>*</code> stands for exactly one path segment, so <code>/blog/*</code> groups <code>/blog/hello</code> but not{' '}
          <code>/blog/2026/hello</code>. Creating one merges the matching routes and their history. Deleting one keeps the merged route; new paths are grouped as before.
        </p>
        <ErrorBox error={q.error ?? add.error ?? remove.error} />
        {q.data && q.data.length > 0 && (
          <Table head={['Pattern', 'Host', 'Added', '']}>
            {q.data.map((p) => (
              <tr key={p.id}>
                <td className="font-mono">{p.pattern}</td>
                <td>{p.host || 'Every host'}</td>
                <td>{when(p.created_at)}</td>
                <td className="text-right">
                  {can('routes.manage') && (
                    <ConfirmButton
                      variant="danger"
                      title={`Delete the grouping ${p.pattern}?`}
                      action="Delete grouping"
                      onConfirm={() => remove.mutate(p.id)}
                      confirm="The route it made stays with its history. New paths are no longer grouped by it."
                    >
                      Delete
                    </ConfirmButton>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
        {can('routes.manage') && (
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              add.mutate();
            }}
          >
            <Input label="Pattern" required placeholder="/blog/*" className="min-w-48" value={pattern} onChange={(e) => setPattern(e.target.value)} />
            <Input label="Host" hint="Empty for every host." placeholder="api.example.com" className="min-w-48" value={host} onChange={(e) => setHost(e.target.value)} />
            <Button type="submit" disabled={add.isPending || !pattern.trim()}>
              {add.isPending ? 'Adding…' : 'Add grouping'}
            </Button>
          </form>
        )}
      </div>
    </details>
  );
}

// --- One route ---

export function RouteDetail({ id, can }: { id: number; can: (p: string) => boolean }) {
  const qc = useQueryClient();
  const [params, set] = useSearchState();
  const hours = Number(params.get('hours')) || 24;
  const q = useQuery({
    queryKey: ['route', id, hours],
    queryFn: () => api<RouteDetailData>('GET', `/api/observed-routes/${id}?hours=${hours}`),
    refetchInterval: 15_000,
  });
  const del = useMutation({
    mutationFn: () => api('DELETE', `/api/observed-routes/${id}`),
    onSuccess: () => (qc.invalidateQueries({ queryKey: ['routes'] }), navigate('/routes', { force: true })),
  });
  const [adding, setAdding] = useState(false);
  if (!q.data)
    return q.error && (q.error as { status?: number }).status === 404 ? (
      <Page title="Route not found">
        <p className="text-body">This route was deleted, or it has had no traffic for 30 days.</p>
        <p>
          <Link to="/routes" className="font-medium text-heading underline">
            Back to routes
          </Link>
        </p>
      </Page>
    ) : (
      <Pending error={q.error} />
    );
  const r = q.data;
  const f = figures(r);
  const phrase = phraseOf(hours);
  const shapes = Object.entries(r.query_shapes).sort((a, b) => b[1] - a[1]);
  const decisions = Object.entries(r.decisions).sort((a, b) => b[1] - a[1]);
  return (
    <Page
      title={`${r.method} ${r.host}${r.template}`}
      actions={
        <>
          <RangeSelect hours={hours} onChange={(h) => set({ hours: h === 24 ? '' : String(h) })} />
          {can('config.write') && (
            <Button variant="primary" onClick={() => setAdding(true)}>
              Add rule for this route
            </Button>
          )}
          {can('routes.manage') && (
            <ConfirmButton
              variant="danger"
              title="Delete this route?"
              action="Delete route"
              disabled={del.isPending}
              onConfirm={() => del.mutate()}
              confirm="Its counts and history are deleted. If it still gets traffic, it is collected again from new requests."
            >
              Delete
            </ConfirmButton>
          )}
        </>
      }
    >
      <p className="-mt-3">
        <Link to="/routes" className="text-sm text-body underline">
          All routes
        </Link>
      </p>
      <ErrorBox error={del.error} />
      {adding && <AddRule id={r.id} onClose={() => setAdding(false)} />}
      {r.errors_only && (
        <Notice tone="amber">
          Every answer to this route so far has been an error, such as a rate limit, a refused token or a 404. It is kept apart from other routes, under its own limit, until it serves an
          answer that isn't, so a scanner's guesses can't push real routes out.
        </Notice>
      )}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Figure label="Requests" value={`${r.estimated > 0 ? '≈ ' : ''}${count(r.requests)}`} note={phrase} />
        <Figure label="5xx" value={rate(f.errors, r.requests)} note={`${count(f.errors)} requests`} tone={f.errors ? 'red' : undefined} />
        <Figure label="Rate limited" value={rate(f.limited, r.requests)} note={`${count(f.limited)} requests`} tone={f.limited ? 'amber' : undefined} />
        <Figure label="Latency" value={ms(r.p95_ms)} note={`p95; p50 ${ms(r.p50_ms)}`} />
      </div>
      <p className="text-sm text-body">
        First seen {when(r.first_seen)}, last seen <time title={when(r.last_seen)}>{ago(r.last_seen)}</time>.{' '}
        {r.estimated > 0
          ? `Counts are estimates: ${count(r.estimated)} of these requests were counted from sampled access lines, each standing for the share of allowed requests the edge logs. Refused requests and 5xx are exact.`
          : 'Counts are exact for what the edges logged.'}
      </p>
      {can('config.read') && <TrafficFlow id={r.id} r={r} />}
      <Card title={`Requests per hour, ${phrase}`}>
        <HourBars r={r} hours={hours} />
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <div className="flex flex-col gap-2">
          <Title info="The query keys requests sent, never their values. Keys that look like tokens or email addresses show as {token}.">Query shapes</Title>
          <Table head={['Keys', 'Share']} num={[1]} empty="No requests in this range.">
            {shapes.map(([s, n]) => (
              <tr key={s}>
                <td>
                  <span className="flex flex-wrap gap-1">
                    <QueryKeys shape={s} />
                  </span>
                </td>
                <td className="text-right tabular-nums">{rate(n, r.requests)}</td>
              </tr>
            ))}
          </Table>
        </div>
        <div className="flex flex-col gap-2">
          <Title info="What the edge did with each request, from its access log.">Outcomes</Title>
          <Table head={['Outcome', 'Requests', 'Share']} num={[1, 2]} empty="No requests in this range.">
            {decisions.map(([d, n]) => (
              <tr key={d}>
                <td>{decisionName(d)}</td>
                <td className="text-right tabular-nums">{count(n)}</td>
                <td className="text-right tabular-nums">{rate(n, r.requests)}</td>
              </tr>
            ))}
          </Table>
        </div>
      </div>
    </Page>
  );
}

function Figure({ label, value, note, tone }: { label: string; value: string; note: string; tone?: 'red' | 'amber' | undefined }) {
  const color = tone === 'red' ? 'text-danger' : tone === 'amber' ? 'text-warning' : 'text-heading';
  return (
    <div className="rounded-card bg-panel p-4 shadow-card">
      <p className="eyebrow text-body">{label}</p>
      <p className={`text-2xl font-semibold tabular-nums ${color}`}>{value}</p>
      <p className="text-sm text-body">{note}</p>
    </div>
  );
}

// AddRule picks the phase a new rule for the route goes in; the rule editor
// starts it with a condition that matches the route.
function AddRule({ id, onClose }: { id: number; onClose: () => void }) {
  const kinds = [
    ['config', 'Config rule', 'Set auth, CORS, upstream timeout or body limit for this route.'],
    ['rate_limit', 'Rate limit rule', 'Limit how often clients can call this route.'],
    ['request_headers', 'Header rule', 'Change the headers this route’s upstream receives.'],
  ] as const;
  return (
    <Modal title="Add a rule for this route" onClose={onClose}>
      <ul className="flex flex-col gap-2">
        {kinds.map(([phase, title, about]) => (
          <li key={phase}>
            <button type="button" className="w-full rounded-control p-3 text-left shadow-field hover:bg-soft" onClick={() => (onClose(), navigate(`/rules/${phase}/?route=${id}`))}>
              <span className="block font-medium text-heading">{title}</span>
              <span className="block text-sm text-body">{about}</span>
            </button>
          </li>
        ))}
      </ul>
      <div className="mt-4 flex justify-end">
        <Button data-autofocus onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Modal>
  );
}

// HourBars draws requests per hour, with 5xx and rate limited on top, so a
// spike shows what it was. Ranges over a week draw a bar per day.
function HourBars({ r, hours }: { r: RouteDetailData; hours: number }) {
  const per = hours > 168 ? 24 : 1;
  const start = Date.parse(r.since);
  const n = Math.ceil(hours / per);
  const bars = Array.from({ length: n }, (_, i) => ({
    t: start + i * per * 3600_000,
    requests: 0,
    errors: 0,
    limited: 0,
  }));
  for (const p of r.series) {
    const b = bars[Math.floor((Date.parse(p.hour) - start) / (per * 3600_000))];
    if (!b) continue;
    b.requests += p.requests;
    b.errors += p.status[5] ?? 0;
    b.limited += p.decisions.rate_limited ?? 0;
  }
  const max = Math.max(1, ...bars.map((b) => b.requests));
  const label = (t: number) => new Date(t).toLocaleString([], per === 24 ? { month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric', hour: 'numeric' });
  return (
    <figure className="flex flex-col gap-2">
      <figcaption className="eyebrow flex flex-wrap justify-between gap-2 text-body">
        <span>
          Peak {count(max)} per {per === 24 ? 'day' : 'hour'}
        </span>
        <span className="flex gap-3">
          <span className="flex items-center gap-1.5">
            <span aria-hidden className="size-2 rounded-xs bg-heading/75" />
            Other
          </span>
          <span className="flex items-center gap-1.5">
            <span aria-hidden className="size-2 rounded-xs bg-warning" />
            Rate limited
          </span>
          <span className="flex items-center gap-1.5">
            <span aria-hidden className="size-2 rounded-xs bg-danger" />
            5xx
          </span>
        </span>
      </figcaption>
      <ol aria-label={`Requests per ${per === 24 ? 'day' : 'hour'}`} className="flex h-32 items-end gap-px border-b border-line">
        {bars.map((b) => {
          const rest = Math.max(0, b.requests - b.errors - b.limited);
          const h = (x: number) => `${(100 * x) / max}%`;
          const text = `${label(b.t)}: ${count(b.requests)} requests, ${count(b.limited)} rate limited, ${count(b.errors)} 5xx`;
          return (
            <li key={b.t} title={text} className="flex h-full min-w-0 flex-1 flex-col justify-end">
              <span className="sr-only">{text}</span>
              <span aria-hidden className="bg-heading/75" style={{ height: h(rest) }} />
              <span aria-hidden className="bg-warning" style={{ height: h(b.limited) }} />
              <span aria-hidden className="bg-danger" style={{ height: h(b.errors) }} />
            </li>
          );
        })}
      </ol>
      <div className="eyebrow flex justify-between text-body">
        <span>{label(start)}</span>
        <span>{label(bars[bars.length - 1]!.t)}</span>
      </div>
    </figure>
  );
}

// --- What happens to the traffic ---

type Mode = 'published' | 'canary' | 'draft';

// TrafficFlow walks a sample request of the route through the edge's steps,
// in the order the edge runs them, using the edge's own simulation. Each
// step says what it does to this route and what the logs show it did.
function TrafficFlow({ id, r }: { id: number; r: RouteDetailData }) {
  const [mode, setMode] = useState<Mode>('published');
  // During a canary its version serves part of the traffic, so it is one
  // of the policies to show.
  const canary = useVersions().data?.find((x) => x.status === 'canary')?.version;
  const shown = mode === 'canary' && !canary ? 'published' : mode;
  const flow = useQuery({
    queryKey: ['route-flow', id, shown, canary],
    queryFn: () => api<Flow>('GET', `/api/observed-routes/${id}/flow${shown === 'draft' ? '?version=draft' : shown === 'canary' ? `?version=${canary}` : ''}`),
  });
  const v = flow.data?.version;
  const config = useQuery({
    queryKey: shown === 'draft' ? ['route-flow-draft'] : ['version', v],
    queryFn: () => (shown === 'draft' ? api<Draft>('GET', '/api/draft').then((d) => d.config) : api<VersionDetail>('GET', `/api/versions/${v}`).then((d) => d.config)),
    enabled: !!flow.data && (shown === 'draft' || v != null),
  });
  return (
    <Card
      title="What happens to this traffic"
      info="The edge's own simulation runs on a sample request for this route, with each placeholder filled in and the commonest query shape. Rules that depend on something only a request carries, such as a header or the client's country, are marked as depending on it."
    >
      <div role="group" aria-label="Policy to show" className="mb-4 inline-flex rounded-control shadow-field">
        {(canary ? (['published', 'canary', 'draft'] as const) : (['published', 'draft'] as const)).map((m) => (
          <button
            key={m}
            type="button"
            aria-pressed={shown === m}
            onClick={() => setMode(m)}
            className="px-3 py-1.5 text-sm first:rounded-l-control last:rounded-r-control aria-pressed:bg-brand aria-pressed:text-on-brand"
          >
            {m === 'published' ? `Live policy${shown === 'published' && v ? ` (v${v})` : ''}` : m === 'canary' ? `Canary (v${canary})` : 'Saved draft'}
          </button>
        ))}
      </div>
      {!flow.data || !config.data ? <Pending error={flow.error ?? config.error} /> : <Steps flow={flow.data} config={config.data} r={r} />}
    </Card>
  );
}

const ruleLink = (phase: string, id: string) => `/rules/${phase}/${encodeURIComponent(id)}`;

// Matches lists the rules of one phase that can apply to the route, with
// the ones that never do behind a toggle.
function Matches({
  phase,
  matches,
  describe,
  observed,
  verb = 'matched',
  approx,
}: {
  phase: string;
  matches: RuleMatch[];
  describe: (id: string) => string;
  observed?: Record<string, number>;
  verb?: string;
  // approx marks counts that include estimates from sampled lines.
  approx?: boolean;
}) {
  const [all, setAll] = useState(false);
  const shown = matches.filter((m) => all || m.match !== 'never');
  const never = matches.length - matches.filter((m) => m.match !== 'never').length;
  if (matches.length === 0) return <p className="text-sm text-body">No rules in this phase.</p>;
  return (
    <div className="flex flex-col gap-1.5">
      {shown.length === 0 && <p className="text-sm text-body">None of the {matches.length} rules apply to this route.</p>}
      <ul className="flex flex-col gap-1.5">
        {shown.map((m) => (
          <li key={m.id} className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-sm">
            <Badge tone={m.match === 'always' ? 'green' : m.match === 'depends' ? 'amber' : 'slate'}>
              {m.match === 'always' ? 'Always' : m.match === 'never' ? 'Never' : `Depends on ${m.depends_on?.join(', ')}`}
            </Badge>
            <Link to={ruleLink(phase, m.id)} className="font-mono text-heading underline">
              {m.id}
            </Link>
            <span className="text-body">{describe(m.id)}</span>
            {observed?.[m.id] ? (
              <span className="text-body">
                · {verb} {approx && '≈ '}
                {count(observed[m.id]!)} requests
              </span>
            ) : null}
          </li>
        ))}
      </ul>
      {never > 0 && (
        <button type="button" className="self-start text-sm text-body underline" onClick={() => setAll(!all)}>
          {all ? 'Hide rules that never apply' : `Show ${never} ${never === 1 ? 'rule that never applies' : 'rules that never apply'}`}
        </button>
      )}
    </div>
  );
}

function Steps({ flow, config, r }: { flow: Flow; config: Config; r: RouteDetailData }) {
  const s = flow.result.settings;
  const find = (list: Rule[] | null, id: string) => list?.find((x) => x.id === id);
  // Each rule in the words the Rules page uses for it.
  const describe = (list: Rule[] | null) => (id: string) => {
    const x = find(list, id);
    return x ? summary(x) : '';
  };
  const rejected = flow.result.rejected;
  const d = r.decisions;
  const share = (n: number | undefined) => (n ? `${count(n)} requests (${rate(n, r.requests)})` : undefined);
  const sample = `${flow.sample.method ?? 'GET'} ${flow.sample.host}${flow.sample.path}`;

  const steps: {
    title: string;
    body: ReactNode;
    seen?: string | undefined;
    stop?: boolean;
  }[] = [
    {
      title: 'A request arrives',
      body: (
        <>
          Shown for a request like <code className="break-all">{sample}</code>.
        </>
      ),
    },
    {
      title: 'Config rules choose the settings',
      body: (
        <div className="flex flex-col gap-2">
          <Matches phase="config" matches={flow.rules.config} describe={describe(config.config_rules)} observed={r.config_rules} approx={r.estimated > 0} />
          <p className="text-sm text-body">
            Result: waiting up to {s.upstream_timeout || 'the default'} for the upstream, body limit{' '}
            {bytes(s.body_limit)}
            {s.cors_policy ? `, CORS policy ${s.cors_policy}` : ''}
            {s.locale ? ', locale detected' : ''}.
          </p>
        </div>
      ),
    },
    {
      title: 'Backstop',
      body: 'Each client IP gets a fixed allowance per second on each edge, before anything costly runs.',
      seen: share(d.backstop) && `${share(d.backstop)} were over it`,
    },
    {
      title: 'CORS preflight',
      body: s.cors_policy
        ? `An OPTIONS preflight is answered by the edge with CORS policy ${s.cors_policy}; it never reaches the upstream.`
        : 'No CORS policy applies, so a preflight is forwarded to the upstream like any request.',
    },
    {
      title: 'Authentication',
      body:
        s.auth_mode === 'required'
          ? `A valid token is required${s.accepted.length ? ` from ${s.accepted.join(', ')}` : ''}. Requests without one are refused.`
          : s.auth_mode === 'optional'
            ? `A token is checked when one is sent${s.accepted.length ? ` (from ${s.accepted.join(', ')})` : ''}; requests without one go through.`
            : 'No token is checked.',
      seen: share(d.auth) && `${share(d.auth)} were refused for a missing or invalid token`,
      stop: rejected === 'auth',
    },
    {
      title: 'Rate limits',
      body: (
        <div className="flex flex-col gap-2">
          <Matches phase="rate_limit" matches={flow.rules.rate_limit} describe={describe(config.rate_limit_rules)} observed={r.rate_limit_rules} verb="blocked" />
          {flow.result.rate_limit_capped && <Notice tone="amber">More rules match than the edge checks for one request; the extra ones are skipped.</Notice>}
        </div>
      ),
      seen: share(d.rate_limited) && `${share(d.rate_limited)} were blocked by a rate limit`,
      stop: rejected === 'rate_limit_key',
    },
    {
      title: 'Header rules shape what the upstream receives',
      body: <Matches phase="request_headers" matches={flow.rules.request_headers} describe={describe(config.request_header_rules)} />,
    },
    {
      title: 'Upstream',
      body: (
        <>
          Forwarded to the edge&apos;s upstream, the load balancer or gateway that routes this host.
        </>
      ),
      seen: `Answers: ${
        [
          ['2xx', r.status[2]],
          ['3xx', r.status[3]],
          ['4xx', r.status[4]],
          ['5xx', r.status[5]],
        ]
          .filter(([, n]) => n)
          .map(([c, n]) => `${rate(Number(n), r.requests)} ${String(c)}`)
          .join(', ') || 'none in this range'
      }`,
    },
  ];
  // A request the simulation refuses stops at that step.
  const stopAt = rejected && rejected !== 'auth' && rejected !== 'rate_limit_key' ? 0 : steps.findIndex((x) => x.stop);
  return (
    <ol className="flex flex-col">
      {(stopAt >= 0 ? steps.slice(0, stopAt + 1) : steps).map((step, i, list) => (
        <li key={step.title} className="relative flex gap-4 pb-5 last:pb-0">
          {i < list.length - 1 && <span aria-hidden className="absolute top-8 bottom-0 left-[15px] w-px bg-line" />}
          <span aria-hidden className="z-10 grid size-8 shrink-0 place-items-center rounded-full bg-soft text-sm font-semibold text-heading shadow-field">
            {i + 1}
          </span>
          <div className="flex min-w-0 flex-1 flex-col gap-1.5 pt-1">
            <h3 className="font-medium text-heading">{step.title}</h3>
            <div className="text-sm text-body">{step.body}</div>
            {step.seen && <p className="text-sm text-heading">Logged: {step.seen}.</p>}
          </div>
        </li>
      ))}
      {stopAt >= 0 && (
        <li className="ml-12">
          <Notice tone="amber">This sample request stops here: {decisionName(rejected!)}.</Notice>
        </li>
      )}
    </ol>
  );
}

const bytes = (n: number) => (n >= 1 << 20 ? `${n / (1 << 20)} MiB` : n >= 1024 ? `${n / 1024} KiB` : `${n} bytes`);
