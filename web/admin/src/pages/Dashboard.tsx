import { type ReactNode, useId } from 'react';
import { phases, rulesOf } from '../phases';
import { Link } from '../router';
import { Button, ErrorBox, Info, Page, Rolling, ago, plural, when, who } from '../ui';
import { said } from './Audit';
import { count, type DashboardData, quiet, useAttention, useDashboardData } from '../attention';
import { LogLink, useLogSearch } from '../logSearch';
import { Bars, codeName, type Edge, pct, type Range, RangePicker, type Row, statusCodes, statusOf, sum, Unranked, useMarks } from './Fleet';

// Dashboard is the first screen. It leads with what needs a person, then
// shows traffic, rate limiting, the live policy, the fleet and recent
// changes. Each part needs its own permission and is left out without it.
// Query keys match the detail pages, so moving between them shares data.
export function Dashboard({ can }: { can: (p: string) => boolean }) {
  const d = useDashboardData(can);
  return (
    <Page title="Dashboard" actions={d.stats && <RangePicker r={d.stats} />}>
      <Attention d={d} can={can} />
      {/* One source order for every width, so screen readers and Tab follow
          what people see: traffic, what is live and where, then detail.
          From lg the live column sits beside the rest and spans their rows;
          the last row takes any spare height, so no gaps open above it. */}
      <div className="grid items-start gap-5 lg:grid-cols-3 lg:grid-rows-[auto_auto_1fr]">
        {d.stats && (
          <div className="min-w-0 lg:col-span-2">
            <Traffic r={d.stats} />
          </div>
        )}
        {(d.versions || d.fleet) && (
          <div className="flex min-w-0 flex-col gap-5 lg:col-start-3 lg:row-span-3 lg:row-start-1">
            {d.versions && <Policy versions={d.versions} live={d.live} />}
            {d.fleet && <Fleet fleet={d.fleet} liveVersion={d.liveVersion} canaryVersion={d.canaryVersion} />}
          </div>
        )}
        {d.stats && (
          <div className="min-w-0 lg:col-span-2">
            <Limiting r={d.stats} />
          </div>
        )}
        {d.audit && (
          <div className="min-w-0 lg:col-span-2">
            <Changes audit={d.audit} verify={d.verify} />
          </div>
        )}
      </div>
    </Page>
  );
}

function Panel({ title, info, link, error, children }: { title: string; info?: ReactNode; link?: [string, string] | undefined; error?: unknown; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="flex min-w-0 flex-col gap-4 rounded-card bg-panel p-6 shadow-card">
      <div className="flex items-baseline justify-between gap-3">
        <div className="flex items-center gap-2">
          <h2 id={id}>{title}</h2>
          {info && <Info label={title}>{info}</Info>}
        </div>
        {link && (
          <Link to={link[1]} className="text-sm font-medium whitespace-nowrap text-heading underline">
            {link[0]}
          </Link>
        )}
      </div>
      <ErrorBox error={error} />
      {children}
    </section>
  );
}

// Figure is one number with its label. Screen readers get label, number,
// then the sub line; order shows the number on top. The sub line is a second
// dd, since a dl holds only dt and dd.
function Figure({ n, label, sub, tone = 'text-heading' }: { n: ReactNode; label: string; sub?: ReactNode; tone?: string }) {
  return (
    <div className="flex flex-col">
      <dt className="eyebrow order-2 text-muted">{label}</dt>
      <dd className={`order-1 text-2xl font-semibold tabular-nums ${tone}`}>{n}</dd>
      {sub !== undefined && <dd className="order-3 text-sm text-body">{sub}</dd>}
    </div>
  );
}

// totals sums each rate limit rule over the rows.
function totals(rows: Row[]) {
  const rules = new Map<
    string,
    {
      id: string;
      evaluated: number;
      limited: number;
      logged: number;
      failed: number;
    }
  >();
  for (const r of rows)
    for (const c of r.rate_limit_rules ?? []) {
      const t = rules.get(c.id) ?? {
        id: c.id,
        evaluated: 0,
        limited: 0,
        logged: 0,
        failed: 0,
      };
      for (const k of ['evaluated', 'limited', 'logged', 'failed'] as const) t[k] += c[k];
      rules.set(c.id, t);
    }
  return [...rules.values()];
}

// Attention renders the items useAttention reads.
function Attention({ d, can }: { d: DashboardData; can: (p: string) => boolean }) {
  const { shown, acked, acks, send, canAck, waiting, checked } = useAttention(d, can);
  if (!checked.length && !waiting) return null;
  const mark = {
    danger: 'bg-danger',
    warning: 'bg-warning',
    neutral: 'bg-muted',
  };
  return (
    <Panel
      title="Needs attention"
      link={d.versions ? ['Kill switch', '/settings#kill-switch'] : undefined}
      info="Each line is read from admin: a state such as a running canary or an edge that cannot reach admin, or an anomaly the notification checks found firing. Red needs action now, amber needs a look, grey is worth knowing."
    >
      <ErrorBox error={send.error ?? acks.error} />
      {shown.length === 0 ? (
        <p className="text-body">{waiting ? 'Checking…' : acked.length ? 'Nothing else needs attention.' : `Nothing needs attention. Checked: ${checked.join(', ')}.`}</p>
      ) : (
        <ul className="flex flex-col divide-y divide-line">
          {shown.map((it) => (
            <li key={it.key} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2 first:pt-0 last:pb-0">
              <span aria-hidden className={`size-2 shrink-0 translate-y-[-1px] rounded-full ${mark[it.tone]}`} />
              <span className="sr-only">{{ danger: 'Urgent:', warning: 'Check:', neutral: 'Note:' }[it.tone]}</span>
              <span className="min-w-[12rem] flex-1 text-heading">
                {it.text}
                {!!it.under?.length && (
                  <ul className="mt-1 flex flex-col gap-1 border-l border-line pl-3 text-sm text-body">
                    {it.under.map((u, j) => (
                      <li key={j}>{u}</li>
                    ))}
                  </ul>
                )}
              </span>
              <span className="flex shrink-0 items-baseline gap-3 pl-5 sm:pl-0">
                <Link to={it.to} className="text-sm font-medium whitespace-nowrap text-heading underline">
                  {it.action}
                </Link>
                {canAck && (
                  <Button className="!px-2.5 !py-0.5" disabled={send.isPending} onClick={() => send.mutate({ it })}>
                    Acknowledge
                  </Button>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
      {acked.length > 0 && (
        <details>
          <summary className="cursor-pointer text-sm font-medium text-heading">{plural(acked.length, 'acknowledged item')}</summary>
          <ul className="mt-2 flex flex-col divide-y divide-line">
            {acked.map((it) => {
              const a = acks.data!.find((x) => x.key === it.key)!;
              return (
                <li key={it.key} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2 first:pt-0 last:pb-0">
                  <span className="min-w-[12rem] flex-1 text-heading">
                    {it.text}
                    <span className="block text-sm text-muted" title={when(a.acked_at)}>
                      {who(a.actor)}, {ago(a.acked_at)}
                    </span>
                  </span>
                  <span className="flex shrink-0 items-baseline gap-3">
                    <Link to={it.to} className="text-sm font-medium whitespace-nowrap text-heading underline">
                      {it.action}
                    </Link>
                    {canAck && (
                      <Button className="!px-2.5 !py-0.5" disabled={send.isPending} onClick={() => send.mutate({ it, undo: true })}>
                        Undo
                      </Button>
                    )}
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="mt-2 text-sm text-muted">Acknowledging hides an item for everyone until it clears. It does not change traffic or stop notifications.</p>
        </details>
      )}
    </Panel>
  );
}

const sum2 = <K extends string>(xs: Record<K, number>[], k: K) => xs.reduce((n, x) => n + x[k], 0);

function Traffic({ r }: { r: Range }) {
  const { rows } = r;
  const logs = useLogSearch();
  const marks = useMarks(r.from);
  // The commonest codes each side answered, so a 502 from the edge reads
  // apart from a 502 the upstream sent.
  const codes = statusCodes(rows);
  const top = (origin: 'edge' | 'upstream') =>
    codes
      .filter((c) => c.origin === origin)
      .slice(0, 4)
      .map((c): [string, string, string | undefined] => [codeName(c.code), count(c.n), logs({ from: r.from, to: r.to, status: statusOf(c.code) })]);
  const edgeCodes = top('edge');
  const upstreamCodes = top('upstream');
  const loaded = r.q.data !== undefined;
  const n = sum(rows, (x) => x.requests);
  const limited = sum2(totals(rows), 'limited');
  const share = (x: number) => (loaded ? <Rolling text={pct(x, n)} /> : '…');
  return (
    <Panel
      title={`Traffic, ${r.title}`}
      link={['Stats', '/stats']}
      error={r.q.error}
      info="Counts the edges report every 10 seconds, including the minute in progress. Edge 5xx are answers the edge made itself, such as 503 from a rule that fails closed; upstream 5xx came from the upstream. Drag across the chart to zoom in. The marks above the chart are releases; each opens its version."
    >
      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-5">
        <Figure
          n={
            loaded ? (
              <span title={n.toLocaleString()}>
                <Rolling text={count(n)} />
              </span>
            ) : (
              '…'
            )
          }
          label="Requests"
        />
        <Figure n={share(limited)} label="Rate limited" sub={n ? <Rolling text={`${count(limited)} requests`} /> : undefined} />
        <Figure n={share(sum(rows, (x) => x.edge_5xx))} label="Edge 5xx" />
        <Figure n={share(sum(rows, (x) => x.upstream_5xx))} label="Upstream 5xx" />
        <Figure n={share(sum(rows, (x) => x.auth_failures))} label="Auth failures" />
      </dl>
      {loaded && (n === 0 && !r.zoom ? <p className="text-body">No traffic reported {r.phrase}.</p> : <Bars r={r} marks={marks} />)}
      {n > 0 && (
        <div className="grid gap-6 sm:grid-cols-2">
          {edgeCodes.length > 0 && <List title="Status codes the edge sent" items={edgeCodes} />}
          {upstreamCodes.length > 0 && <List title="Status codes from the upstream" items={upstreamCodes} />}
        </div>
      )}
    </Panel>
  );
}

function Limiting({ r }: { r: Range }) {
  const { rows } = r;
  const rules = totals(rows)
    .filter((r) => r.limited + r.logged > 0)
    .sort((a, b) => b.limited + b.logged - a.limited - a.logged)
    .slice(0, 5);
  const clients = new Map<string, { display: string; rule: string; n: number }>();
  for (const r of rows)
    for (const t of r.top_limited ?? []) {
      const e = clients.get(t.rule + t.key) ?? {
        display: t.display,
        rule: t.rule,
        n: 0,
      };
      e.n += t.limited + (t.logged ?? 0);
      clients.set(t.rule + t.key, e);
    }
  const top = [...clients.values()].sort((a, b) => b.n - a.n).slice(0, 5);
  const unranked = rules.filter((x) => ![...clients.values()].some((t) => t.rule === x.id)).map((x) => x.id);
  return (
    <Panel
      title={`Rate limiting, ${r.title}`}
      link={['Stats', '/stats']}
      info="Blocked counts requests a rule answered with 429. Logged instead of limited counts requests a log only rule found over its limit and let through. Both count every request, not a sample; clients are estimated from samples each edge keeps."
    >
      {r.q.data && rules.length === 0 ? (
        <p className="text-body">No rule blocked a request, or found one over its limit, {r.phrase}.</p>
      ) : (
        <div className="grid gap-6 sm:grid-cols-2">
          <List title="Rules" items={rules.map((r) => [r.id, r.limited ? `${count(r.limited)} blocked` : `${count(r.logged)} logged instead of limited`])} />
          <List title="Clients" items={top.map((t) => [t.display, `${count(t.n)} · ${t.rule}`])} />
          {unranked.length > 0 && (
            <div className="sm:col-span-2">
              <Unranked ids={unranked} />
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

// List is a short ranking; an item's optional third value links its name
// to the log store.
function List({ title, items }: { title: string; items: [string, string, (string | undefined)?][] }) {
  return (
    <div className="min-w-0">
      <h3 className="eyebrow mb-1 text-muted">{title}</h3>
      <ul className="divide-y divide-line text-sm">
        {items.map(([k, v, to]) => (
          <li key={k + v} className="flex justify-between gap-3 py-1.5">
            <code className="truncate text-heading" title={k}>
              <LogLink href={to}>{k}</LogLink>
            </code>
            <span className="whitespace-nowrap text-body tabular-nums">{v}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Policy({ versions, live }: { versions: NonNullable<DashboardData['versions']>; live: DashboardData['live'] }) {
  const v = versions.data?.find((x) => x.status === 'active');
  const cfg = live?.data?.config;
  const limits = cfg?.rate_limit_rules ?? [];
  const logOnly = limits.filter((r) => r.action === 'log').length;
  return (
    <Panel title="Live policy" link={v ? ['Version', `/versions/${v.version}`] : ['Versions', '/versions']} error={versions.error ?? live?.error}>
      {versions.data && !v ? (
        <p className="text-body">Nothing is published yet. Save the draft, then publish it.</p>
      ) : (
        <>
          {v && (
            <p className="text-body">
              <span className="font-semibold text-heading">Version {v.version}</span>, published by {who(v.author)}{' '}
              <time dateTime={v.published_at} title={when(v.published_at)}>
                {ago(v.published_at)}
              </time>
              {v.message && <span className="mt-1 block text-heading">“{v.message}”</span>}
            </p>
          )}
          {cfg && (
            <dl className="grid grid-cols-3 gap-4">
              {phases.map((p) => (
                <Figure
                  key={p.phase}
                  n={rulesOf(cfg, p.key).length}
                  label={p.title}
                  sub={p.phase === 'rate_limit' && limits.length > 0 ? `${logOnly} log only` : undefined}
                />
              ))}
            </dl>
          )}
        </>
      )}
    </Panel>
  );
}

function Fleet({ fleet, liveVersion, canaryVersion }: { fleet: NonNullable<DashboardData['fleet']>; liveVersion: number | undefined; canaryVersion: number | undefined }) {
  const edges = fleet.data ?? [];
  const live = edges.filter((e) => e.live);
  const by = (f: (e: Edge) => string) => {
    const n = new Map<string, number>();
    for (const e of live) n.set(f(e), (n.get(f(e)) ?? 0) + 1);
    return [...n].sort((a, b) => b[1] - a[1]);
  };
  const name = (v: number) => (v === liveVersion ? `v${v} live` : v === canaryVersion ? `v${v} canary` : `v${v}`);
  const latest = live.reduce<string | undefined>((t, e) => (!t || e.last_seen > t ? e.last_seen : t), undefined);
  return (
    <Panel title="Fleet" link={['Fleet', '/fleet']} error={fleet.error}>
      {fleet.data && edges.length === 0 ? (
        <p className="text-body">No edge has reported to this admin yet. Edges report once they fetch a snapshot.</p>
      ) : (
        <>
          <dl className="grid grid-cols-2 gap-4">
            <Figure n={fleet.data ? live.length : '…'} label="Reporting" sub={latest && `last report ${ago(latest)}`} />
            <Figure n={fleet.data ? edges.length - live.length : '…'} label="Gone" sub="no report in a minute" />
          </dl>
          {live.length > 0 && (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1">
              <List title="Versions loaded" items={by((e) => e.versions.map(name).join(' + ')).map(([k, n]) => [k, `${n} ${n === 1 ? 'edge' : 'edges'}`])} />
              <List title="Config from" items={by((e) => e.config_source).map(([k, n]) => [k, `${n} ${n === 1 ? 'edge' : 'edges'}`])} />
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

function Changes({ audit, verify }: { audit: NonNullable<DashboardData['audit']>; verify: DashboardData['verify'] }) {
  const events = (audit.data ?? []).filter((e) => e.action in said && !quiet.has(e.action)).slice(0, 8);
  const v = verify?.data?.[0];
  return (
    <Panel
      title="Recent changes"
      link={['Audit log', '/audit']}
      error={audit.error}
      info="Changes to policy, releases, settings, users and tokens, from the latest 100 audit events. Sign-ins and reads are left out here; the audit log has everything."
    >
      {v && (
        <p className={`-mt-2 text-sm ${v.details?.broken_at ? 'text-danger' : 'text-body'}`}>
          {v.details?.broken_at ? `Audit log tampering found at event ${v.details.broken_at}` : `Audit log intact to event ${v.details?.verified_to}`}, checked {ago(v.occurred_at)}.
        </p>
      )}
      {audit.data && events.length === 0 ? (
        <p className="text-body">No changes among the latest 100 audit events.</p>
      ) : (
        <ul className="divide-y divide-line text-sm">
          {events.map((e) => (
            <li key={e.seq} className="flex flex-wrap items-baseline justify-between gap-x-3 py-1.5">
              <span className="min-w-0">
                <span className="font-medium text-heading">{who(e.actor)}</span> <span className="text-body">{said[e.action]}</span>{' '}
                {/* A token's target is its ID; its name is what people gave it. */}
                <span className="wrap-anywhere text-heading">{e.action.startsWith('token.') && e.details?.name ? e.details.name : e.target}</span>
              </span>
              <time dateTime={e.occurred_at} title={when(e.occurred_at)} className="text-muted">
                {ago(e.occurred_at)}
              </time>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
