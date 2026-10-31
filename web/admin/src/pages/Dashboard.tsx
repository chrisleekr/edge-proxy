import { useQueries, useQuery } from '@tanstack/react-query';
import { type ReactNode, useId } from 'react';
import { api, type VersionDetail } from '../api';
import { phases, ruleLink, rulesOf } from '../phases';
import { Link } from '../router';
import { ErrorBox, Info, Page, Rolling, ago, when, who } from '../ui';
import { type Event, said } from './Audit';
import { LogLink, useLogSearch } from '../logSearch';
import { Bars, codeName, type Edge, pct, type Range, RangePicker, type Row, statusCodes, statusOf, sum, Unranked, useMarks, useRange } from './Fleet';
import { type Anomaly, anomaliesQuery, groupAnomalies, label } from './Notifications';
import { useVersions } from './Publish';
import { outcomeSays, whyKept } from '../guard';

// Dashboard is the first screen. It leads with what needs a person, then
// shows traffic, rate limiting, the live policy, the fleet and recent
// changes. Each part needs its own permission and is left out without it.
// Query keys match the detail pages, so moving between them shares data.
export function Dashboard({ can }: { can: (p: string) => boolean }) {
  const d = useData(can);
  return (
    <Page title="Dashboard" actions={d.stats && <RangePicker r={d.stats} />}>
      <Attention d={d} />
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

// count is exact below a million, so a live figure visibly moves, and
// shortens larger totals, such as 12.35M, to fit its column; the exact
// number is in the request figure's title.
const count = (n: number) => (n < 1e6 ? n.toLocaleString() : n.toLocaleString(undefined, { notation: 'compact', maximumFractionDigits: 2 }));

function useData(can: (p: string) => boolean) {
  const config = can('config.read');
  const stats = can('stats.read');
  const audit = can('audit.read');
  const versions = useVersions();
  const liveVersion = versions.data?.find((v) => v.status === 'active')?.version;
  const canaryVersion = versions.data?.find((v) => v.status === 'canary')?.version;
  const live = useQuery({
    queryKey: ['version', liveVersion],
    queryFn: () => api<VersionDetail>('GET', `/api/versions/${liveVersion}`),
    enabled: config && liveVersion !== undefined,
  });
  const canary = useQuery({
    queryKey: ['canary'],
    queryFn: () =>
      api<{
        canary: { version: number; percent: number; started_at: string } | null;
      }>('GET', '/api/canary'),
    enabled: config && canaryVersion !== undefined,
    refetchInterval: 30_000,
  });
  const fleet = useQuery({
    queryKey: ['fleet'],
    queryFn: () => api<Edge[]>('GET', '/api/fleet'),
    refetchInterval: 15_000,
    enabled: stats,
  });
  const range = useRange(stats);
  // Published versions never change, so their configs are fetched once.
  const statVersions = [...new Set((range.q.data ?? []).map((r) => r.version))];
  const versionConfigs = useQueries({
    queries: statVersions.map((v) => ({
      queryKey: ['version', v],
      queryFn: () => api<VersionDetail>('GET', `/api/versions/${v}`),
      enabled: config && stats,
      staleTime: Infinity,
    })),
  });
  const events = useQuery({
    queryKey: ['audit', 'recent'],
    queryFn: () => api<Event[]>('GET', '/api/audit'),
    enabled: audit,
  });
  const verify = useQuery({
    queryKey: ['audit', 'last-verify'],
    queryFn: () => api<Event[]>('GET', '/api/audit?action=audit.verify'),
    enabled: audit,
  });
  const anomalies = useQuery({ ...anomaliesQuery, enabled: stats });
  return {
    // Attention reads the whole picked range, not a zoom into it.
    span: range.label,
    anomalies: stats ? anomalies : undefined,
    versions: config ? versions : undefined,
    // With nothing published there is no live config to check.
    live: config && liveVersion !== undefined ? live : undefined,
    canary: config ? canary : undefined,
    liveVersion,
    canaryVersion,
    fleet: stats ? fleet : undefined,
    stats: stats ? range : undefined,
    configs: config && stats ? new Map(statVersions.map((v, i) => [v, versionConfigs[i]])) : undefined,
    audit: audit ? events : undefined,
    verify: audit ? verify : undefined,
  };
}
type Data = ReturnType<typeof useData>;

function Panel({ title, info, link, error, children }: { title: string; info?: ReactNode; link?: [string, string]; error?: unknown; children: ReactNode }) {
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
      would_limit: number;
      failed: number;
    }
  >();
  for (const r of rows)
    for (const c of r.rate_limit_rules ?? []) {
      const t = rules.get(c.id) ?? {
        id: c.id,
        evaluated: 0,
        limited: 0,
        would_limit: 0,
        failed: 0,
      };
      for (const k of ['evaluated', 'limited', 'would_limit', 'failed'] as const) t[k] += c[k];
      rules.set(c.id, t);
    }
  return [...rules.values()];
}

type Item = {
  tone: 'danger' | 'warning' | 'neutral';
  text: ReactNode;
  to: string;
  action: string;
  // under lists items shown with this one, such as the rule anomalies under a fleet one.
  under?: ReactNode[];
};

// Attention lists states someone should act on or watch, each read from
// admin: the dashboard sets no thresholds of its own, only the anomaly
// checks do.
function Attention({ d }: { d: Data }) {
  const items: Item[] = [];
  const checked: string[] = [];
  const cfg = d.live?.data?.config;
  // A check counts only once its data is in, so the panel never says
  // nothing needs attention about something it has not read yet. A failed
  // read is settled too, and shows its own error, so it can't wait forever.
  let waiting = false;
  const check = (q: { data?: unknown; isError?: boolean } | undefined, name: string) => {
    if (!q) return;
    if (q.data !== undefined) checked.push(name);
    else if (!q.isError) waiting = true;
  };
  check(d.live, 'kill switch');
  if (cfg?.kill_switch.rate_limit)
    items.push({
      tone: 'danger',
      text: 'Rate limiting is switched off. No request is blocked for going over a limit; every rule only counts what it would have blocked.',
      to: '/settings',
      action: 'Settings',
    });
  if (cfg?.kill_switch.block)
    items.push({
      tone: 'danger',
      text: 'Blocking by config rules is switched off. No request gets a 403 from a block setting; every such rule only logs what it would have blocked.',
      to: '/settings',
      action: 'Settings',
    });
  if (cfg?.kill_switch.auth)
    items.push({
      tone: 'danger',
      text: 'JWT checks are switched off. Requests reach upstreams on every route without their token being checked.',
      to: '/settings',
      action: 'Settings',
    });

  const vs = d.versions?.data ?? [];
  check(d.versions, 'releases');
  // A rolled back canary leaves the live version as it was; a rolled back
  // full publish is followed by the guard's copy of the version before it.
  // Either way it is news until someone publishes again.
  const rb = vs.find((v) => v.status === 'rolled_back');
  const live = vs.find((v) => v.status === 'active');
  if (rb && vs.every((v) => v.version <= rb.version || v.source === 'guard_rollback'))
    items.push({
      tone: 'danger',
      text: [
        rb.abort_reason ? `Version ${rb.version}'s canary was aborted: ${rb.abort_reason}.` : `The guard rolled back version ${rb.version}${rb.guard_outcome ? ` ${ago(rb.guard_outcome.at)}` : ''}.`,
        live && `Edges serve version ${live.version}${live.source === 'guard_rollback' && live.based_on ? `, a copy of version ${live.based_on}` : ''}.`,
        ...(!rb.abort_reason && rb.guard_outcome ? outcomeSays(rb.guard_outcome) : []),
        'To try the change again, fix it in the draft; Publish shows how.',
      ]
        .filter(Boolean)
        .join(' '),
      to: `/versions/${rb.version}`,
      action: 'See why',
    });
  for (const v of vs.filter((x) => (x.status === 'active' || x.status === 'canary') && x.guard_outcome?.decision === 'alert'))
    items.push({
      tone: 'warning',
      text: [`The guard raised an alert on ${v.status === 'canary' ? 'canary' : 'live'} version ${v.version}, ${ago(v.guard_outcome!.at)}.`, ...outcomeSays(v.guard_outcome!), whyKept(v.guard_outcome!, v.source)].join(' '),
      to: `/versions/${v.version}`,
      action: 'Version',
    });
  const c = d.canary?.data?.canary;
  if (c)
    items.push({
      tone: 'neutral',
      text: `Version ${c.version} is on trial (canary) for ${c.percent}% of traffic, started ${ago(c.started_at)}. The rest still gets the live version until you promote or stop it.`,
      to: '/publish',
      action: 'Manage',
    });

  const edges = (d.fleet?.data ?? []).filter((e) => e.live);
  check(d.fleet, 'edges');
  const fallback = edges.filter((e) => e.config_source !== 'admin');
  if (fallback.length)
    items.push({
      tone: 'warning',
      text: `${fallback.length} of ${edges.length} live edges could not get config from admin and run on ${[...new Set(fallback.map((e) => sources[e.config_source] ?? e.config_source))].join(' or ')}. They keep serving, but miss new publishes until they reach admin again.`,
      to: '/fleet',
      action: 'Fleet',
    });
  if (d.liveVersion !== undefined) {
    const behind = edges.filter((e) => !e.versions.includes(d.liveVersion!));
    if (behind.length)
      items.push({
        tone: 'warning',
        text: `${behind.length} live ${behind.length === 1 ? 'edge has' : 'edges have'} not loaded version ${d.liveVersion}, so ${behind.length === 1 ? 'it still enforces' : 'they still enforce'} an older policy.`,
        to: '/fleet',
        action: 'Fleet',
      });
  }

  const rows = d.stats?.q.data ?? [];
  check(d.stats?.q, 'rate limit checks');
  // Each stats row is counted under the version that served it, and a
  // published version never changes, so its rules say what each rule did
  // with its own counts. The lines wait until every version has loaded, so a
  // slow fetch never reads as settings that could not be read.
  let configsLoading = false;
  for (const q of d.configs?.values() ?? []) if (q && q.data === undefined && !q.isError) configsLoading = true;
  waiting ||= configsLoading;
  const ruleAt = (version: number, id: string) => {
    const c = d.configs?.get(version)?.data?.config;
    const rule = c && rulesOf(c, 'rate_limit_rules').find((x) => x.id === id);
    return rule && { rule, kill: c.kill_switch.rate_limit };
  };
  const by = { passed: 0, refused: 0, local: 0, unknown: 0 };
  const shadow = new Map<string, { id: string; evaluated: number; over: number; penalty: boolean }>();
  for (const row of rows)
    for (const c of row.rate_limit_rules ?? []) {
      const at = ruleAt(row.version, c.id);
      if (c.failed) {
        const k = !at ? 'unknown' : at.rule.fail_mode === 'local' ? 'local' : at.rule.fail_mode === 'closed' && at.rule.action === 'block' && !at.kill ? 'refused' : 'passed';
        by[k] += c.failed;
      }
      // The kill switch has its own line; this one is about rules set to log.
      if (at?.rule.action === 'log' && !at.kill) {
        const t = shadow.get(c.id) ?? { id: c.id, evaluated: 0, over: 0, penalty: false };
        t.evaluated += c.evaluated;
        t.over += c.would_limit;
        t.penalty ||= !!at.rule.penalty;
        shadow.set(c.id, t);
      }
    }
  const failed = by.passed + by.refused + by.local + by.unknown;
  // Per check, not per request: a request matched by several rules counts
  // once for each, and a 429 from one rule wins over another's 503.
  if (failed && !configsLoading) {
    const parts = [
      by.passed && `${count(by.passed)} let through uncounted`,
      by.refused && `${count(by.refused)} answered 503, unless another rule blocked the request with a 429`,
      by.local && `${count(by.local)} counted on that edge alone, against its share of the limit`,
      by.unknown && `${count(by.unknown)} for rules whose settings could not be read`,
    ].filter(Boolean);
    items.push({
      tone: 'warning',
      text: `Valkey did not answer ${count(failed)} rate limit checks in the ${d.span}, counting one check per rule per request. Each rule's "When Valkey cannot answer" setting decided the request: ${parts.join('; ')}.`,
      to: '/stats',
      action: 'Stats',
    });
  }
  // Log only runs without the penalty, so blocking would also stop a key's
  // later requests until its penalty ends.
  for (const r of [...shadow.values()]
    .filter((x) => x.over > 0 && !configsLoading)
    .sort((a, b) => b.over - a.over)
    .slice(0, 3))
    items.push({
      tone: 'neutral',
      text: (
        <>
          While set to log only, rule <code className="font-medium text-heading">{r.id}</code> checked {count(r.evaluated)} requests in the {d.span}. {count(r.over)} of them ({pct(r.over, r.evaluated)}) were over its limit and let through. Every request is counted, not sampled; set to block, those requests would have got a 429
          {r.penalty ? ', and its penalty would have blocked more after them.' : '.'}
        </>
      ),
      to: ruleLink(cfg, r.id) ?? '/stats',
      action: 'Review',
    });

  // Firing anomalies, one line and one action each; rule anomalies for the
  // same signal as a firing fleet one are listed under it.
  check(d.anomalies, 'anomalies');
  const severe = { critical: 'danger', warning: 'warning' } as const;
  const ruleSays = (k: Anomaly) => (
    <>
      {label(k.signal)} for rule <code className="font-medium">{k.rule}</code>: {k.summary}.
    </>
  );
  for (const { a, under } of groupAnomalies((d.anomalies?.data?.anomalies ?? []).filter((x) => x.state === 'firing')))
    items.push({
      tone: severe[a.severity as keyof typeof severe] ?? 'neutral',
      // A fleet summary names its signal; a rule's needs the rule.
      text: a.rule ? ruleSays(a) : `${a.summary}.`,
      to: '/notifications',
      action: 'Notifications',
      under: under.map(ruleSays),
    });

  const v = d.verify?.data?.[0];
  check(d.verify, 'audit chain');
  if (v?.details?.broken_at)
    items.push({
      tone: 'danger',
      text: `The audit log failed its tamper check at event ${v.details.broken_at}: an event from there was changed, removed or signed with an unknown key.`,
      to: '/audit',
      action: 'Audit log',
    });

  if (!checked.length && !waiting) return null;
  const mark = {
    danger: 'bg-danger',
    warning: 'bg-warning',
    neutral: 'bg-muted',
  };
  return (
    <Panel
      title="Needs attention"
      info="Each line is read from admin: a state such as a running canary or an edge that cannot reach admin, or an anomaly the notification checks found firing. Red needs action now, amber needs a look, grey is worth knowing."
    >
      {items.length === 0 ? (
        <p className="text-body">{waiting ? 'Checking…' : `Nothing needs attention. Checked: ${checked.join(', ')}.`}</p>
      ) : (
        <ul className="flex flex-col divide-y divide-line">
          {items.map((it, i) => (
            <li key={i} className="flex items-baseline gap-3 py-2 first:pt-0 last:pb-0">
              <span aria-hidden className={`size-2 shrink-0 translate-y-[-1px] rounded-full ${mark[it.tone]}`} />
              <span className="sr-only">{{ danger: 'Urgent:', warning: 'Check:', neutral: 'Note:' }[it.tone]}</span>
              <span className="min-w-0 flex-1 text-heading">
                {it.text}
                {!!it.under?.length && (
                  <ul className="mt-1 flex flex-col gap-1 border-l border-line pl-3 text-sm text-body">
                    {it.under.map((u, j) => (
                      <li key={j}>{u}</li>
                    ))}
                  </ul>
                )}
              </span>
              <Link to={it.to} className="text-sm font-medium whitespace-nowrap text-heading underline">
                {it.action}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

const sum2 = <K extends string>(xs: Record<K, number>[], k: K) => xs.reduce((n, x) => n + x[k], 0);

// sources names where an edge got its config, when not from admin.
const sources: Record<string, string> = { cache: 'their last saved copy', bootstrap: 'the bootstrap file from their deployment' };

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
    .filter((r) => r.limited + r.would_limit > 0)
    .sort((a, b) => b.limited + b.would_limit - a.limited - a.would_limit)
    .slice(0, 5);
  const clients = new Map<string, { display: string; rule: string; n: number }>();
  for (const r of rows)
    for (const t of r.top_limited ?? []) {
      const e = clients.get(t.rule + t.key) ?? {
        display: t.display,
        rule: t.rule,
        n: 0,
      };
      e.n += t.limited + (t.would_limit ?? 0);
      clients.set(t.rule + t.key, e);
    }
  const top = [...clients.values()].sort((a, b) => b.n - a.n).slice(0, 5);
  const unranked = rules.filter((x) => ![...clients.values()].some((t) => t.rule === x.id)).map((x) => x.id);
  return (
    <Panel
      title={`Rate limiting, ${r.title}`}
      link={['Stats', '/stats']}
      info="Blocked counts requests a rule answered with 429. Over limit, log only counts requests a log only rule found over its limit and let through. Both count every request, not a sample; clients are estimated from samples each edge keeps."
    >
      {r.q.data && rules.length === 0 ? (
        <p className="text-body">No rule blocked a request, or found one over its limit, {r.phrase}.</p>
      ) : (
        <div className="grid gap-6 sm:grid-cols-2">
          <List title="Rules" items={rules.map((r) => [r.id, r.limited ? `${count(r.limited)} blocked` : `${count(r.would_limit)} over limit, log only`])} />
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

function Policy({ versions, live }: { versions: NonNullable<Data['versions']>; live: Data['live'] }) {
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

function Fleet({ fleet, liveVersion, canaryVersion }: { fleet: NonNullable<Data['fleet']>; liveVersion: number | undefined; canaryVersion: number | undefined }) {
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
            <Figure n={fleet.data ? live.length : '…'} label="Live edges" sub={latest && `last report ${ago(latest)}`} />
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

// Recent changes leaves out what the audit log shows only for the record.
const quiet = new Set(['auth.login.success', 'auth.login.failure', 'auth.logout', 'audit.verify', 'config.export', 'audit.export', 'anomaly.fire', 'anomaly.resolve']);

function Changes({ audit, verify }: { audit: NonNullable<Data['audit']>; verify: Data['verify'] }) {
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
