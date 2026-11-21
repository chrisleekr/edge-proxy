import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { type ReactNode, useEffect, useRef } from 'react';
import { api, type VersionDetail } from './api';
import { outcomeSays, whyKept } from './guard';
import { ruleLink, rulesOf } from './phases';
import { ago } from './ui';
import { type Edge, pct, useRange } from './pages/Fleet';
import { type Event } from './pages/Audit';
import { type Anomaly, about, anomaliesQuery, groupAnomalies, label, subjectWord } from './pages/Notifications';
import { useVersions } from './pages/Publish';

// count is exact below a million, so a live figure visibly moves, and
// shortens larger totals, such as 12.35M, to fit its column; the exact
// number is in the request figure's title.
export const count = (n: number) => (n < 1e6 ? n.toLocaleString() : n.toLocaleString(undefined, { notation: 'compact', maximumFractionDigits: 2 }));

export function useDashboardData(can: (p: string) => boolean) {
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
export type DashboardData = ReturnType<typeof useDashboardData>;

export type AttentionItem = {
  // key names one condition; an ack lasts while the same key is present.
  key: string;
  // say is the item in plain text, kept with the ack for the audit log.
  say: string;
  tone: 'danger' | 'warning' | 'neutral';
  text: ReactNode;
  to: string;
  action: string;
  // under lists items shown with this one, such as the rule anomalies under a fleet one.
  under?: ReactNode[];
  // anomaly is the anomaly behind an anomaly item, the head of its group.
  anomaly?: Anomaly;
  // since is the ISO time the condition started, where the data has it.
  since?: string;
};

// Ack is an acknowledgement of an item, kept until the item clears.
export type Ack = { key: string; summary: string; actor: string; acked_at: string };

// sources names where an edge got its config, when not from admin.
const sources: Record<string, string> = { cache: 'their last saved copy', bootstrap: 'the bootstrap file from their deployment' };

// useAttention lists states someone should act on or watch, each read from
// admin: the dashboard sets no thresholds of its own, only the anomaly
// checks do.
export function useAttention(d: DashboardData, can: (p: string) => boolean) {
  const qc = useQueryClient();
  const items: AttentionItem[] = [];
  // Every condition that holds, before display cuts and nesting hide some from items.
  const present = new Set<string>();
  const acks = useQuery({ queryKey: ['attention-acks'], queryFn: () => api<Ack[]>('GET', '/api/attention/acks'), refetchInterval: 15_000, enabled: can('stats.read') });
  const ackedKeys = new Set((acks.data ?? []).map((a) => a.key));
  const checked: string[] = [];
  const cfg = d.live?.data?.config;
  // A check counts only once its data is in, so the panel never says
  // nothing needs attention about something it has not read yet. A failed
  // read is settled too, and shows its own error, so it can't wait forever.
  let waiting = false;
  // unreadable stops acks from being cleared on a read that did not work.
  let unreadable = false;
  const check = (q: { data?: unknown; isError?: boolean } | undefined, name: string) => {
    if (!q) return;
    unreadable ||= !!q.isError;
    if (q.data !== undefined) checked.push(name);
    else if (!q.isError) waiting = true;
  };
  check(d.live, 'kill switch');
  if (cfg?.kill_switch.rate_limit)
    items.push({
      key: 'kill:rate_limit',
      say: 'Rate limiting is switched off',
      tone: 'danger',
      text: 'Rate limiting is switched off. No request is blocked for going over a limit; every rule only counts what it would have blocked.',
      to: '/settings',
      action: 'Settings',
    });
  if (cfg?.kill_switch.block)
    items.push({
      key: 'kill:block',
      say: 'Blocking by access rules is switched off',
      tone: 'danger',
      text: 'Blocking by access rules is switched off. No request gets a 403 from a block setting; every such rule only logs what it would have blocked.',
      to: '/settings',
      action: 'Settings',
    });
  if (cfg?.kill_switch.auth)
    items.push({
      key: 'kill:auth',
      say: 'JWT checks are switched off',
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
      key: `rollback:${rb.version}`,
      say: rb.abort_reason ? `Version ${rb.version}'s canary was aborted` : `The guard rolled back version ${rb.version}`,
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
      ...(rb.guard_outcome && { since: rb.guard_outcome.at }),
    });
  for (const v of vs.filter((x) => (x.status === 'active' || x.status === 'canary') && x.guard_outcome?.decision === 'alert'))
    items.push({
      // The time keeps a later alert on the same version apart from this one.
      key: `guard:${v.version}:${v.guard_outcome!.at.replace(/[^A-Za-z0-9._-]/g, '-')}`,
      say: `The guard raised an alert on ${v.status === 'canary' ? 'canary' : 'live'} version ${v.version}`,
      tone: 'warning',
      text: [`The guard raised an alert on ${v.status === 'canary' ? 'canary' : 'live'} version ${v.version}, ${ago(v.guard_outcome!.at)}.`, ...outcomeSays(v.guard_outcome!), whyKept(v.guard_outcome!, v.source)].join(' '),
      to: `/versions/${v.version}`,
      action: 'Version',
      since: v.guard_outcome!.at,
    });
  const c = d.canary?.data?.canary;
  if (c)
    items.push({
      key: `canary:${c.version}`,
      say: `Version ${c.version} is on trial (canary)`,
      tone: 'neutral',
      text: `Version ${c.version} is on trial (canary) for ${c.percent}% of traffic, started ${ago(c.started_at)}. The rest still gets the live version until you promote or stop it.`,
      to: '/publish',
      action: 'Manage',
      since: c.started_at,
    });

  const edges = (d.fleet?.data ?? []).filter((e) => e.live);
  check(d.fleet, 'edges');
  const fallback = edges.filter((e) => e.config_source !== 'admin');
  if (fallback.length)
    items.push({
      key: 'fallback',
      say: 'Edges could not get config from admin',
      tone: 'warning',
      text: `${fallback.length} of ${edges.length} reporting edges could not get config from admin and run on ${[...new Set(fallback.map((e) => sources[e.config_source] ?? e.config_source))].join(' or ')}. They keep serving, but miss new publishes until they reach admin again.`,
      to: '/fleet',
      action: 'Fleet',
    });
  if (d.liveVersion !== undefined) {
    const behind = edges.filter((e) => !e.versions.includes(d.liveVersion!));
    if (behind.length)
      items.push({
        key: `behind:${d.liveVersion}`,
        say: `Edges have not loaded version ${d.liveVersion}`,
        tone: 'warning',
        text: `${behind.length} reporting ${behind.length === 1 ? 'edge has' : 'edges have'} not loaded version ${d.liveVersion}, so ${behind.length === 1 ? 'it still enforces' : 'they still enforce'} an older policy.`,
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
  for (const q of d.configs?.values() ?? []) {
    if (q && q.data === undefined && !q.isError) configsLoading = true;
    unreadable ||= !!q?.isError;
  }
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
        t.over += c.logged;
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
      key: 'valkey',
      say: 'Valkey did not answer rate limit checks',
      tone: 'warning',
      text: `Valkey did not answer ${count(failed)} rate limit checks in the ${d.span}, counting one check per rule per request. Each rule's "When Valkey cannot answer" setting decided the request: ${parts.join('; ')}.`,
      to: '/stats',
      action: 'Stats',
    });
  }
  // Log only runs without the penalty, so blocking would also stop a key's
  // later requests until its penalty ends.
  const over = [...shadow.values()].filter((x) => x.over > 0).sort((a, b) => b.over - a.over);
  for (const r of over) present.add(`shadow:${r.id}`);
  // Acked rules would otherwise take the top slots and hide a newer one.
  for (const r of configsLoading ? [] : [...over.filter((x) => !ackedKeys.has(`shadow:${x.id}`)).slice(0, 3), ...over.filter((x) => ackedKeys.has(`shadow:${x.id}`))])
    items.push({
      key: `shadow:${r.id}`,
      say: `Rule ${r.id} logged requests over its limit`,
      tone: 'neutral',
      text: (
        <>
          While set to log only, rule <code className="font-medium text-heading">{r.id}</code> checked {count(r.evaluated)} requests in the {d.span}. {count(r.over)} of them ({pct(r.over, r.evaluated)}) were over its limit, let through and logged. Every request is counted, not sampled; set to block, those requests would have got a 429
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
      {label(k.signal)} for {subjectWord(k)}<code className="font-medium">{k.rule}</code>: {k.summary}.
    </>
  );
  const firing = (d.anomalies?.data?.anomalies ?? []).filter((x) => x.state === 'firing');
  for (const a of firing) present.add(`anomaly:${a.id}`);
  for (const { a, under } of groupAnomalies(firing))
    items.push({
      key: `anomaly:${a.id}`,
      say: a.rule ? `${label(a.signal)} for ${about(a)}` : a.summary,
      tone: severe[a.severity as keyof typeof severe] ?? 'neutral',
      // A fleet summary names its signal; any other needs its subject: a rule, a crawler source, or an autopilot case or note.
      text: a.rule ? ruleSays(a) : `${a.summary}.`,
      to: a.phase === 'verified_bots' ? '/fleet#crawler-ranges' : '/notifications',
      action: a.phase === 'verified_bots' ? 'Fleet' : 'Notifications',
      under: under.map(ruleSays),
      anomaly: a,
      since: a.fired_at ?? a.started_at,
    });

  const v = d.verify?.data?.[0];
  check(d.verify, 'audit chain');
  if (v?.details?.broken_at)
    items.push({
      key: `audit:${v.details.broken_at}`,
      say: 'The audit log failed its tamper check',
      tone: 'danger',
      text: `The audit log failed its tamper check at event ${v.details.broken_at}: an event from there was changed, removed or signed with an unknown key.`,
      to: '/audit',
      action: 'Audit log',
    });

  const canAck = can('attention.ack');
  const refresh = () => qc.invalidateQueries({ queryKey: ['attention-acks'] });
  const send = useMutation({
    mutationFn: (a: { it: AttentionItem; undo?: boolean }) =>
      a.undo ? api('DELETE', `/api/attention/acks?key=${encodeURIComponent(a.it.key)}&reason=undo`) : api('POST', '/api/attention/acks', { key: a.it.key, summary: a.it.say.slice(0, 500) }),
    onSettled: refresh,
  });
  for (const it of items) present.add(it.key);
  const shown = items.filter((it) => !ackedKeys.has(it.key));
  const acked = items.filter((it) => ackedKeys.has(it.key));
  // An ack ends when its item is gone. Only a complete read says so: a
  // check that failed or is loading, or one this role cannot see, would
  // otherwise wipe acks. Valkey and log-only items follow the picked range,
  // so only the default range can tell they are gone.
  const complete = !waiting && !unreadable && !(d.canaryVersion !== undefined && !d.canary?.data) && !!(d.versions && d.canary && d.fleet && d.stats && d.anomalies && d.verify);
  // An ack is cleared only by data fetched after this browser first saw it, so
  // a dashboard older than the ack cannot clear it. Acks in the first response
  // count from mount, so an ack made between a source's first answer and the
  // first acks answer can still clear early; a source that is missing keeps it.
  const mounted = useRef<number>(null);
  const firstSeen = useRef(new Map<string, number>());
  const gotAcks = useRef(false);
  const sentClear = useRef(new Set<string>());
  const gate = complete && canAck;
  const candidates = (acks.data ?? []).filter((a) => !present.has(a.key) && (d.stats?.key === '24h' || !(a.key === 'valkey' || a.key.startsWith('shadow:')))).map((a) => a.key);
  const sourceOf = (k: string) => {
    const kind = k.split(':')[0];
    return { kill: d.live, rollback: d.versions, guard: d.versions, canary: d.canaryVersion === undefined ? d.versions : d.canary, fallback: d.fleet, behind: d.fleet, valkey: d.stats?.q, shadow: d.stats?.q, anomaly: d.anomalies, audit: d.verify }[kind!];
  };
  // No dependency list: refs are read here, and sentClear stops repeat sends.
  useEffect(() => {
    mounted.current ??= Date.now();
    if (acks.data) {
      // A key leaves sentClear only once its ack is gone, so a clear that
      // failed is not resent on every render.
      for (const k of firstSeen.current.keys())
        if (!ackedKeys.has(k)) {
          firstSeen.current.delete(k);
          sentClear.current.delete(k);
        }
      for (const k of ackedKeys) if (!firstSeen.current.has(k)) firstSeen.current.set(k, gotAcks.current ? acks.dataUpdatedAt : mounted.current);
      gotAcks.current = true;
    }
    if (!gate) return;
    const todo = candidates.filter((k) => !sentClear.current.has(k) && (sourceOf(k)?.dataUpdatedAt ?? 0) > (firstSeen.current.get(k) ?? Infinity));
    for (const k of todo) sentClear.current.add(k);
    if (todo.length)
      void Promise.allSettled(todo.map((k) => api('DELETE', `/api/attention/acks?key=${encodeURIComponent(k)}&reason=cleared`))).then(() => void refresh());
  });
  return { items, shown, acked, acks, send, canAck, waiting, checked, unreadable };
}

// Recent changes leaves out what the audit log shows only for the record.
export const quiet = new Set(['auth.login.success', 'auth.login.failure', 'auth.logout', 'audit.verify', 'config.export', 'audit.export', 'anomaly.fire', 'anomaly.resolve', 'attention.cleared', 'denylist.changed', 'ip_list.changed']);

