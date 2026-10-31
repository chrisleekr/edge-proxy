import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, type Json, Problem, useCan } from '../api';
import { LogLink, useLogSearch } from '../logSearch';
import { Link, useSearch } from '../router';
import { Badge, Button, Card, ErrorBox, Modal, NotFound, Notice, Page, Pending, Table, ago, when, who } from '../ui';
import { ranges, type RangeKey } from './Fleet';

// The autopilot's memory: the notes its runs recorded and admin checked.
// Claims are shown in words from a fixed dictionary, never parsed.

interface Scope {
  kind: 'global' | 'host' | 'route' | 'rule';
  host?: string;
  method?: string;
  template?: string;
  rule?: string;
}

interface Claim {
  metric: string;
  window: { last_minutes?: number; daily_utc?: [number, number] };
  op: '>=' | '<=';
  value: number;
  subject?: string;
}

interface Stats {
  metric: string;
  precision: 'exact' | 'estimate';
  from: string;
  to: string;
  value: number;
  sample: { requests: number; subjects: number; minutes: number };
  baseline: { days: number; present: number; median: number; p95: number; ratio: number; z: number | null; held_days: number } | null;
}

interface Links {
  page?: 'stats' | 'route' | 'rule';
  from_ms?: number;
  to_ms?: number;
  host?: string;
  method?: string;
  template?: string;
  status?: string;
  rule?: string;
}

export interface Note {
  id: number;
  kind: string;
  basis: 'observed' | 'hypothesis';
  scope: Scope;
  claim: Claim | null;
  effect: { key?: string[]; max_block_share?: number; require_jwt_claim?: boolean } | null;
  statement: string;
  rationale: string;
  stats: Stats | null;
  links: Links;
  anchor: string | null;
  trust: string;
  case_id: number;
  run_id: number;
  created_at: string;
}

interface NoteRead {
  note: Note;
  revisions: { id: number; change: string; trust: string; reason: string | null; actor: string; at: string }[];
  uses: { id: number; source: string; case_id: number | null; proposal_id: number | null; matched: boolean; cited: boolean; value: number | null; at: string }[];
  evidence: { run_id: number; seq: number; tool: string; sha256: string; payload?: Json; hidden?: boolean; hidden_reason?: string }[];
  blast_radius: { cases: number[]; proposals: number[]; enforcing_rules: string[] };
}

export const notesQuery = (trust = '') => ({
  queryKey: ['autopilot', 'notes', trust],
  queryFn: () => api<Note[]>('GET', `/api/autopilot/notes${trust ? `?trust=${encodeURIComponent(trust)}` : ''}`),
});

const trusts = ['unconfirmed', 'confirmed', 'dormant', 'retired', 'retracted'];
const tone = (t: string) => ({ confirmed: 'green', unconfirmed: 'amber', retracted: 'red' } as const)[t as 'confirmed'] ?? 'slate';
// A note that still counts, which a person can retract.
const kept = ['unconfirmed', 'confirmed', 'dormant'];
const num = (x: number) => x.toLocaleString(undefined, { maximumFractionDigits: 2 });

export const scopeWords = (s: Scope) =>
  ({ global: 'the fleet', host: `host ${s.host}`, route: `${s.method} ${s.host}${s.template}`, rule: `rule ${s.rule}` })[s.kind] ?? s.kind;

// claimWords is the claim as a sentence, from the metric catalog admin keeps.
export function claimWords(s: Scope, c: Claim) {
  const where = scopeWords(s);
  const what: Record<string, string> = {
    requests: 'requests to the fleet',
    auth_failures: 'requests that failed authentication',
    upstream_5xx: '5xx answers from the upstream',
    rule_evaluated: `requests ${where} checked`,
    rule_limited: `requests ${where} blocked with 429`,
    rule_would_limit: `requests ${where} found over its limit, log only`,
    rule_subjects: `clients ${where} found over its limit`,
    subject_limited: `requests from ${c.subject} ${where} found over its limit`,
    route_requests: `requests to ${where}`,
    route_4xx: `4xx answers on ${where}`,
    route_5xx: `5xx answers on ${where}`,
  };
  const h = (x: number) => `${String(x).padStart(2, '0')}:00`;
  const w = c.window.daily_utc ? `every day ${h(c.window.daily_utc[0])} to ${h(c.window.daily_utc[1])} UTC` : `in the ${c.window.last_minutes} minutes before it was checked`;
  return `${what[c.metric] ?? c.metric.replaceAll('_', ' ')}: ${c.op === '<=' ? 'at most' : 'at least'} ${num(c.value)} ${w}`;
}

export function Memory() {
  const [search, setSearch] = useSearch();
  const trust = search.get('trust') ?? '';
  const q = useQuery(notesQuery(trust));
  return (
    <Page
      title="Memory"
      info="What the autopilot's runs learned and recorded, newest first. Admin checks each claim on its own stats before a note is kept, and serves a note to later runs only while it holds."
    >
      <p className="-mt-3">
        <Link to="/autopilot" className="text-sm text-body underline">
          Autopilot
        </Link>
      </p>
      <label className="flex max-w-xs flex-col gap-1 text-sm">
        <span className="font-medium text-heading">Trust</span>
        <select value={trust} onChange={(e) => setSearch({ trust: e.target.value })}>
          <option value="">All</option>
          {trusts.map((t) => (
            <option key={t} value={t}>
              {t[0]!.toUpperCase() + t.slice(1)}
            </option>
          ))}
        </select>
      </label>
      {!q.data ? (
        <Pending error={q.error} />
      ) : (
        <Table head={['Note', 'Trust', 'Kind', 'Claim', 'Statement', 'Written']} empty={trust ? `No ${trust} note.` : 'No notes yet: a run records one when it learns something it can show.'}>
          {q.data.map((x) => (
            <tr key={x.id} className="align-top">
              <td className="px-3 py-2.5">
                <Link to={`/autopilot/notes/${x.id}`} className="font-medium text-heading underline">
                  Note {x.id}
                </Link>
              </td>
              <td className="px-3 py-2.5">
                <Badge tone={tone(x.trust)}>{x.trust}</Badge>
              </td>
              <td className="px-3 py-2.5 whitespace-normal">{x.kind.replaceAll('_', ' ')}</td>
              <td className="px-3 py-2.5 whitespace-normal">{x.claim ? claimWords(x.scope, x.claim) : `About ${scopeWords(x.scope)}, a hypothesis`}</td>
              <td className="px-3 py-2.5 whitespace-normal wrap-anywhere">{x.statement}</td>
              <td className="px-3 py-2.5" title={when(x.created_at)}>
                {ago(x.created_at)}
              </td>
            </tr>
          ))}
        </Table>
      )}
    </Page>
  );
}

// statsRange is the smallest range that shows from to now.
function statsRange(from: number): RangeKey {
  const minutes = (Date.now() - from) / 60_000;
  return (Object.keys(ranges) as RangeKey[]).find((k) => ranges[k].minutes >= minutes) ?? '30d';
}

export function NoteDetail({ id }: { id: number }) {
  const can = useCan();
  const qc = useQueryClient();
  const logs = useLogSearch();
  const [retracting, setRetracting] = useState(false);
  const q = useQuery({ queryKey: ['autopilot', 'note', id], queryFn: () => api<NoteRead>('GET', `/api/autopilot/notes/${id}`) });
  const routes = useQuery({
    queryKey: ['routes', 25],
    queryFn: () => api<{ routes: { id: number; method: string; host: string; template: string }[] }>('GET', '/api/observed-routes?hours=25'),
    enabled: can('stats.read'),
  });
  const reevaluate = useMutation({
    mutationFn: () => api<{ cases: number[] }>('POST', `/api/autopilot/notes/${id}/reevaluate`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['autopilot'] }),
  });
  if (!q.data) return q.error instanceof Problem && q.error.status === 404 ? <NotFound title="Note not found" back={['/autopilot/notes', 'Back to memory']} /> : <Pending error={q.error} />;
  const { note: x, revisions, uses, evidence, blast_radius: blast } = q.data;
  const l = x.links;
  const manage = can('autopilot.manage');
  const route = l.page === 'route' && l.method ? routes.data?.routes.find((r) => r.host === l.host && r.method === l.method && r.template === l.template) : undefined;
  const routeTo =
    l.page !== 'route'
      ? undefined
      : route
        ? `/routes/${route.id}`
        : `/routes?${new URLSearchParams({ host: l.host ?? '', ...(l.method ? { method: l.method, q: l.template ?? '' } : {}) })}`;
  // A log search takes a status code, and a note keeps only a class such as 4xx.
  const logURL = l.from_ms !== undefined && l.to_ms !== undefined ? logs({ from: l.from_ms, to: l.to_ms, host: l.host, status: /^\d{3}$/.test(l.status ?? '') ? l.status : undefined }) : undefined;
  const st = x.stats;
  return (
    <Page
      title={`Note ${x.id}`}
      actions={
        manage && (
          <>
            {kept.includes(x.trust) && (
              <Button variant="danger" onClick={() => setRetracting(true)}>
                Retract
              </Button>
            )}
            <Button disabled={reevaluate.isPending} onClick={() => reevaluate.mutate()}>
              Re-evaluate
            </Button>
          </>
        )
      }
    >
      <p className="-mt-3">
        <Link to="/autopilot/notes" className="text-sm text-body underline">
          Memory
        </Link>
      </p>
      {reevaluate.data && (
        <Notice>
          Opened {reevaluate.data.cases.length === 1 ? 'a case' : `${reevaluate.data.cases.length} cases`} on the rules still enforcing because of it:{' '}
          {reevaluate.data.cases.map((c, i) => (
            <span key={c}>
              {i > 0 && ', '}
              <Link to={`/autopilot/cases/${c}`} className="underline">
                Case {c}
              </Link>
            </span>
          ))}
        </Notice>
      )}
      <ErrorBox error={reevaluate.error} />
      <Card title="Claim">
        <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
          <dt className="text-body">Trust</dt>
          <dd>
            <Badge tone={tone(x.trust)}>{x.trust}</Badge>
          </dd>
          <dt className="text-body">Kind</dt>
          <dd className="text-heading">
            {x.kind.replaceAll('_', ' ')}, {x.basis === 'observed' ? 'observed: admin checks its claim' : 'a hypothesis: nothing admin can check'}
          </dd>
          <dt className="text-body">About</dt>
          <dd className="text-heading">{scopeWords(x.scope)}</dd>
          {x.claim && (
            <>
              <dt className="text-body">Claim</dt>
              <dd className="text-heading">{claimWords(x.scope, x.claim)}</dd>
            </>
          )}
          {x.effect && (
            <>
              <dt className="text-body">Effect</dt>
              <dd className="text-heading">
                {[
                  x.effect.key && `count by ${x.effect.key.join(' + ')}`,
                  x.effect.max_block_share !== undefined && `block at most ${num(x.effect.max_block_share * 100)}% of its requests`,
                  x.effect.require_jwt_claim && 'key on a verified JWT claim',
                ]
                  .filter(Boolean)
                  .join('; ')}
              </dd>
            </>
          )}
          {x.anchor && (
            <>
              <dt className="text-body">Anchor</dt>
              <dd className="text-heading">{x.anchor}</dd>
            </>
          )}
          <dt className="text-body">Statement</dt>
          <dd className="wrap-anywhere text-heading">{x.statement}</dd>
          {x.rationale && (
            <>
              <dt className="text-body">Why</dt>
              <dd className="wrap-anywhere text-heading">{x.rationale}</dd>
            </>
          )}
          <dt className="text-body">Written</dt>
          <dd>
            <time title={when(x.created_at)}>{ago(x.created_at)}</time> by{' '}
            <Link to={`/autopilot/cases/${x.case_id}`} className="underline">
              case {x.case_id}
            </Link>
          </dd>
        </dl>
      </Card>
      <Card title="Statistics" intro="What admin found on its own stats when the note was written.">
        {!st ? (
          <p className="text-body">No claim, so admin has nothing to check.</p>
        ) : (
          <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
            <dt className="text-body">Value</dt>
            <dd className="flex flex-wrap items-baseline gap-2">
              <span className="font-semibold text-heading tabular-nums">{num(st.value)}</span>
              <Badge tone={st.precision === 'exact' ? 'green' : 'amber'}>{st.precision === 'exact' ? 'Exact' : 'Estimate'}</Badge>
              {st.precision !== 'exact' && <span className="text-body">edges sample 1 in 16 over limit requests into client counts</span>}
            </dd>
            <dt className="text-body">Window</dt>
            <dd>
              <time title={when(st.from)}>{ago(st.from)}</time> to <time title={when(st.to)}>{ago(st.to)}</time>
            </dd>
            <dt className="text-body">Sample</dt>
            <dd>
              {num(st.sample.requests)} requests{st.sample.subjects > 0 && `, ${num(st.sample.subjects)} clients`}, over {num(st.sample.minutes)} minutes
            </dd>
            <dt className="text-body">Days before</dt>
            <dd>
              {!st.baseline || st.baseline.present === 0
                ? 'no earlier days'
                : `median ${num(st.baseline.median)}, p95 ${num(st.baseline.p95)}, present on ${st.baseline.present} of ${st.baseline.days} days; ${num(st.baseline.ratio)} times the median, robust z ${st.baseline.z === null ? 'undefined' : num(st.baseline.z)}; the claim held on ${st.baseline.held_days} of them`}
            </dd>
          </dl>
        )}
      </Card>
      <Card title="Links" intro="Where to look at what the claim counts.">
        <ul className="flex flex-col gap-1 text-sm">
          {routeTo && (
            <li>
              <Link to={routeTo} className="underline">
                {route ? `Route ${route.method} ${route.host}${route.template}` : `Routes on ${l.host}`}
              </Link>
            </li>
          )}
          {l.rule && (
            <li>
              <Link to={`/rules/rate_limit/${encodeURIComponent(l.rule)}`} className="underline">
                Rule {l.rule}
              </Link>
            </li>
          )}
          {l.from_ms !== undefined && (
            <li>
              <Link to={`/stats?range=${statsRange(l.from_ms)}`} className="underline">
                Stats over the window
              </Link>
            </li>
          )}
          {logURL && (
            <li>
              <LogLink href={logURL}>Log lines in the window</LogLink>
            </li>
          )}
        </ul>
      </Card>
      <Card title="Evidence" intro="The stats reads the run cited, as admin answered them.">
        {evidence.length === 0 ? (
          <p className="text-body">It cites no reads.</p>
        ) : (
          <ol className="flex flex-col gap-1 text-sm">
            {evidence.map((e) => (
              <li key={`${e.run_id}-${e.seq}`}>
                {e.hidden ? (
                  <p className="rounded-control px-3 py-1.5 text-body shadow-field">
                    <span className="font-mono text-heading">{e.tool}</span>, call {e.seq} of run {e.run_id}: answer hidden, it {e.hidden_reason}
                  </p>
                ) : (
                  <details className="rounded-control shadow-field">
                    <summary className="cursor-pointer px-3 py-1.5">
                      <span className="font-mono text-heading">{e.tool}</span>
                      <span className="text-body">
                        , call {e.seq} of run {e.run_id}
                      </span>
                    </summary>
                    <pre className="max-h-96 wrap-anywhere whitespace-pre-wrap border-t border-line p-3">{JSON.stringify(e.payload ?? null, null, 2)}</pre>
                  </details>
                )}
              </li>
            ))}
          </ol>
        )}
      </Card>
      <Card title="Uses" intro="The latest 200 times a run or admin's checks read it, newest first. A run of unmatched checks makes it dormant.">
        <Table head={['When', 'By', 'Case', 'Matched', 'Value']} empty="Not used yet.">
          {uses.map((u) => (
            <tr key={u.id}>
              <td className="px-3 py-2.5" title={when(u.at)}>
                {ago(u.at)}
              </td>
              <td className="px-3 py-2.5">
                {u.source}
                {u.cited && ', cited'}
              </td>
              <td className="px-3 py-2.5">
                {u.case_id !== null && (
                  <Link to={`/autopilot/cases/${u.case_id}`} className="underline">
                    Case {u.case_id}
                  </Link>
                )}
              </td>
              <td className="px-3 py-2.5">{u.matched ? 'yes' : 'no'}</td>
              <td className="px-3 py-2.5 tabular-nums">{u.value === null ? '' : num(u.value)}</td>
            </tr>
          ))}
        </Table>
      </Card>
      <Card title="Blast radius" intro="What relied on it, and what a retraction would make admin look at again.">
        <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
          <dt className="text-body">Cases served it</dt>
          <dd>
            {blast.cases.length === 0
              ? 'none'
              : blast.cases.map((c, i) => (
                  <span key={c}>
                    {i > 0 && ', '}
                    <Link to={`/autopilot/cases/${c}`} className="underline">
                      Case {c}
                    </Link>
                  </span>
                ))}
          </dd>
          <dt className="text-body">Proposals citing it</dt>
          <dd>{blast.proposals.length === 0 ? 'none' : blast.proposals.join(', ')}</dd>
          <dt className="text-body">Rules enforcing because of it</dt>
          <dd className="font-mono">{blast.enforcing_rules.length === 0 ? <span className="font-sans">none</span> : blast.enforcing_rules.join(', ')}</dd>
        </dl>
      </Card>
      <Card title="History">
        <ol className="flex flex-col gap-0.5 text-sm text-body">
          {revisions.map((r) => (
            <li key={r.id}>
              <time title={when(r.at)}>{ago(r.at)}</time>: {r.change}, {r.trust}
              {r.reason && `: ${r.reason}`} ({who(r.actor)})
            </li>
          ))}
        </ol>
      </Card>
      {retracting && <Retract id={x.id} onClose={() => setRetracting(false)} />}
    </Page>
  );
}

function Retract({ id, onClose }: { id: number; onClose: () => void }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState('');
  const retract = useMutation({
    mutationFn: () => api('POST', `/api/autopilot/notes/${id}/retract`, { reason }),
    onSuccess: () => (void qc.invalidateQueries({ queryKey: ['autopilot'] }), onClose()),
  });
  return (
    <Modal title={`Retract note ${id}?`} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), retract.mutate())}>
        <p>Runs are no longer served it, and it no longer counts toward confirming anything. Nothing is deleted: the retraction is kept in its history.</p>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-heading">Reason</span>
          <textarea rows={3} maxLength={500} required value={reason} onChange={(e) => setReason(e.target.value)} />
          <span className="text-body">Kept with the note's history and in the audit log.</span>
        </label>
        <ErrorBox error={retract.error} />
        <div className="flex flex-wrap justify-end gap-2">
          <Button data-autofocus onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="danger-solid" disabled={!reason.trim() || retract.isPending}>
            Retract
          </Button>
        </div>
      </form>
    </Modal>
  );
}
