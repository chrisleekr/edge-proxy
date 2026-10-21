import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';
import { api, type Diff, type Json } from '../api';
import { Badge, Button, download, ErrorBox, Hint, Notice, Input, Page, Table, ago, when, who } from '../ui';
import { outcomeSays } from '../guard';
import { guardWords } from '../GuardForm';
import { DiffView, isEmpty } from './DiffView';

export interface Event {
  seq: number;
  occurred_at: string;
  actor: string;
  action: string;
  target: string;
  // Fields read here; the rest is shown as JSON.
  details: {
    changes?: Diff;
    broken_at?: number;
    verified_to?: number;
    name?: string;
    baseline?: number;
    signals?: Record<string, Json>;
    before?: Json;
    after?: Json;
    guard_settings?: Json;
    guard_override?: Json;
  } | null;
}

// said is what each audit action did, in words. The dashboard's quiet
// list says which it leaves out.
export const said: Record<string, string> = {
  'config.publish': 'published',
  'config.revert': 'reverted',
  'config.rollback': 'rolled back',
  'config.save': 'saved the',
  'config.rebase': 'rebased the',
  'config.copy_to_draft': 'copied a version to the',
  'config.import': 'imported config',
  'canary.manage': 'changed the canary',
  'canary.step': 'stepped the canary',
  'canary.promote': 'promoted the canary',
  'canary.abort': 'aborted the canary',
  'guard.rollback': 'rolled back',
  'guard.canary_abort': 'aborted the canary',
  'guard.alert': 'raised an alert on',
  'settings.save': 'changed settings',
  'settings.guard': 'changed guard settings',
  'user.create': 'added user',
  'user.disable': 'disabled user',
  'user.roles': 'changed roles of',
  'token.create': 'created token',
  'token.revoke': 'revoked token',
  'jwks.keys_changed': 'saw new signing keys for',
  'auth.login.success': 'signed in',
  'auth.login.failure': 'failed to sign in as',
  'auth.logout': 'signed out',
  'audit.verify': 'checked the audit log',
  'config.export': 'exported',
  'audit.export': 'exported the audit log',
  'auth.password.change': 'changed the password of',
  'route.delete': 'deleted route',
  'route.delete_all': 'deleted every route',
  'route_pattern.create': 'grouped routes as',
  'route_pattern.delete': 'stopped grouping routes as',
};

// flat lists an object's leaf values by dotted path, to compare two.
const flat = (v: Json, at = ''): [string, string][] =>
  v !== null && typeof v === 'object' && !Array.isArray(v) ? Object.entries(v).flatMap(([k, x]) => flat(x, at ? `${at}.${k}` : k)) : [[at, JSON.stringify(v)]];

// Changed is a before and after pair as the settings that differ, such as
// a guard settings save, rather than two whole copies.
function Changed({ before, after, words }: { before: Json; after: Json; words?: ((path: string, value: string | undefined) => readonly [string, string]) | undefined }) {
  const was = new Map(flat(before));
  const is = new Map(flat(after));
  const keys = [...new Set([...was.keys(), ...is.keys()])].filter((k) => was.get(k) !== is.get(k));
  if (!keys.length) return <p className="text-body">No settings changed.</p>;
  return (
    <ul className="font-mono wrap-anywhere">
      {keys.map((k) => {
        const [label, from] = words ? words(k, was.get(k)) : [k, was.get(k) ?? 'unset'];
        const to = words ? words(k, is.get(k))[1] : (is.get(k) ?? 'unset');
        return (
          <li key={k}>
            {label && `${label}: `}
            {from} → {to}
          </li>
        );
      })}
    </ul>
  );
}

// pairOf is an event's before and after: a settings save's own pair, or a
// publish's guard override beside the settings it replaced.
const pairOf = (e: Event): [Json, Json] | undefined =>
  e.details?.before !== undefined && e.details.after !== undefined
    ? [e.details.before, e.details.after]
    : e.details?.guard_settings !== undefined && e.details.guard_override !== undefined
      ? [e.details.guard_settings, e.details.guard_override]
      : undefined;
const paired = new Set(['before', 'after', 'guard_settings', 'guard_override']);

const example = {
  actor: 'such as user:admin',
  action: 'such as config.publish',
  target: 'such as version 2',
};

export function Audit() {
  const qc = useQueryClient();
  const [typed, setTyped] = useState({ actor: '', action: '', target: '', mentions: '' });
  // Filters apply once typing pauses, not on every keystroke.
  const [filter, setFilter] = useState(typed);
  useEffect(() => {
    const t = setTimeout(() => setFilter(typed), 300);
    return () => clearTimeout(t);
  }, [typed]);
  const q = useInfiniteQuery({
    queryKey: ['audit', filter],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => {
      const p = new URLSearchParams(filter);
      if (pageParam) p.set('before', String(pageParam));
      return api<Event[]>('GET', `/api/audit?${p}`);
    },
    // The API returns 100 rows per page, newest first.
    getNextPageParam: (last) => (last.length === 100 ? last.at(-1)?.seq : undefined),
    // The old rows stay while new filters load, so the table does not blank.
    placeholderData: keepPreviousData,
  });
  // The leader's daily full verification is audited; its latest result is
  // the integrity badge, without re-reading the whole chain here.
  const lastCheck = useQuery({
    queryKey: ['audit', 'last-verify'],
    queryFn: () => api<Event[]>('GET', '/api/audit?action=audit.verify'),
  });
  const badge = lastCheck.data?.[0];
  const verify = useMutation({
    mutationFn: () =>
      api<{
        ok: boolean;
        verified_to: number;
        broken_at?: number;
        reason?: string;
      }>('POST', '/api/audit/verify'),
    // Verify and export each write an audit row, which the badge and list show.
    onSuccess: () => qc.invalidateQueries({ queryKey: ['audit'] }),
  });
  const exportAll = useMutation({
    mutationFn: async () => download(await api('POST', '/api/audit/export'), 'audit-export.json'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['audit'] }),
  });
  const v = verify.data;
  // Suggestions come from the latest 100 events, whatever the filters.
  const recent = useQuery({
    queryKey: ['audit', 'recent'],
    queryFn: () => api<Event[]>('GET', '/api/audit'),
  });
  const seen = recent.data ?? [];
  // Memoized: typing in a filter re-renders the page on every keystroke, and
  // a few loaded pages are hundreds of rows.
  const rows = useMemo(
    () =>
      q.data?.pages.flat().map((e) => (
        <tr key={e.seq}>
          <td className="text-right align-top tabular-nums">{e.seq}</td>
          <td className="min-w-24 align-top whitespace-normal">{when(e.occurred_at)}</td>
          <td className="align-top">{who(e.actor)}</td>
          <td className="min-w-72 whitespace-normal">
            <div className="flex flex-col gap-1">
              <span>
                {/* The code stays beside the words: the action filter takes it. */}
                <span className="font-medium text-heading">{said[e.action] ?? e.action}</span>{' '}
                {e.target !== who(e.actor) && <span className="wrap-anywhere text-heading">{e.target}</span>} <code className="text-xs text-muted">{e.action}</code>
              </span>
              {/* A guard event's signals, in the words the dashboard uses. */}
              {e.details?.signals && (
                <ul className="flex flex-col gap-0.5">
                  {outcomeSays({ signals: e.details.signals, baseline_version: e.details.baseline }).map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              )}
              {/* A save that changed only tests has an empty config diff; its other details still say what changed. */}
              {e.details?.changes && !isEmpty(e.details.changes) && (
                <details>
                  <summary className="cursor-pointer font-medium text-heading">Before and after</summary>
                  <DiffView diff={e.details.changes} />
                </details>
              )}
              {pairOf(e) && (
                <Changed before={pairOf(e)![0]} after={pairOf(e)![1]} words={e.action === 'settings.guard' || e.details?.guard_override !== undefined ? guardWords : undefined} />
              )}
              {e.details && (
                <dl className="grid grid-cols-[max-content_1fr] gap-x-3">
                  {Object.entries(e.details)
                    // A null detail, such as a token's unset scopes, says nothing.
                    .filter(([k, v]) => k !== 'changes' && k !== 'signals' && v !== null && !(pairOf(e) && paired.has(k)))
                    .map(([k, v]) => (
                      <div key={k} className="contents">
                        <dt className="text-body">{k.replaceAll('_', ' ')}</dt>
                        <dd className="font-mono wrap-anywhere">{typeof v === 'string' ? v : typeof v === 'boolean' ? (v ? 'yes' : 'no') : JSON.stringify(v)}</dd>
                      </div>
                    ))}
                </dl>
              )}
            </div>
          </td>
        </tr>
      )),
    [q.data],
  );
  return (
    <Page
      title="Audit log"
      info="Every change, sign-in and automatic action, append-only. Each row is chained to the one before it with a key kept outside the database, so an edited or deleted row breaks the chain. It is verified every 5 minutes and in full daily; Verify chain checks it now."
      actions={
        <>
          <Button onClick={() => verify.mutate()} disabled={verify.isPending}>
            Verify chain
          </Button>
          <Button onClick={() => exportAll.mutate()} disabled={exportAll.isPending}>
            {exportAll.isPending ? 'Exporting…' : 'Export with HMACs'}
          </Button>
        </>
      }
    >
      {badge && (
        <p role="status" aria-label="Audit integrity">
          {badge.details?.broken_at ? (
            <Badge tone="red">tampering found at event {badge.details.broken_at}</Badge>
          ) : (
            <Badge tone="green">intact to event {badge.details?.verified_to}</Badge>
          )}{' '}
          <span className="text-sm text-body" title={when(badge.occurred_at)}>
            last full check {ago(badge.occurred_at)}
          </span>
        </p>
      )}
      {v && (
        <Notice tone={v.ok ? 'green' : 'red'}>{v.ok ? `No tampering found: events 1 to ${v.verified_to} are intact.` : `Tampering found at event ${v.broken_at}: ${v.reason}.`}</Notice>
      )}
      <ErrorBox error={verify.error ?? exportAll.error ?? q.error} />
      <form className="flex flex-col gap-1" onSubmit={(e) => e.preventDefault()}>
        <div className="flex flex-wrap items-end gap-2">
          {(['actor', 'action', 'target'] as const).map((k) => (
            <div key={k}>
              <Input label={`Filter by ${k}`} placeholder={example[k]} list={`audit-${k}`} value={typed[k]} onChange={(e) => setTyped({ ...typed, [k]: e.target.value })} />
              {/* The filter matches exactly, so offer the values already seen. */}
              <datalist id={`audit-${k}`}>
                {[...new Set(seen.map((e) => e[k]))].map((v) => (
                  <option key={v} value={v} />
                ))}
              </datalist>
            </div>
          ))}
          <Input label="Mentions" placeholder="such as login or vera" value={typed.mentions} onChange={(e) => setTyped({ ...typed, mentions: e.target.value })} />
        </div>
        <Hint>
          Actor, action and target match the whole value exactly; pick from the suggestions as you type. Mentions matches any part of the target or details, so a rule ID finds the
          saves that changed that rule and a username finds what happened to that user.
        </Hint>
      </form>
      {/* Action, target and details share a cell so a row fits a laptop
          screen without scrolling sideways. */}
      <Table head={['#', 'When', 'Actor', 'Event']} num={[0]} empty={q.data && 'No events match these filters.'}>
        {rows}
      </Table>
      {q.hasNextPage && (
        <Button onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
          Older events
        </Button>
      )}
    </Page>
  );
}
