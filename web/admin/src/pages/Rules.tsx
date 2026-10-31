import { closestCenter, DndContext, type DragEndEvent, KeyboardSensor, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
import { arrayMove, SortableContext, sortableKeyboardCoordinates, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useContext, useState } from 'react';
import { api, etag, type Json, type Phase, Problem, type Rule, useCan } from '../api';
import { draftKey, useDraft, useOptionalDraft } from '../draft';
import { phases, rulesOf } from '../phases';
import { Link, navigate } from '../router';
import { Badge, Button, CanWrite, Card, Editable, ErrorBox, Input, Page, ReadOnlyNote, when } from '../ui';
import { countWords, type Range, RangePicker, ruleCounts, Spark, useRange } from './Fleet';

// Durations arrive as Go writes them ("1m0s"); trailing zero units are noise.
const short = (d: string | undefined) => d?.replace(/(\D)0s$/, '$1').replace(/(\D)0m$/, '$1');

// setting is one config setting in a few words: its value when short.
// bytes shows a size in the largest unit that divides it evenly, so it
// reads back exactly as written.
const bytes = (n: number) => {
  for (const [u, size] of [['GiB', 2 ** 30], ['MiB', 2 ** 20], ['KiB', 2 ** 10]] as const) if (n >= size && n % size === 0) return `${n / size} ${u}`;
  return `${n.toLocaleString()} bytes`;
};

const setting = ([k, v]: [string, Json]) => {
  if (k === 'auth') {
    const a = v as { mode?: string; accepted?: string[] };
    return `auth ${a.mode ?? ''}${a.accepted?.length ? ` from ${a.accepted.join(', ')}` : ''}`;
  }
  if (k === 'cors_policy') return v === '' ? 'CORS off' : `CORS ${String(v)}`;
  if (k === 'body_limit' && typeof v === 'number') return `body limit ${bytes(v)}`;
  if (k === 'upstream_timeout' && typeof v === 'string') return `upstream timeout ${short(v)}`;
  if (k === 'locale') return v ? 'detects locale' : 'no locale';
  if (k === 'ratelimit_headers') return v ? 'RateLimit headers' : 'no RateLimit headers';
  if (k === 'block') return v === 'block' ? 'blocks with 403' : 'log only, would block';
  if (k === 'responses' && v !== null && typeof v === 'object')
    return Object.entries(v)
      .map(([kind, t]) => `${kind.replaceAll('_', ' ')} response ${String(t)}`)
      .join(', ');
  return v !== null && typeof v === 'object' ? k : `${k} ${String(v)}`;
};

// onFailure is what a rate limit rule does when Valkey cannot answer, when
// that is not the default of letting the request through.
const onFailure: Record<string, string> = { closed: '503 if Valkey is down', local: 'counts per edge if Valkey is down' };

type HeaderOp = { op: string; name?: string; from?: string; to?: string; names?: string[] };

// headerOp is one operation in words, such as "rename x-a to x-b".
const headerOp = (o: HeaderOp) => `${o.op} ${o.from ? `${o.from} to ${o.to ?? ''}` : (o.name ?? o.names?.join(' ') ?? '')}`.trim();

// keyPart is one part of a rate limit key in words, such as "X-Api-Key
// header" for header:X-Api-Key.
function keyPart(part: string) {
  const i = part.indexOf(':');
  const [kind, name] = i < 0 ? [part, ''] : [part.slice(0, i), part.slice(i + 1)];
  const named: Record<string, string> = { header: `${name} header`, cookie: `${name} cookie`, query: `${name} query argument`, jwt_claim: `JWT ${name} claim` };
  return named[kind] ?? { ip: 'IP', host: 'hostname', method: 'method', country: 'country', asnum: 'AS number', ja4: 'JA4', locale: 'locale', constant: 'one shared count' }[kind] ?? part;
}

// distinct and counted say what a rule counts when it is not requests.
const distinctNames: Record<string, string> = { path: 'paths', ip: 'IPs', asnum: 'AS numbers', ja4: 'JA4s' };
const distinct = (d: Json) => {
  if (typeof d !== 'string') return '';
  if (d.startsWith('query:')) return ` different ${d.slice(6)} query arguments`;
  return ` different ${distinctNames[d] ?? d}`;
};
const counted = (c: Json) => (Array.isArray(c) && c.length ? ` of ${c.join(', ')} responses` : '');

// summary is a rule's action in a few words; the editor shows the rest.
export function summary(r: Rule) {
  if (r.limit !== undefined) {
    // A log only rule never answers 503 and starts no penalty until it blocks.
    const log = r.action === 'log';
    return [
      `${log ? 'log only' : 'block'} over ${r.limit.toLocaleString()}${distinct(r.distinct_of)} per ${short(r.period)}${counted(r.count_statuses)} by ${(r.key ?? []).map(keyPart).join(' + ')}`,
      typeof r.penalty === 'string' && `${short(r.penalty)} penalty${log ? ' once it blocks' : ''}`,
      !(log && r.fail_mode === 'closed') && onFailure[String(r.fail_mode)],
    ]
      .filter(Boolean)
      .join(', ');
  }
  if (r.ops) return r.ops.map((o) => headerOp(o as HeaderOp)).join(', ') || 'no operations';
  return Object.entries(r.settings ?? {}).map(setting).join(', ') || 'no settings';
}

// logOnly says a rule only logs what it would block: a rate limit set to
// log, or a config rule whose block setting logs.
export const logOnly = (r: Rule) => r.action === 'log' || r.settings?.block === 'log';

// Live is a rule's counts over the picked range, with a spark of its matches.
export function Live({ r, id }: { r: Range; id: string }) {
  if (!r.q.data) return null;
  return (
    <span className="flex items-center gap-2 text-sm text-body">
      <Spark rows={r.rows} from={r.from} to={r.to} value={(x) => ruleCounts([x], id).matched} />
      <span>
        {r.phrase.charAt(0).toUpperCase() + r.phrase.slice(1)}: {countWords(ruleCounts(r.rows, id))}
      </span>
    </span>
  );
}

function Row({ rule, to, phase, live }: { rule: Rule; to: string; phase: Phase; live?: Range | undefined }) {
  // The condition, rendered by the server, so the list says what each rule
  // matches without opening it. Rendering is deterministic, so it never goes stale.
  const rendered = useQuery({
    queryKey: ['render', phase, JSON.stringify(rule.expression)],
    queryFn: () => api<{ text: string }>('POST', '/api/expr/render', { ast: rule.expression, phase }),
    staleTime: Infinity,
  });
  const { setNodeRef, attributes, listeners, transform, transition } = useSortable({ id: rule.id });
  const style = { transform: transform ? `translate3d(0, ${transform.y}px, 0)` : undefined, transition };
  const expires = typeof rule.expires_at === 'string' ? rule.expires_at : undefined;
  return (
    <li ref={setNodeRef} style={style} className="flex items-center gap-3 border-b border-line bg-panel py-2 last:border-0">
      <button type="button" aria-label={`Move ${rule.id}`} className="shrink-0 cursor-grab touch-none self-start rounded-control px-1.5 py-0.5 text-body hover:bg-soft hover:text-heading" {...attributes} {...listeners}>
        ⠿
      </button>
      <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-0.5">
        <Link to={to} className="font-mono text-sm font-medium whitespace-nowrap text-heading underline">
          {rule.id}
        </Link>
        {logOnly(rule) && <Badge tone="amber">log only</Badge>}
        {expires && <Badge tone="amber">{`${new Date(expires) <= new Date() ? 'expired' : 'expires'} ${when(expires)}`}</Badge>}
        <span className="text-sm text-body">{summary(rule)}</span>
        {live && (
          <span className="basis-full">
            <Live r={live} id={rule.id} />
          </span>
        )}
        {rendered.data && (
          <code className="basis-full truncate text-sm text-body" title={rendered.data.text}>
            {rendered.data.text === 'true' ? 'for every request' : `when ${rendered.data.text}`}
          </code>
        )}
      </div>
    </li>
  );
}

// AdoptButton copies a live autopilot rule into the draft as a rule of your
// own, with no expiry. It shows nothing for a role that can't change the
// draft, and says so once the draft keeps the copy.
export function AdoptButton({ id }: { id: string }) {
  const d = useOptionalDraft();
  const qc = useQueryClient();
  const write = useCan()('config.write');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  if (!d) return null;
  // An adoption counts only while its copy, the id without ap-, is still a
  // rate limit rule in the draft; the server matches the same way.
  if (d.draft.adopted.includes(id) && rulesOf(d.draft.config, 'rate_limit_rules').some((r) => r.id === id.replace(/^ap-/, '')))
    return <span className="text-sm text-body">adopted, leaves autopilot on next publish</span>;
  if (!write) return null;
  const adopt = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await api('POST', '/api/draft/adopt', { id }, { 'If-Match': etag(d.draft.revision) });
      await qc.invalidateQueries({ queryKey: draftKey });
    } catch (e) {
      // Someone saved first: fetch their revision so a retry can succeed.
      if (e instanceof Problem && e.status === 412) await qc.invalidateQueries({ queryKey: draftKey });
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button disabled={busy || d.dirty} title={d.dirty ? 'Save or discard your changes first' : undefined} onClick={() => void adopt()}>
        Adopt
      </Button>
      {error !== undefined && <ErrorBox error={error} />}
    </>
  );
}

// AutopilotRules lists the active version's autopilot rules. The draft does
// not hold them, so they can't be edited; adopting one copies it into the
// draft as a rule of your own.
function AutopilotRules() {
  const d = useDraft();
  const write = useCan()('config.write');
  const overlay = d.draft.overlay;
  if (overlay.length === 0) return null;
  return (
    <section aria-labelledby="autopilot-rules" className="mt-4 border-t border-line pt-3">
      <h3 id="autopilot-rules" className="text-sm font-medium text-heading">
        Autopilot rules
      </h3>
      <p className="text-sm text-body">Run after the rules above, each until it expires. Every publish keeps them. Adopt one to keep it as your own rule, with no expiry.</p>
      {write && d.dirty && <p className="text-sm text-body">Save or discard your changes first to adopt a rule.</p>}
      <ul aria-label="Autopilot rules">
        {overlay.map((rule) => {
          const expires = typeof rule.expires_at === 'string' ? rule.expires_at : undefined;
          return (
            <li key={rule.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-line py-2 last:border-0">
              <Link to={`/autopilot?rule=${encodeURIComponent(rule.id)}`} className="font-mono text-sm font-medium text-heading underline">
                {rule.id}
              </Link>
              <Badge>autopilot</Badge>
              {expires && <Badge tone="amber">{`${new Date(expires) <= new Date() ? 'expired' : 'expires'} ${when(expires)}`}</Badge>}
              <span className="text-sm text-body">{summary(rule)}</span>
              <AdoptButton id={rule.id} />
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function Rules() {
  const d = useDraft();
  const canWrite = useContext(CanWrite);
  const stats = useCan()('stats.read');
  const r = useRange(stats);
  const sensors = useSensors(useSensor(PointerSensor), useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }));
  const [find, setFind] = useState('');
  // A rule's ID, summary and the values in its condition, such as a path
  // or header name, so either what it is called or what it matches finds it.
  const words = find.trim().toLowerCase();
  const matches = (r: Rule) => !words || `${r.id} ${summary(r)} ${JSON.stringify(r.expression)}`.toLowerCase().includes(words);
  return (
    <Page
      title="Rules"
      info={`A request passes the three phases in order: config picks its settings, rate limit counts it, request headers shape what the upstream receives. Each rule is a condition and what to do when it matches. Rules run top to bottom within each phase.${canWrite ? ' Drag to reorder, or focus the handle and use Space and the arrow keys.' : ''}${stats ? " Each rule's counts cover the picked range; every request is counted, not sampled." : ''}`}
      actions={stats && <RangePicker r={r} />}
    >
      <ReadOnlyNote />
      <Input label="Find a rule" hint="Part of an ID, a setting or a value the rule matches, such as login, block or /api/." type="search" className="max-w-md" value={find} onChange={(e) => setFind(e.target.value)} />
      {phases.map(({ phase, key, title, intro, info }) => {
        const rules = rulesOf(d.config, key);
        const shown = rules.filter(matches);
        const move = (e: DragEndEvent) => {
          const from = rules.findIndex((r) => r.id === e.active.id);
          const to = rules.findIndex((r) => r.id === e.over?.id);
          if (from >= 0 && to >= 0 && from !== to) d.setConfig((c) => ({ ...c, [key]: arrayMove(rules, from, to) }));
        };
        // What a screen reader hears while a rule is moved, in place of the
        // library's "draggable item ... droppable area".
        const at = (id: unknown) => `position ${rules.findIndex((r) => r.id === id) + 1} of ${rules.length}`;
        const accessibility = {
          screenReaderInstructions: { draggable: 'Press Space to pick up the rule, the arrow keys to move it, and Space to drop it, or Escape to cancel.' },
          announcements: {
            onDragStart: ({ active }: { active: { id: unknown } }) => `Picked up rule ${String(active.id)}, at ${at(active.id)}.`,
            onDragOver: ({ active, over }: { active: { id: unknown }; over: { id: unknown } | null }) => (over ? `Rule ${String(active.id)} would move to ${at(over.id)}.` : undefined),
            onDragEnd: ({ active, over }: { active: { id: unknown }; over: { id: unknown } | null }) =>
              over && over.id !== active.id ? `Rule ${String(active.id)} moved to ${at(over.id)}. Save the draft to keep the new order.` : `Rule ${String(active.id)} stays at ${at(active.id)}.`,
            onDragCancel: ({ active }: { active: { id: unknown } }) => `Move cancelled. Rule ${String(active.id)} stays at ${at(active.id)}.`,
          },
        };
        return (
          <Card key={phase} title={title} intro={intro} info={info}>
            <Editable>
              <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={move} accessibility={accessibility}>
                <SortableContext items={shown.map((r) => r.id)} strategy={verticalListSortingStrategy}>
                  <ul aria-label={title}>
                    {shown.map((x) => (
                      <Row key={x.id} rule={x} phase={phase} to={`/rules/${phase}/${encodeURIComponent(x.id)}`} live={stats ? r : undefined} />
                    ))}
                  </ul>
                </SortableContext>
              </DndContext>
              {rules.length === 0 && <p className="text-body">No rules in this phase yet.</p>}
              {rules.length > 0 && shown.length === 0 && <p className="text-body">No rule matches “{find.trim()}”.</p>}
              {words && shown.length > 0 && (
                <p className="text-sm text-body">
                  {shown.length} of {rules.length} shown.
                </p>
              )}
              {canWrite && (
                <Button className="mt-3" onClick={() => navigate(`/rules/${phase}/`)}>
                  Add {title.toLowerCase().replace(/s$/, '')}
                </Button>
              )}
            </Editable>
            {phase === 'rate_limit' && <AutopilotRules />}
          </Card>
        );
      })}
    </Page>
  );
}
