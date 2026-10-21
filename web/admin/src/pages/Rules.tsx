import { closestCenter, DndContext, type DragEndEvent, KeyboardSensor, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
import { arrayMove, SortableContext, sortableKeyboardCoordinates, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable';
import { useQuery } from '@tanstack/react-query';
import { useContext, useState } from 'react';
import { api, type Json, type Phase, type Rule } from '../api';
import { useDraft } from '../draft';
import { phases, rulesOf } from '../phases';
import { Link, navigate } from '../router';
import { Button, CanWrite, Card, Editable, Input, Page, ReadOnlyNote } from '../ui';

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
  return named[kind] ?? { ip: 'IP', host: 'hostname', method: 'method', country: 'country', asnum: 'AS number', locale: 'locale', constant: 'one shared count' }[kind] ?? part;
}

// summary is a rule's action in a few words; the editor shows the rest.
export function summary(r: Rule) {
  if (r.limit !== undefined) {
    // A log only rule never answers 503 and starts no penalty until it blocks.
    const log = r.action === 'log';
    return [
      `${log ? 'log only' : 'block'} over ${r.limit.toLocaleString()} per ${short(r.period)} by ${(r.key ?? []).map(keyPart).join(' + ')}`,
      typeof r.penalty === 'string' && `${short(r.penalty)} penalty${log ? ' once it blocks' : ''}`,
      !(log && r.fail_mode === 'closed') && onFailure[String(r.fail_mode)],
    ]
      .filter(Boolean)
      .join(', ');
  }
  if (r.ops) return r.ops.map((o) => headerOp(o as HeaderOp)).join(', ') || 'no operations';
  return Object.entries(r.settings ?? {}).map(setting).join(', ') || 'no settings';
}

function Row({ rule, to, phase }: { rule: Rule; to: string; phase: Phase }) {
  // The condition, rendered by the server, so the list says what each rule
  // matches without opening it. Rendering is deterministic, so it never goes stale.
  const when = useQuery({
    queryKey: ['render', phase, JSON.stringify(rule.expression)],
    queryFn: () => api<{ text: string }>('POST', '/api/expr/render', { ast: rule.expression, phase }),
    staleTime: Infinity,
  });
  const { setNodeRef, attributes, listeners, transform, transition } = useSortable({ id: rule.id });
  const style = { transform: transform ? `translate3d(0, ${transform.y}px, 0)` : undefined, transition };
  return (
    <li ref={setNodeRef} style={style} className="flex items-center gap-3 border-b border-line bg-panel py-2 last:border-0">
      <button type="button" aria-label={`Move ${rule.id}`} className="shrink-0 cursor-grab touch-none self-start rounded-control px-1.5 py-0.5 text-body hover:bg-soft hover:text-heading" {...attributes} {...listeners}>
        ⠿
      </button>
      <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-0.5">
        <Link to={to} className="font-mono text-sm font-medium whitespace-nowrap text-heading underline">
          {rule.id}
        </Link>
        <span className="text-sm text-body">{summary(rule)}</span>
        {when.data && (
          <code className="basis-full truncate text-sm text-body" title={when.data.text}>
            {when.data.text === 'true' ? 'for every request' : `when ${when.data.text}`}
          </code>
        )}
      </div>
    </li>
  );
}

export function Rules() {
  const d = useDraft();
  const canWrite = useContext(CanWrite);
  const sensors = useSensors(useSensor(PointerSensor), useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }));
  const [find, setFind] = useState('');
  // A rule's ID, summary and the values in its condition, such as a path
  // or header name, so either what it is called or what it matches finds it.
  const words = find.trim().toLowerCase();
  const matches = (r: Rule) => !words || `${r.id} ${summary(r)} ${JSON.stringify(r.expression)}`.toLowerCase().includes(words);
  return (
    <Page
      title="Rules"
      info="A request passes the three phases in order: config picks its settings, rate limit counts it, request headers shape what the upstream receives. Each rule is a condition and what to do when it matches."
    >
      <ReadOnlyNote />
      <p className="max-w-prose text-body">
        Rules run top to bottom within each phase.{canWrite && ' Drag to reorder, or focus the handle and use Space and the arrow keys.'}
      </p>
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
                    {shown.map((r) => (
                      <Row key={r.id} rule={r} phase={phase} to={`/rules/${phase}/${encodeURIComponent(r.id)}`} />
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
          </Card>
        );
      })}
    </Page>
  );
}
