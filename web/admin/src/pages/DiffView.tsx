import type { Diff, FieldChange, Json } from '../api';
import { Badge } from '../ui';

const show = (v: Json) => (v === undefined || v === null ? '—' : typeof v === 'string' ? v : JSON.stringify(v));

function Changes({ list }: { list: FieldChange[] }) {
  return (
    <ul className="flex flex-col gap-1">
      {list.map((f) => (
        <li key={f.path} className="text-sm">
          <code className="font-medium">{f.path}</code>: <del className="text-danger">{show(f.before)}</del> → <ins className="text-success no-underline">{show(f.after)}</ins>
        </li>
      ))}
    </ul>
  );
}

export const isEmpty = (diff: Diff) =>
  !diff.sections?.length && Object.values(diff.phases ?? {}).every((p) => !p.added?.length && !p.removed?.length && !p.changed?.length && !p.reordered);

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`;

// describe says what a diff holds in words: "3 rules added, 1 setting changed".
export function describe(diff: Diff) {
  const ps = Object.values(diff.phases ?? {});
  const count = (f: (p: (typeof ps)[number]) => unknown[] | null) => ps.reduce((n, p) => n + (f(p)?.length ?? 0), 0);
  const parts = [
    [count((p) => p.added), 'added'],
    [count((p) => p.removed), 'removed'],
    [count((p) => p.changed), 'changed'],
  ]
    .filter(([n]) => n)
    .map(([n, what]) => `${plural(n as number, 'rule')} ${what as string}`);
  if (ps.some((p) => p.reordered)) parts.push('rules reordered');
  if (diff.sections?.length) parts.push(`${plural(diff.sections.length, 'setting')} changed`);
  return parts.join(', ') || 'No changes';
}

// DiffView renders the API's semantic diff: rules by ID and changed fields,
// with expressions as rendered text.
export function DiffView({ diff }: { diff: Diff }) {
  // A phase with no changes would show as an empty heading.
  const phases = Object.entries(diff.phases ?? {}).filter(([, p]) => p.added?.length || p.removed?.length || p.changed?.length || p.reordered);
  if (isEmpty(diff)) return <p className="text-body">No changes.</p>;
  return (
    <div className="flex flex-col gap-3" data-testid="diff">
      {diff.sections && diff.sections.length > 0 && <Changes list={diff.sections} />}
      {phases.map(([name, p]) => (
        <div key={name}>
          <h3 className="mb-1 text-sm font-semibold">{(name.charAt(0).toUpperCase() + name.slice(1)).replaceAll('_', ' ')}</h3>
          <ul className="flex flex-col gap-1 text-sm">
            {p.added?.map((id) => (
              <li key={`+${id}`}>
                <Badge tone="green">added</Badge> <code>{id}</code>
              </li>
            ))}
            {p.removed?.map((id) => (
              <li key={`-${id}`}>
                <Badge tone="red">removed</Badge> <code>{id}</code>
              </li>
            ))}
            {p.changed?.map((c) => (
              <li key={`~${c.id}`}>
                <Badge tone="amber">changed</Badge> <code>{c.id}</code>
                <div className="ml-4">
                  <Changes list={c.fields} />
                </div>
              </li>
            ))}
            {p.reordered && (
              <li>
                <Badge>reordered</Badge>
              </li>
            )}
          </ul>
        </div>
      ))}
    </div>
  );
}
