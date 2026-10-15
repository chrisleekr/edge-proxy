import type { Diff, FieldChange, Json } from '../api';
import { Badge } from '../ui';

const show = (v: Json) => (v === undefined || v === null ? '—' : typeof v === 'string' ? v : JSON.stringify(v));

function Changes({ list }: { list: FieldChange[] }) {
  return (
    <ul className="flex flex-col gap-1">
      {list.map((f) => (
        <li key={f.path} className="text-sm">
          <code className="font-medium">{f.path}</code>: <del className="text-red-800">{show(f.before)}</del> → <ins className="text-green-800 no-underline">{show(f.after)}</ins>
        </li>
      ))}
    </ul>
  );
}

// DiffView renders the API's semantic diff: rules by ID and changed fields,
// with expressions as rendered text.
export function DiffView({ diff }: { diff: Diff }) {
  const phases = Object.entries(diff.phases ?? {});
  const empty = !diff.sections?.length && phases.every(([, p]) => !p.added?.length && !p.removed?.length && !p.changed?.length && !p.reordered);
  if (empty) return <p className="text-sm text-slate-600">No changes.</p>;
  return (
    <div className="flex flex-col gap-3" data-testid="diff">
      {diff.sections && diff.sections.length > 0 && <Changes list={diff.sections} />}
      {phases.map(([name, p]) => (
        <div key={name}>
          <h3 className="mb-1 text-sm font-semibold">{name.replaceAll('_', ' ')}</h3>
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
