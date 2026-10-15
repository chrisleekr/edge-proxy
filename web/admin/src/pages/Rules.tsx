import { closestCenter, DndContext, type DragEndEvent, KeyboardSensor, PointerSensor, useSensor, useSensors } from '@dnd-kit/core';
import { arrayMove, SortableContext, sortableKeyboardCoordinates, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable';
import type { Rule } from '../api';
import { useDraft } from '../draft';
import { phases, rulesOf } from '../phases';
import { Link, navigate } from '../router';
import { Button, Card, Page } from '../ui';

// summary is a rule's action in a few words; the editor shows the rest.
function summary(r: Rule) {
  if (r.limit !== undefined) return `${r.action} over ${r.limit} per ${r.period} by ${(r.key ?? []).join(' + ')}`;
  if (r.ops) return `${r.ops.length} header operations`;
  return Object.keys(r.settings ?? {}).join(', ') || 'no settings';
}

function Row({ rule, to }: { rule: Rule; to: string }) {
  const { setNodeRef, attributes, listeners, transform, transition } = useSortable({ id: rule.id });
  const style = { transform: transform ? `translate3d(0, ${transform.y}px, 0)` : undefined, transition };
  return (
    <li ref={setNodeRef} style={style} className="flex items-center gap-3 border-b border-slate-100 bg-white py-2 last:border-0">
      <button type="button" aria-label={`Move ${rule.id}`} className="cursor-grab px-1 text-slate-400" {...attributes} {...listeners}>
        ⠿
      </button>
      <Link to={to} className="font-mono text-sm font-medium underline">
        {rule.id}
      </Link>
      <span className="text-sm text-slate-600">{summary(rule)}</span>
    </li>
  );
}

export function Rules() {
  const d = useDraft();
  const sensors = useSensors(useSensor(PointerSensor), useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }));
  return (
    <Page title="Rules">
      <p className="text-sm text-slate-600">
        Rules run top to bottom within each phase. Drag to reorder, or focus the handle and use Space and the arrow keys. Draft based on version {d.draft.base_version ?? 'none'}.
      </p>
      {phases.map(({ phase, key, title }) => {
        const rules = rulesOf(d.config, key);
        const move = (e: DragEndEvent) => {
          const from = rules.findIndex((r) => r.id === e.active.id);
          const to = rules.findIndex((r) => r.id === e.over?.id);
          if (from >= 0 && to >= 0 && from !== to) d.setConfig((c) => ({ ...c, [key]: arrayMove(rules, from, to) }));
        };
        return (
          <Card key={phase} title={title}>
            <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={move}>
              <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
                <ul aria-label={title}>
                  {rules.map((r) => (
                    <Row key={r.id} rule={r} to={`/rules/${phase}/${encodeURIComponent(r.id)}`} />
                  ))}
                </ul>
              </SortableContext>
            </DndContext>
            {rules.length === 0 && <p className="text-sm text-slate-500">No rules.</p>}
            <Button className="mt-3" onClick={() => navigate(`/rules/${phase}/`)}>
              Add rule
            </Button>
          </Card>
        );
      })}
    </Page>
  );
}
