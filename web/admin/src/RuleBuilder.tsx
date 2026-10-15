import * as DndKit from '@dnd-kit/core';
import { QueryBuilderDnD } from '@react-querybuilder/dnd';
import { createDndKitAdapter } from '@react-querybuilder/dnd/dnd-kit';
import { useEffect, useMemo, useState } from 'react';
import {
  type FieldSelectorProps,
  QueryBuilder,
  type RuleGroupType,
  type ValueEditorProps,
  ValueSelector,
} from 'react-querybuilder';
import 'react-querybuilder/dist/query-builder.css';
import { api, type Json, type Phase, type Rendered, type Schema } from './api';

const dnd = createDndKitAdapter(DndKit);

// toAST drops the bookkeeping react-querybuilder adds (id, path and
// valueSource), which the strict API decoder rejects. The tree is otherwise
// our stored AST unchanged.
const builderOnly = new Set(['id', 'path', 'valueSource']);
export const toAST = (q: RuleGroupType) => JSON.parse(JSON.stringify(q, (k, v: unknown) => (builderOnly.has(k) ? undefined : v))) as Json;

interface Ctx {
  schema: Schema;
}

// FieldSelector adds the key input (header, cookie, query arg or claim name)
// for keyed fields.
function FieldSelector(props: FieldSelectorProps) {
  const { schema } = props.context as Ctx;
  const keyed = schema.fields.find((f) => f.name === props.value)?.keyed;
  return (
    <>
      <ValueSelector {...props} />
      {keyed && (
        <input
          aria-label="Key"
          placeholder="name"
          value={(props.rule as { key?: string }).key ?? ''}
          // RuleType has no key property; the API's AST does.
          onChange={(e) => props.schema.dispatchQuery(setKey(props.schema.getQuery() as RuleGroupType, props.path, e.target.value))}
        />
      )}
    </>
  );
}

function setKey(q: RuleGroupType, path: number[], key: string): RuleGroupType {
  const [i, ...rest] = path;
  const rules = q.rules.map((r, j) => {
    if (j !== i) return r;
    if (rest.length > 0) return setKey(r as RuleGroupType, rest, key);
    return { ...r, key };
  });
  return { ...q, rules };
}

// ValueEditor takes no value, a list (one item per line) or one value.
function ValueEditor(props: ValueEditorProps) {
  const { schema } = props.context as Ctx;
  const op = schema.operators.find((o) => o.name === props.operator);
  if (!op || op.no_value) return null;
  if (op.list) {
    const items = Array.isArray(props.value) ? (props.value as string[]) : [];
    return (
      <textarea
        aria-label="Values"
        rows={Math.max(2, items.length)}
        value={items.join('\n')}
        onChange={(e) => props.handleOnChange(e.target.value === '' ? [] : e.target.value.split('\n'))}
      />
    );
  }
  return <input aria-label="Value" value={typeof props.value === 'string' ? props.value : ''} onChange={(e) => props.handleOnChange(e.target.value)} />;
}

export function RuleBuilder({ schema, phase, query, onChange }: { schema: Schema; phase: Phase; query: RuleGroupType; onChange: (q: RuleGroupType) => void }) {
  const fields = useMemo(
    () => schema.fields.filter((f) => f.available && f.phases.includes(phase)).map((f) => ({ name: f.name, label: f.label })),
    [schema, phase],
  );
  const typeOf = useMemo(() => new Map(schema.fields.map((f) => [f.name, f.type])), [schema]);
  const context: Ctx = { schema };
  return (
    <QueryBuilderDnD dnd={dnd}>
      <QueryBuilder
        fields={fields}
        getOperators={(field) => schema.operators.filter((o) => o.types.includes(typeOf.get(field) ?? '')).map((o) => ({ name: o.name, label: o.label }))}
        getDefaultValue={({ operator }) => (schema.operators.find((o) => o.name === operator)?.list ? [] : '')}
        combinators={[
          { name: 'and', label: 'And' },
          { name: 'or', label: 'Or' },
        ]}
        controlElements={{ fieldSelector: FieldSelector, valueEditor: ValueEditor }}
        context={context}
        query={query}
        onQueryChange={onChange}
        showNotToggle
        resetOnFieldChange
        resetOnOperatorChange
      />
    </QueryBuilderDnD>
  );
}

// usePreview posts the AST to the server after edits settle. The browser
// never renders or validates expressions itself.
export function usePreview(query: RuleGroupType, phase: Phase) {
  const [preview, setPreview] = useState<Rendered | { failed: string }>();
  useEffect(() => {
    const ctl = { cancelled: false };
    const t = setTimeout(() => {
      api<Rendered>('POST', '/api/expr/render', { ast: toAST(query), phase })
        .then((r) => !ctl.cancelled && setPreview(r))
        .catch((e: Error) => !ctl.cancelled && setPreview({ failed: e.message }));
    }, 250);
    return () => {
      ctl.cancelled = true;
      clearTimeout(t);
    };
  }, [query, phase]);
  return preview;
}
