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

// Example values by field, shown as placeholders so an empty row says what
// to type. Keys are the names keyed fields take.
const keyExample: Record<string, string> = {
  'http.request.headers': 'header, such as x-api-key',
  'http.request.cookies': 'cookie, such as session',
  'http.request.uri.args': 'argument, such as page',
  'http.request.jwt.claims': 'claim, such as sub',
};
const valueExample: Record<string, string> = {
  'http.request.full_uri': 'https://api.example.com/v1/orders?page=2',
  'http.request.uri': '/v1/orders?page=2',
  'http.request.uri.path': '/v1/orders',
  'http.request.uri.query': 'page=2',
  'http.host': 'api.example.com',
  'http.request.method': 'POST',
  'http.cookie': 'session=abc',
  'http.referer': 'https://www.example.com/',
  'http.user_agent': 'curl/8.7.1',
  'http.x_forwarded_for': '203.0.113.7',
  'ip.src': '203.0.113.7',
  'ip.src.country': 'AU',
  'ip.src.asnum': '13335',
  'edge.locale': 'en-AU',
};

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
          placeholder={keyExample[props.value ?? ''] ?? 'name'}
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
        // An IP list also takes ranges; a single IP value does not.
        placeholder={`One per line, such as\n${props.field === 'ip.src' ? '203.0.113.0/24\n198.51.100.7' : (valueExample[props.field] ?? 'value')}`}
        value={items.join('\n')}
        onChange={(e) => props.handleOnChange(e.target.value === '' ? [] : e.target.value.split('\n'))}
      />
    );
  }
  const wildcard = props.operator.includes('wildcard') && (props.field === 'http.host' ? '*.example.com' : props.field.startsWith('http.request.uri') ? '/v1/*/orders' : undefined);
  const example = wildcard || valueExample[props.field];
  const input = <input aria-label="Value" placeholder={example && `such as ${example}`} value={typeof props.value === 'string' ? props.value : ''} onChange={(e) => props.handleOnChange(e.target.value)} />;
  const how = wildcardHow[props.operator];
  if (!how) return input;
  return (
    <>
      {input}
      <span className="order-last basis-full text-sm text-body">{how}</span>
    </>
  );
}

// The two wildcard operators differ only in letter case, which their names
// don't say.
const wildcardHow: Record<string, string> = {
  wildcard: '* matches any characters, / included. The whole value must match. Letter case is ignored.',
  strict_wildcard: '* matches any characters, / included. The whole value must match, letter case too.',
};

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
        // Most rules match on the path, which every phase has, so a new
        // condition starts there.
        getDefaultField="http.request.uri.path"
        // "Rule" already names a whole policy rule here; rows are conditions.
        translations={{
          addRule: { label: '+ Condition', title: 'Add condition' },
          addGroup: { label: '+ Group', title: 'Add group' },
          removeRule: { label: 'Remove', title: 'Remove condition' },
          removeGroup: { label: 'Remove group', title: 'Remove group' },
        }}
        // The library's own classes: rows wrap on narrow screens, and tree
        // lines show which group a condition belongs to.
        controlClassnames={{ queryBuilder: 'queryBuilder-branches queryBuilder-responsive' }}
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

// usePreview posts the expression to the server after edits settle: the
// builder's AST, or text, which the server parses first. The browser never
// parses, renders or validates expressions itself.
export function usePreview(query: RuleGroupType, phase: Phase, text?: string) {
  const [preview, setPreview] = useState<Rendered | { failed: string }>();
  useEffect(() => {
    const ctl = { cancelled: false };
    const t = setTimeout(() => {
      const ast = text === undefined ? Promise.resolve(toAST(query)) : api<{ ast: Json }>('POST', '/api/expr/parse', { text }).then((r) => r.ast);
      ast
        .then((a) => api<Rendered>('POST', '/api/expr/render', { ast: a, phase }))
        .then((r) => !ctl.cancelled && setPreview(r))
        .catch((e: Error) => !ctl.cancelled && setPreview({ failed: e.message }));
    }, 250);
    return () => {
      ctl.cancelled = true;
      clearTimeout(t);
    };
  }, [query, phase, text]);
  return preview;
}
