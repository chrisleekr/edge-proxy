import * as DndKit from '@dnd-kit/core';
import { QueryBuilderDnD } from '@react-querybuilder/dnd';
import { createDndKitAdapter } from '@react-querybuilder/dnd/dnd-kit';
import { useQuery } from '@tanstack/react-query';
import { type ReactNode, useEffect, useId, useMemo, useState } from 'react';
import {
  type FieldSelectorProps,
  QueryBuilder,
  type RuleGroupType,
  toOptions,
  type ValueEditorProps,
  type ValueSelectorProps,
  useSelectElementChangeHandler,
  useValueSelector,
} from 'react-querybuilder';
import 'react-querybuilder/dist/query-builder.css';
import { ipListsQuery } from './pages/IPLists';
import { Link } from './router';
import { api, type Json, type Phase, type Rendered, type Schema, useCan } from './api';

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
  'tls.client.ja4': 't13d1516h2_8daaf6152771_02713d6af862',
  'tls.client.ja3': '773906b0efdefa24a7f2b8eb6985bf37',
  'client.signals': 'ua_tool',
  'client.ip_lists': 'aws',
};

// Select is the library's select with its title as its name too: a title
// alone is not a label every screen reader announces.
function Select(props: ValueSelectorProps) {
  const { onChange, val } = useValueSelector(props);
  const change = useSelectElementChangeHandler({ multiple: !!props.multiple, onChange });
  return (
    <select data-testid={props.testID} aria-label={props.title} title={props.title} className={props.className} value={val} disabled={props.disabled} multiple={!!props.multiple} onChange={change}>
      {toOptions(props.options)}
    </select>
  );
}

// FieldSelector adds the key input (header, cookie, query arg or claim name)
// for keyed fields.
function FieldSelector(props: FieldSelectorProps) {
  const { schema } = props.context as Ctx;
  const keyed = schema.fields.find((f) => f.name === props.value)?.keyed;
  const listId = useId();
  // Suggestions only: any header name can still be typed.
  const suggest = props.value === 'http.request.headers' && schema.cdn_headers.length > 0;
  return (
    <>
      <Select {...props} />
      {keyed && (
        <input
          aria-label="Key"
          placeholder={keyExample[props.value ?? ''] ?? 'name'}
          list={suggest ? listId : undefined}
          value={(props.rule as { key?: string }).key ?? ''}
          // RuleType has no key property; the API's AST does.
          onChange={(e) => props.schema.dispatchQuery(setKey(props.schema.getQuery() as RuleGroupType, props.path, e.target.value))}
        />
      )}
      {suggest && <datalist id={listId}>{schema.cdn_headers.map((h) => <option key={h} value={h} />)}</datalist>}
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
  const canReadLists = useCan()('stats.read');
  const mode = useId();
  const [find, setFind] = useState('');
  // Only the IP list field reads the lists; a role that cannot read them types the names.
  const lists = useQuery({ ...ipListsQuery, enabled: props.field === 'client.ip_lists' && canReadLists });
  const op = schema.operators.find((o) => o.name === props.operator);
  if (!op || op.no_value) return null;
  let text: string | undefined;
  let picker: ReactNode;
  if (props.field === 'client.signals') {
    text = `Signal names: ${schema.rules.signals.map((s) => s.name).join(', ')}.`;
  } else if (props.field === 'client.ip_lists' && canReadLists && lists.data) {
    text = 'A list that is off matches no one until you turn it on in IP lists.';
    // Picking from the lists avoids mistyped names; a role that cannot read them types.
    const picked = op.list ? (Array.isArray(props.value) ? (props.value as string[]) : []) : typeof props.value === 'string' && props.value ? [props.value] : [];
    const known = new Set(lists.data.map((l) => l.name));
    const options = [
      ...lists.data.map((l) => ({ name: l.name, state: !l.enabled ? 'off' : l.entries > 0 ? 'on' : 'on, not downloaded yet' })),
      ...[...new Set(picked)].filter((n) => !known.has(n)).map((n) => ({ name: n, state: 'no such list' })),
    ].filter((o) => o.name.toLowerCase().includes(find.toLowerCase()));
    picker = (
      <div className="flex min-w-0 basis-full flex-col gap-2">
        <input type="search" aria-label="Find a list" placeholder="Find a list" value={find} onChange={(e) => setFind(e.target.value)} />
        <div className="flex max-h-48 flex-col gap-1 overflow-y-auto rounded border border-line p-2">
          {lists.data.length === 0 && picked.length === 0 && (
            <span className="text-sm text-body">
              There are no IP lists yet. Add one in{' '}
              <Link to="/ip-lists" className="font-medium text-heading underline">
                IP lists
              </Link>
              .
            </span>
          )}
          {lists.data.length + picked.length > 0 && options.length === 0 && <span className="text-sm text-body">No list matches.</span>}
          {options.map((o) => (
            <label key={o.name} className="inline-flex min-w-0 items-center gap-2 break-all text-sm text-heading">
              <input
                type={op.list ? 'checkbox' : 'radio'}
                name={`${mode}-pick`}
                checked={picked.includes(o.name)}
                onChange={(e) => props.handleOnChange(op.list ? (e.target.checked ? [...picked, o.name] : picked.filter((n) => n !== o.name)) : o.name)}
              />
              {o.name} ({o.state})
            </label>
          ))}
        </div>
      </div>
    );
  }
  const hint = text && <span className="order-last basis-full text-sm text-body">{text}</span>;
  if (op.list) {
    const items = Array.isArray(props.value) ? (props.value as string[]) : [];
    return (
      <>
      {picker ?? <textarea
        aria-label="Values"
        rows={Math.max(2, items.length)}
        // An IP list also takes ranges; a single IP value does not.
        placeholder={`One per line, such as\n${props.field === 'ip.src' ? '203.0.113.0/24\n198.51.100.7' : (valueExample[props.field] ?? 'value')}`}
        value={items.join('\n')}
        onChange={(e) => props.handleOnChange(e.target.value === '' ? [] : e.target.value.split('\n'))}
      />}
      {hint}
      </>
    );
  }
  const wildcard = props.operator.includes('wildcard') && (props.field === 'http.host' ? '*.example.com' : props.field.startsWith('http.request.uri') ? '/v1/*/orders' : undefined);
  const example = wildcard || valueExample[props.field];
  const input = <input aria-label="Value" placeholder={example && `such as ${example}`} value={typeof props.value === 'string' ? props.value : ''} onChange={(e) => props.handleOnChange(e.target.value)} />;
  const how = wildcardHow[props.operator];
  return (
    <>
      {picker ?? input}
      {hint}
      {!hint && how && <span className="order-last basis-full text-sm text-body">{how}</span>}
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
  const used = useMemo(() => {
    const names = new Set<string>();
    const walk = (g: RuleGroupType) => g.rules.forEach((r) => ('rules' in r ? walk(r) : names.add((r as { field: string }).field)));
    walk(query);
    return names;
  }, [query]);
  const fields = useMemo(
    () => schema.fields.filter((f) => f.available && f.phases.includes(phase) && (!f.deprecated || used.has(f.name))).map((f) => ({ name: f.name, label: f.label })),
    [schema, phase, used],
  );
  const byName = useMemo(() => new Map(schema.fields.map((f) => [f.name, f])), [schema]);
  // An exact field offers only the operators that compare whole values; the server rejects the rest.
  const offers = (field: string) => {
    const f = byName.get(field);
    return schema.operators.filter((o) => o.types.includes(f?.type ?? '') && (!f?.exact || ['eq', 'in'].includes(o.negates ?? o.name)));
  };
  const context: Ctx = { schema };
  return (
    <QueryBuilderDnD dnd={dnd}>
      <QueryBuilder
        fields={fields}
        getOperators={(field) => offers(field).map((o) => ({ name: o.name, label: o.label }))}
        getDefaultValue={({ operator }) => (schema.operators.find((o) => o.name === operator)?.list ? [] : '')}
        combinators={[
          { name: 'and', label: 'And' },
          { name: 'or', label: 'Or' },
        ]}
        controlElements={{ fieldSelector: FieldSelector, valueEditor: ValueEditor, combinatorSelector: Select, operatorSelector: Select }}
        // Most rules match on the path, which every phase has, so a new
        // condition starts there.
        getDefaultField="http.request.uri.path"
        // "Rule" already names a whole policy rule here; rows are conditions.
        translations={{
          addRule: { label: '+ Condition', title: 'Add condition' },
          addGroup: { label: '+ Group', title: 'Add group' },
          removeRule: { label: 'Remove', title: 'Remove condition' },
          removeGroup: { label: 'Remove group', title: 'Remove group' },
          fields: { title: 'Field' },
          operators: { title: 'Operator' },
          combinators: { title: 'Match all or any' },
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
