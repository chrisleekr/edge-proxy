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
import { valueExample } from './values';
import { useDraft } from './draft';
import { Link } from './router';
import { Button } from './ui';
import { withList } from './pages/Sections';
import { api, type Checked, type Json, type Phase, type Rendered, type Schema, useCan } from './api';

const dnd = createDndKitAdapter(DndKit);

// toAST drops the bookkeeping react-querybuilder adds (id, path and
// valueSource), which the strict API decoder rejects. The tree is otherwise
// our stored AST unchanged.
const builderOnly = new Set(['id', 'path', 'valueSource']);
export const toAST = (q: RuleGroupType) => JSON.parse(JSON.stringify(q, (k, v: unknown) => (builderOnly.has(k) ? undefined : v))) as Json;

interface Ctx {
  schema: Schema;
}

// Example keys by field, shown as placeholders so an empty row says what
// to type.
const keyExample: Record<string, string> = {
  'http.request.headers': 'header, such as x-api-key',
  'http.request.cookies': 'cookie, such as session',
  'http.request.uri.args': 'argument, such as page',
  'http.request.jwt.claims': 'claim, such as sub',
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

const listOf = (v: unknown) => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as { list?: string }).list : undefined);

// SaveList names the typed values as a value list. The server checks the draft
// with the list in it, so a bad name is refused with its message and no name
// format is kept here.
function SaveList({ field, values, taken, onSave, onCancel }: { field: string; values: string[]; taken: Record<string, unknown>; onSave: (name: string) => void; onCancel: () => void }) {
  const d = useDraft();
  const [name, setName] = useState('');
  // A result counts only for the exact name, values and draft it checked.
  const stamp = JSON.stringify({ name, field, values });
  const [res, setRes] = useState<{ stamp: string; config: unknown; message: string }>();
  const exists = Object.hasOwn(taken, name);
  useEffect(() => {
    if (!name) return;
    let live = true;
    const t = setTimeout(() => {
      const path = `config.global.lists[${JSON.stringify(name)}]`;
      api<Checked>('POST', '/api/draft/check', { config: withList(d.config, undefined, name, { field, values }) })
        .then((r) => live && setRes({ stamp, config: d.config, message: r.errors.filter((i) => i.path === 'config.global.lists' || i.path === path || i.path.startsWith(`${path}.`) || i.path.startsWith(`${path}[`)).map((i) => i.message).join(' ') }))
        .catch((e: Error) => live && setRes({ stamp, config: d.config, message: e.message }));
    }, 300);
    return () => {
      live = false;
      clearTimeout(t);
    };
    // values is a new array every render; stamp stands for it.
    // oxlint-disable-next-line react/exhaustive-deps
  }, [stamp, d.config]);
  const cur = res?.stamp === stamp && res.config === d.config ? res : undefined;
  const message = exists ? `“${name}” already exists. Pick another name.` : (cur?.message ?? '');
  return (
    <span className="order-last flex basis-full flex-wrap items-center gap-2 text-sm">
      <input aria-label="List name" placeholder="such as bad-agents" value={name} onChange={(e) => setName(e.target.value)} />
      <Button
        disabled={!name || exists || !cur || !!cur.message}
        onClick={() => {
          d.setConfig((c) => withList(c, undefined, name, { field, values }));
          onSave(name);
        }}
      >
        Save
      </Button>
      <Button onClick={onCancel}>Cancel</Button>
      {message && <span className="text-danger">{message}</span>}
    </span>
  );
}

// ValueEditor takes no value, a list (one item per line), one value, or a
// value list of the config's global.lists for the field. IP list names are
// picked from admin's lists when the role can read them.
function ValueEditor(props: ValueEditorProps) {
  const { schema } = props.context as Ctx;
  const d = useDraft();
  const canReadLists = useCan()('stats.read');
  const mode = useId();
  const [wantList, setWantList] = useState(false);
  const [saving, setSaving] = useState(false);
  const [find, setFind] = useState('');
  // Only the IP list field reads the lists; a role that cannot read them types the names.
  const lists = useQuery({ ...ipListsQuery, enabled: props.field === 'client.ip_lists' && canReadLists });
  const op = schema.operators.find((o) => o.name === props.operator);
  if (!op || op.no_value) return null;
  const f = schema.fields.find((x) => x.name === props.field);
  const valueLists = (d.config.global.lists ?? {}) as Record<string, { field: string; values: string[] }>;
  const takesList = !!f?.list_ops?.includes(props.operator);
  const chosen = listOf(props.value);
  const useList = chosen !== undefined || (wantList && takesList);
  const kind = (f?.list_kind ?? 'values').toLowerCase();
  // The value the operator takes when nothing is typed or picked.
  const empty = op.list ? [] : '';
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
  const switcher = (takesList || chosen !== undefined) && (
    <fieldset className="order-last flex basis-full flex-wrap items-center gap-x-4 text-sm">
      <legend className="sr-only">Where the values come from</legend>
      <label className="inline-flex items-center gap-2">
        <input
          type="radio"
          name={mode}
          checked={!useList}
          onChange={() => {
            setWantList(false);
            if (chosen !== undefined) props.handleOnChange(empty);
          }}
        />
        Type values
      </label>
      <label className="inline-flex items-center gap-2">
        <input type="radio" name={mode} checked={useList} onChange={() => setWantList(true)} />
        Use a list
      </label>
    </fieldset>
  );
  if (useList) {
    const mine = Object.entries(valueLists).filter(([, g]) => g.field === props.field);
    const g = chosen ? valueLists[chosen] : undefined;
    const n = g?.values.length ?? 0;
    const words = op.label.toLowerCase();
    const matches = props.operator === 'in' ? `is one of the ${n}` : props.operator === 'not_in' ? `is none of the ${n}` : `${words} any of the ${n}`;
    return (
      <>
        {switcher}
        <select aria-label="Value list" value={chosen ?? ''} onChange={(e) => props.handleOnChange(e.target.value === '' ? empty : { list: e.target.value })}>
          <option value="">Pick a list</option>
          {chosen && !mine.some(([name]) => name === chosen) && <option value={chosen}>{chosen} (not a list of {kind})</option>}
          {mine.map(([name, x]) => (
            <option key={name} value={name}>
              {name} · {x.values.length} {kind}
            </option>
          ))}
        </select>
        {g && <span className="order-last basis-full text-sm text-body">Matches when the {f?.label.toLowerCase()} {matches} values.{!op.list && ` Counts as ${n} of this rule's 32 conditions.`}</span>}
        {mine.length === 0 && (
          <span className="order-last basis-full text-sm text-body">
            No lists of {kind} yet. Create one in{' '}
            <Link to={`/value-lists/_new?field=${encodeURIComponent(props.field)}`} className="font-medium text-heading underline">
              Value lists
            </Link>
            .
          </span>
        )}
      </>
    );
  }
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
      {switcher}
      {takesList && items.some((x) => x.trim()) && (saving ? (
        <SaveList
          field={props.field}
          values={items.filter((x) => x.trim())}
          taken={valueLists}
          onSave={(name) => {
            props.handleOnChange({ list: name });
            setSaving(false);
          }}
          onCancel={() => setSaving(false)}
        />
      ) : (
        <span className="order-last basis-full">
          <Button onClick={() => setSaving(true)}>Save as list</Button>
        </span>
      ))}
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
      {switcher}
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
