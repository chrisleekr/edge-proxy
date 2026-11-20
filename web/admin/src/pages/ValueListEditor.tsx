import { useContext, useEffect, useState } from 'react';
import { api, type Checked, type Config, type Issue } from '../api';
import { useDraft } from '../draft';
import { phases, ruleLink, rulesOf } from '../phases';
import { Link, navigate, useLeaveGuard } from '../router';
import { Errors, Labeled } from '../RuleForms';
import { valueExample } from '../values';
import { Button, CanWrite, ConfirmButton, Editable, Hint, Input, NotFound, Page, Pending, ReadOnlyNote } from '../ui';
import { type ValueListDef, listUsers, q, useSchema, withList } from './Sections';

// useListCheck asks the server to validate the draft with this value list in it
// under its proposed name, exactly as a save would. A result counts only for
// the input it checked, so Apply waits until what is on screen was checked.
function useListCheck(config: Config, old: string | undefined, name: string, def: ValueListDef, stamp: string) {
  const [res, setRes] = useState<{ stamp: string; config: Config; checked?: Checked; failed?: string }>();
  useEffect(() => {
    if (!name) return;
    let live = true;
    const t = setTimeout(() => {
      api<Checked>('POST', '/api/draft/check', { config: withList(config, old, name, def) })
        .then((checked) => live && setRes({ stamp, config, checked }))
        .catch((e: Error) => live && setRes({ stamp, config, failed: e.message }));
    }, 300);
    return () => {
      live = false;
      clearTimeout(t);
    };
    // stamp stands for name and def, which are new objects every render.
    // oxlint-disable-next-line react/exhaustive-deps
  }, [stamp, config, old, name]);
  return res?.stamp === stamp && res.config === config ? res : undefined;
}

// ListValues keeps the text as typed, so a new line stays while the values
// drop the blank lines at the end. A blank line in the middle is a value the
// check names by its line. It grows with its text, so it never scrolls inside.
function ListValues({ label, values, placeholder, onChange }: { label: string; values: string[]; placeholder: string; onChange: (v: string[]) => void }) {
  const [text, setText] = useState(values.join('\n'));
  return (
    <textarea
      aria-label={label}
      className="w-full max-w-2xl font-mono"
      rows={Math.max(4, text.split('\n').length + 1)}
      placeholder={placeholder}
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        const t = e.target.value.replace(/\n+$/, '');
        onChange(t === '' ? [] : t.split('\n'));
      }}
    />
  );
}

// ValueListEditor adds a value list (/value-lists/_new, optionally
// ?field=<field>) or edits one, including its name.
export function ValueListEditor({ list }: { list: string }) {
  const d = useDraft();
  const canWrite = useContext(CanWrite);
  const schema = useSchema();
  const all = (d.config.global.lists ?? {}) as Record<string, ValueListDef>;
  const existing = list && Object.hasOwn(all, list) ? all[list] : undefined;
  const old = list || undefined;
  const [name, setName] = useState(list);
  const [field, setField] = useState(existing?.field ?? new URLSearchParams(window.location.search).get('field') ?? '');
  const [values, setValues] = useState<string[]>(existing?.values ?? []);
  const snapshot = JSON.stringify({ name, field, values });
  const [initial] = useState(snapshot);
  const changed = snapshot !== initial;
  const def: ValueListDef = { field, values };
  const check = useListCheck(d.config, old, name, def, snapshot);
  const base = `config.global.lists[${q(name)}]`;
  const found = check?.checked?.errors ?? [];
  // own matches an issue on the list or inside it. The caps across all lists
  // are shown with it but are not this list's doing, so they are told apart.
  const own = (i: Issue) => i.path === base || i.path.startsWith(`${base}.`) || i.path.startsWith(`${base}[`);
  const cap = (i: Issue) => i.path === 'config.global.lists';
  // A new value list shows problems from its first edit, not before anything is typed.
  const errors = existing || changed ? found.filter((i) => own(i) || cap(i)) : [];
  const at = (f: string) => errors.filter((i) => i.path === f);
  // A cap the draft already breaks must not block an unrelated edit, so a cap
  // blocks only when its kind is new. Both messages carry counts that change
  // with the edit, so kinds are compared without digits.
  const kind = (i: Issue) => `${i.path} ${i.message.replace(/[\d,]+/g, '#')}`;
  const capsHad = new Set((d.check?.checked?.errors ?? []).filter(cap).map(kind));
  const blocking = errors.filter((i) => !cap(i) || !capsHad.has(kind(i)));
  // A change to the values or kind can break a rule that uses the list, which
  // the list's own path never shows. Errors the draft already has are not
  // this change's, so only new paths count. Paths, not messages: a message
  // names the list, which a rename changes.
  const had = new Set((d.check?.checked?.errors ?? []).map((i) => i.path));
  const breaks = found.filter((i) => !own(i) && !cap(i) && !had.has(i.path));
  const ruleOf = (path: string) => {
    const m = /^config\.(\w+_rules)\[(\d+)\]/.exec(path);
    const p = m && phases.find((x) => x.key === m[1]);
    return p && rulesOf(d.config, p.key)[Number(m[2])]?.id;
  };
  const lines = errors.filter((i) => /\.values\[\d+\]$/.test(i.path));
  useLeaveGuard(changed ? 'This value list has changes not applied to the draft. Leave and lose them?' : undefined);
  const back: [string, string] = ['/value-lists', 'Back to value lists'];
  if (list && !existing)
    return (
      <NotFound title="Value list not found" back={back}>
        The draft has no value list called “{list}”. It may have been deleted or renamed.
      </NotFound>
    );
  if (!schema.data) return <Pending error={schema.error} />;
  const kinds = schema.data.fields.filter((f) => f.list_kind).sort((a, b) => a.list_kind!.localeCompare(b.list_kind!));
  const users = old ? listUsers(d.config, old) : [];
  const renamed = !!old && name !== old;
  const holds = schema.data.fields.find((f) => f.name === field);
  const taken = name !== old && Object.hasOwn(all, name);
  const blocked = !name
    ? 'Give the value list a name to apply it.'
    : taken
      ? `A value list called ${name} already exists.`
      : !field
        ? 'Choose what the value list holds.'
        : !check
          ? 'Checking the value list…'
          : d.check?.failed
            ? `Could not check the draft: ${d.check.failed}. Apply is off until it can be checked.`
            : !d.check?.checked
              ? 'Checking the draft…'
          : check.failed
            ? `Could not check the value list: ${check.failed}. Apply is off until it can be checked.`
            : blocking.length > 0
              ? 'Fix the problems below to apply.'
              : breaks.length > 0
                ? 'Fix the rules this change breaks to apply.'
                : undefined;
  const apply = () => {
    d.setConfig((c) => withList(c, old, name, def));
    navigate('/value-lists', { force: true });
  };
  const remove = () => {
    d.setConfig((c) => ({ ...c, global: { ...c.global, lists: Object.fromEntries(Object.entries(c.global.lists ?? {}).filter(([n]) => n !== old)) } }));
    navigate('/value-lists', { force: true });
  };
  return (
    <Page
      title={existing ? (canWrite ? `Edit ${list}` : list) : 'New value list'}
      actions={
        <>
          {existing && canWrite && (
            <ConfirmButton
              variant="danger"
              title={`Delete ${list}?`}
              action="Delete value list"
              confirm="The value list leaves the draft. Rules that use it show a problem until changed. Nothing changes in production until the draft is saved and published."
              onConfirm={remove}
            >
              Delete value list
            </ConfirmButton>
          )}
          <Button onClick={() => navigate('/value-lists')}>{canWrite ? 'Cancel' : 'Back to value lists'}</Button>
          {canWrite && (
            <Button variant="primary" disabled={!!blocked} onClick={apply}>
              Apply to draft
            </Button>
          )}
        </>
      }
    >
      <ReadOnlyNote />
      {canWrite && <p className="text-sm text-body">Apply to draft keeps this change in your unsaved draft. Save draft, then Publish, puts it live.</p>}
      <Editable>
        <div className="flex flex-col gap-1">
          <Input label="Name" hint="Lowercase letters, digits, - and _, such as bad-agents." className="max-w-sm" value={name} onChange={(e) => setName(e.target.value)} />
          {renamed && users.length > 0 && <Hint>Renaming also updates the rules that use it: {users.join(', ')}.</Hint>}
          {/* An empty name is explained by the field's own hint, and shown problems by their own messages. A reader has no Apply, so no reason it is off. */}
          <Hint>{canWrite && name && blocking.length + breaks.length === 0 && blocked}</Hint>
          <Errors issues={at(base)} />
          <Errors issues={at('config.global.lists')} />
        </div>
        {users.length > 0 ? (
          <div className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-heading">Holds</span>
            <span className="text-body">{holds?.list_kind ?? field}</span>
            <span className="text-body">It cannot change while rules use the value list, since they read its values as that field.</span>
          </div>
        ) : (
          <Labeled label="Holds" issues={field ? at(`${base}.field`) : []}>
            <select className="max-w-md" value={field} onChange={(e) => setField(e.target.value)}>
              {!holds?.list_kind && <option value={field}>{field ? `${field} (can't hold a value list)` : 'Choose…'}</option>}
              {kinds.map((f) => (
                <option key={f.name} value={f.name}>
                  {f.list_kind}
                </option>
              ))}
            </select>
          </Labeled>
        )}
        <div className="flex flex-col gap-1">
          <label className="flex max-w-2xl flex-col gap-1 text-sm">
            <span className="flex flex-wrap justify-between gap-2">
              <span className="font-medium text-heading">Values, one per line</span>
              <span className="text-body">{values.length.toLocaleString()} of 10,000</span>
            </span>
            <ListValues label="Values" values={values} placeholder={field ? `such as ${valueExample[field] ?? 'value'}` : ''} onChange={setValues} />
          </label>
          <Errors issues={at(`${base}.values`)} />
          {lines.length > 0 && (
            <ul role="alert" className="text-sm text-danger">
              {lines.map((i, n) => (
                <li key={n}>
                  line {Number(/\[(\d+)\]$/.exec(i.path)?.[1]) + 1}: {i.message}
                </li>
              ))}
            </ul>
          )}
        </div>
        {canWrite && breaks.length > 0 && (
          <div className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-danger">This change breaks rules</span>
            <ul role="alert" className="text-danger">
              {breaks.map((i, n) => {
                const id = ruleOf(i.path);
                return (
                  <li key={n}>
                    {id ? (
                      <Link to={ruleLink(d.config, id) ?? '/rules'} className="font-medium underline">
                        {id}
                      </Link>
                    ) : (
                      i.path
                    )}
                    : {i.message}
                  </li>
                );
              })}
            </ul>
          </div>
        )}
        {users.length > 0 && (
          <p className="text-sm text-body">
            Used by{' '}
            {users.map((id, i) => (
              <span key={id}>
                {i > 0 && ', '}
                <Link to={ruleLink(d.config, id) ?? '/rules'} className="font-medium text-heading underline">
                  {id}
                </Link>
              </span>
            ))}
          </p>
        )}
      </Editable>
    </Page>
  );
}
