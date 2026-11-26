import { useContext, useEffect, useState } from 'react';
import { api } from '../api';
import { useDraft } from '../draft';
import { navigate } from '../router';
import { Choice, Errors, Labeled } from '../RuleForms';
import { Button, CanWrite, CodeEditor, ConfirmButton, Editable, NotFound, Page, Pending, ReadOnlyNote } from '../ui';
import { type Body, type Template, bodiesOf, contentLabel, q, templateKind, templateUsers, useSchema, withBodies } from './Sections';

// usePreview asks admin to fill a body with sample values, as validation
// does, once typing pauses. A result counts only for the input it rendered.
function usePreview(status: number | undefined, b: Body) {
  const key = JSON.stringify([status, b.content_type, b.body]);
  const [res, setRes] = useState<{ key: string; body?: string; failed?: string }>();
  useEffect(() => {
    if (status === undefined || !b.content_type) return;
    let live = true;
    const t = setTimeout(() => {
      api<{ body: string }>('POST', '/api/templates/preview', { status, content_type: b.content_type, body: b.body })
        .then((r) => live && setRes({ key, body: r.body }))
        .catch((e: Error) => live && setRes({ key, failed: e.message }));
    }, 300);
    return () => {
      live = false;
      clearTimeout(t);
    };
    // key stands for status and b, which is a new object every render.
    // oxlint-disable-next-line react/exhaustive-deps
  }, [key]);
  return res?.key === key ? res : undefined;
}

// pretty indents JSON for reading; the edge sends it as written.
const pretty = (ct: string, s: string) => {
  if (!ct.includes('json')) return s;
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
};

// Preview shows HTML in a sandboxed frame: no scripts, no forms and an
// opaque origin, so a template's markup can't act in this admin session.
function Preview({ status, body }: { status: number | undefined; body: Body }) {
  const p = usePreview(status, body);
  if (status === undefined || !body.content_type) return <p className="text-sm text-body">Choose a status and content type to preview.</p>;
  if (!p) return <div aria-busy className="h-64 rounded-control bg-panel" />;
  if (p.failed !== undefined) return <p role="alert" className="text-sm text-danger">{p.failed}</p>;
  return body.content_type.startsWith('text/html') ? (
    <iframe sandbox="" title="Preview" srcDoc={p.body} className="h-64 w-full rounded-control border border-line bg-white" />
  ) : (
    <pre className="h-64 overflow-auto whitespace-pre-wrap rounded-control border border-line p-3 text-sm">{pretty(body.content_type, p.body ?? '')}</pre>
  );
}

// TemplateEditor edits one template in the draft: its status and one tab
// per body, each with a live preview.
export function TemplateEditor({ name }: { name: string }) {
  const d = useDraft();
  const canWrite = useContext(CanWrite);
  const schema = useSchema();
  const [tab, setTab] = useState(0);
  const all = (d.config.global.responses ?? {}) as Record<string, Template>;
  if (!Object.hasOwn(all, name))
    return (
      <NotFound title="Template not found" back={['/templates', 'Back to templates']}>
        The draft has no template called “{name}”. It may have been deleted.
      </NotFound>
    );
  if (!schema.data) return <Pending error={schema.error} />;
  const { response_kinds: kinds, content_types, response_bodies } = schema.data.rules;
  const t = all[name]!;
  const bodies = bodiesOf(t);
  const i = Math.min(tab, bodies.length - 1);
  const b = bodies[i]!;
  const p = `global.responses[${q(name)}]`;
  const pathOf = (n: number) => (n === 0 ? p : `${p}.variants[${n - 1}]`);
  const issuesOf = (n: number) => [...d.at(`${pathOf(n)}.content_type`), ...d.at(`${pathOf(n)}.body`)];
  const save = (next: Template) => d.setConfig((c) => ({ ...c, global: { ...c.global, responses: { ...(c.global.responses as Record<string, Template> | undefined), [name]: next } } }));
  const setBodies = (bs: Body[]) => save(withBodies(t, bs));
  const setBody = (patch: Partial<Body>) => setBodies(bodies.map((x, n) => (n === i ? { ...x, ...patch } : x)));
  const statuses = [...new Set(kinds.map((k) => k.status))].sort();
  const statusLabels = Object.fromEntries(statuses.map((s) => [String(s), `${s}, for ${kinds.filter((k) => k.status === s).map((k) => k.name.replaceAll('_', ' ')).join(' and ')}`]));
  const missing = content_types.filter((ct) => !bodies.some((x) => x.content_type === ct));
  const kind = templateKind(d.config, name, t.status, kinds);
  // A new body starts from the kind's default for its type. JSON has only a
  // problem+json default, which is also valid plain JSON.
  const add = (ct: string) => {
    const from = ct === 'application/json' ? 'application/problem+json' : ct;
    setBodies([...bodies, { content_type: ct, body: response_bodies[kind ?? '']?.find((x) => x.content_type === from)?.body ?? '' }]);
    setTab(bodies.length);
  };
  const users = templateUsers(d.config, name, kinds);
  const json = b.content_type.includes('json');
  return (
    <Page
      title={name}
      actions={
        <>
          {canWrite && (
            <ConfirmButton
              variant="danger"
              title={`Delete ${name}?`}
              action="Delete template"
              confirm="The template leaves the draft. Anything that uses it shows a problem until changed."
              onConfirm={() => {
                d.setConfig((c) => ({ ...c, global: { ...c.global, responses: Object.fromEntries(Object.entries(c.global.responses ?? {}).filter(([n]) => n !== name)) } }));
                navigate('/templates', { force: true });
              }}
            >
              Delete template
            </ConfirmButton>
          )}
          <Button onClick={() => navigate('/templates')}>Back to templates</Button>
        </>
      }
    >
      <ReadOnlyNote />
      <p className="text-sm text-body">{users.length ? `Used by ${users.join(', ')}.` : 'Not used yet: name it as a kind’s default on Templates, or in an access rule.'}</p>
      <Editable>
        <Errors issues={d.at(p).filter((x) => x.path === p)} />
        <Labeled label="Status" issues={d.at(`${p}.status`)}>
          <Choice value={typeof t.status === 'number' ? String(t.status) : undefined} options={statuses.map(String)} labels={statusLabels} onChange={(v) => save({ ...t, status: v === undefined ? undefined : Number(v) })} />
        </Labeled>
      </Editable>
      {/* Outside Editable: its fieldset disables every control for readers, and they still switch tabs and see previews. */}
      {/* A tablist may hold only tabs, so the add select sits beside it. */}
      <div className="flex flex-wrap items-center gap-2">
        <div role="tablist" aria-label="Bodies" className="flex flex-wrap gap-2">
          {bodies.map((x, n) => (
            <button key={n} role="tab" aria-selected={n === i} onClick={() => setTab(n)} className="rounded-control border border-line px-3 py-1 text-sm aria-selected:bg-soft aria-selected:font-medium">
              {contentLabel(x.content_type) ?? 'New body'}
              {n === 0 && ', default'}
              {issuesOf(n).length > 0 && <span className="text-danger"> (problem)</span>}
            </button>
          ))}
        </div>
        {canWrite && missing.length > 0 && (
          <select aria-label="Add content type" value="" onChange={(e) => e.target.value && add(e.target.value)}>
            <option value="">Add content type…</option>
            {missing.map((ct) => (
              <option key={ct} value={ct}>
                {contentLabel(ct)}
              </option>
            ))}
          </select>
        )}
      </div>
      <div role="tabpanel" className="grid gap-4 lg:grid-cols-2">
        <Editable>
          <div className="flex flex-col gap-2">
            <Labeled label="Content type" issues={d.at(`${pathOf(i)}.content_type`)}>
              <Choice value={b.content_type || undefined} options={[...(b.content_type ? [b.content_type] : []), ...missing]} labels={{}} onChange={(v) => setBody({ content_type: v ?? '' })} />
            </Labeled>
            <CodeEditor key={`${d.discards}-${i}-${b.content_type}`} label={`Body of ${name}, ${contentLabel(b.content_type) ?? 'new body'}`} value={b.body} onChange={(v) => setBody({ body: v })} {...(json ? { language: 'json' as const } : {})} />
            <Errors issues={d.at(`${pathOf(i)}.body`)} />
            <span className="text-sm text-body">
              <code>{'{{status}}'}</code>, <code>{'{{retry_after}}'}</code> and <code>{'{{request_id}}'}</code> are filled in per request.
              {i === 0 ? ' The default is sent when Accept prefers no other body, as for API calls and curl, so keep it JSON unless only browsers call these paths.' : ' Sent when the request’s Accept prefers this content type.'}
            </span>
            {canWrite && i > 0 && (
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => (setBodies([b, ...bodies.filter((_, n) => n !== i)]), setTab(0))}>Make default</Button>
                <Button variant="danger" onClick={() => (setBodies(bodies.filter((_, n) => n !== i)), setTab(0))}>
                  Remove {contentLabel(b.content_type) ?? 'body'}
                </Button>
              </div>
            )}
          </div>
        </Editable>
        <div className="flex flex-col gap-1">
          <span className="text-sm font-medium text-heading">Preview</span>
          <Preview status={t.status} body={b} />
        </div>
      </div>
    </Page>
  );
}
