import { json } from '@codemirror/lang-json';
import { basicSetup, EditorView } from 'codemirror';
import { type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, useEffect, useRef, useState } from 'react';
import { type Issue, Problem } from './api';

export function Button({ variant = 'default', className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'default' | 'primary' | 'danger' }) {
  const colors = {
    default: 'border-slate-300 bg-white hover:bg-slate-50',
    primary: 'border-slate-900 bg-slate-900 text-white hover:bg-slate-700',
    danger: 'border-red-700 bg-red-700 text-white hover:bg-red-600',
  }[variant];
  return <button type="button" className={`rounded border px-3 py-1.5 text-sm disabled:opacity-50 ${colors} ${className}`} {...props} />;
}

export function Input({ label, className = '', ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  return (
    <label className={`flex flex-col gap-1 text-sm ${className}`}>
      <span className="font-medium text-slate-700">{label}</span>
      <input className="rounded border border-slate-300 px-2 py-1.5" {...props} />
    </label>
  );
}

export function Page({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">{title}</h1>
        <div className="flex flex-wrap gap-2">{actions}</div>
      </header>
      {children}
    </section>
  );
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <div className="rounded border border-slate-200 bg-white p-4">
      {title && <h2 className="mb-3 font-semibold">{title}</h2>}
      {children}
    </div>
  );
}

export function Badge({ children, tone = 'slate' }: { children: ReactNode; tone?: 'slate' | 'green' | 'amber' | 'red' }) {
  const colors = { slate: 'bg-slate-100 text-slate-800', green: 'bg-green-100 text-green-900', amber: 'bg-amber-100 text-amber-900', red: 'bg-red-100 text-red-900' }[tone];
  return <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${colors}`}>{children}</span>;
}

export function Issues({ issues, tone = 'red' }: { issues: Issue[] | null | undefined; tone?: 'red' | 'amber' }) {
  if (!issues?.length) return null;
  const colors = tone === 'red' ? 'border-red-300 bg-red-50 text-red-900' : 'border-amber-300 bg-amber-50 text-amber-900';
  return (
    <ul role={tone === 'red' ? 'alert' : 'status'} className={`rounded border p-3 text-sm ${colors}`}>
      {issues.map((i, n) => (
        <li key={n}>
          {i.path && <code className="mr-1">{i.path}:</code>}
          {i.message}
        </li>
      ))}
    </ul>
  );
}

// ErrorBox shows an API problem with its field errors and failed tests.
export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const p = error instanceof Problem ? error : new Problem(0, error instanceof Error ? error.message : JSON.stringify(error));
  return (
    <div role="alert" className="flex flex-col gap-2 rounded border border-red-300 bg-red-50 p-3 text-sm text-red-900">
      <p className="font-medium">{p.message}</p>
      {p.errors.length > 0 && <Issues issues={p.errors} />}
      {p.testResults
        .filter((t) => !t.pass)
        .map((t) => (
          <p key={t.name}>
            Test “{t.name}” failed: {t.failures?.join('; ')}
          </p>
        ))}
    </div>
  );
}

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded border border-slate-200 bg-white">
      <table className="w-full text-left text-sm">
        <thead className="bg-slate-50 text-slate-600">
          <tr>
            {head.map((h) => (
              <th key={h} className="px-3 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">{children}</tbody>
      </table>
    </div>
  );
}

// CodeEditor is CodeMirror 6, kept in sync with value when it changes from
// outside (for example after a reload).
export function CodeEditor({ value, onChange, label, language }: { value: string; onChange: (v: string) => void; label: string; language?: 'json' }) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView>(null);
  const changed = useRef(onChange);
  useEffect(() => {
    changed.current = onChange;
  });
  useEffect(() => {
    view.current = new EditorView({
      parent: host.current!,
      doc: value,
      extensions: [
        basicSetup,
        ...(language === 'json' ? [json()] : []),
        EditorView.lineWrapping,
        EditorView.contentAttributes.of({ 'aria-label': label }),
        EditorView.updateListener.of((u) => u.docChanged && changed.current(u.state.doc.toString())),
      ],
    });
    return () => view.current?.destroy();
    // The editor is created once; value changes are applied below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    const v = view.current;
    if (v && v.state.doc.toString() !== value) v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value } });
  }, [value]);
  return <div ref={host} className="overflow-hidden rounded border border-slate-300 bg-white text-sm" />;
}

// JsonEditor edits a value as JSON text and reports it only when it parses.
// onValidity lets the owner block saving while the text is not JSON, so
// the last valid value is never saved by mistake.
export function JsonEditor<T>({ value, onChange, label, onValidity }: { value: T; onChange: (v: T) => void; label: string; onValidity?: (ok: boolean) => void }) {
  const [text, setText] = useState(() => JSON.stringify(value, null, 2));
  const [bad, setBad] = useState<string>();
  // A value from outside (a reload, a discard) replaces the text; the
  // value this editor just reported does not, so typing keeps its format.
  // Compared as JSON because owners may build a new object every render.
  const serialized = JSON.stringify(value);
  const [seen, setSeen] = useState(serialized);
  if (serialized !== seen) {
    setSeen(serialized);
    setText(JSON.stringify(value, null, 2));
    setBad(undefined);
  }
  return (
    <div className="flex flex-col gap-1">
      <CodeEditor
        label={label}
        language="json"
        value={text}
        onChange={(t) => {
          setText(t);
          try {
            const v = JSON.parse(t) as T;
            setBad(undefined);
            onValidity?.(true);
            setSeen(JSON.stringify(v));
            onChange(v);
          } catch (e) {
            setBad((e as Error).message);
            onValidity?.(false);
          }
        }}
      />
      {bad && (
        <p role="alert" className="text-sm text-red-800">
          Not valid JSON: {bad}
        </p>
      )}
    </div>
  );
}

export const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : '');
