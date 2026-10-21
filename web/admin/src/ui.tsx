import { type ButtonHTMLAttributes, Children, Component, createContext, type InputHTMLAttributes, lazy, type ReactNode, Suspense, useContext, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { type Issue, Problem } from './api';
import { Link } from './router';

// Edges are 1px shadows, not borders, so a button and a field in a row
// line up exactly. danger is subtle so a row of destructive actions stays quiet; the
// confirm dialog's final button is the solid one.
export function Button({
  variant = 'default',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'default' | 'primary' | 'danger' | 'danger-solid' }) {
  const colors = {
    default: 'bg-panel text-heading shadow-field enabled:hover:bg-soft',
    primary: 'bg-brand text-on-brand enabled:hover:bg-brand-hover',
    danger: 'bg-panel text-danger shadow-[0_0_0_1px_color-mix(in_srgb,var(--color-danger)_40%,transparent)] enabled:hover:bg-danger-wash',
    'danger-solid': 'bg-danger-solid text-white enabled:hover:bg-danger-solid-hover',
  }[variant];
  return (
    <button
      type="button"
      className={`rounded-control px-3.5 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${colors} ${className}`}
      {...props}
    />
  );
}

export function Check({ label, hint, ...props }: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & { label: string; hint?: string }) {
  const id = useId();
  const box = (
    <label className="inline-flex items-center gap-2 text-sm text-heading">
      <input type="checkbox" aria-describedby={hint ? id : undefined} {...props} />
      {label}
    </label>
  );
  if (!hint) return box;
  return (
    <div className="flex flex-col gap-0.5">
      {box}
      <span id={id} className="pl-6 text-sm text-body">
        {hint}
      </span>
    </div>
  );
}

// Input keeps its label short; hint carries the explanation, read out with
// the field.
// The hint sits outside the label so it describes the field without
// becoming part of its name.
export function Input({ label, hint, info, className = '', ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string; info?: ReactNode }) {
  const id = useId();
  return (
    <div className={`relative flex flex-col gap-1 text-sm ${className}`}>
      <LabelInfo label={label} info={info} />
      <label className="flex flex-col gap-1">
        <span className="font-medium text-heading">{label}</span>
        <input aria-describedby={hint && id} {...props} />
      </label>
      {hint && (
        <span id={id} className="text-body">
          {hint}
        </span>
      )}
    </div>
  );
}

// Page owns the screen's title: it names the browser tab and takes focus
// on arrival, so keyboard and screen reader users land on the new screen
// instead of on the body.
export function Page({ title, info, actions, children }: { title: string; info?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  const h1 = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    document.title = `${title} · Edge Policy Admin`;
  }, [title]);
  useEffect(() => h1.current?.focus({ preventScroll: true }), []);
  return (
    <section className="flex w-full max-w-6xl flex-col gap-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <h1 ref={h1} tabIndex={-1} className="min-w-0 wrap-anywhere focus:outline-none">
            {title}
          </h1>
          {info && <Info label={title}>{info}</Info>}
        </div>
        <div className="flex flex-wrap gap-2">{actions}</div>
      </header>
      {children}
    </section>
  );
}

export function Card({ title, intro, info, children }: { title?: string; intro?: ReactNode; info?: ReactNode; children: ReactNode }) {
  return (
    <div className="rounded-card bg-panel p-6 shadow-card">
      {title && <Title info={info} className="mb-3">{title}</Title>}
      {intro && <p className="mb-3 max-w-prose text-body">{intro}</p>}
      {children}
    </div>
  );
}

// Title is a section heading with an optional Info beside it, outside the
// heading so the heading's name stays its text.
export function Title({ info, className = '', children }: { info?: ReactNode; className?: string; children: string }) {
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <h2>{children}</h2>
      {info && <Info label={children}>{info}</Info>}
    </div>
  );
}

// Info explains a concept next to its name. It opens on hover and focus,
// stays open on click (for touch), and closes on Escape or a click
// elsewhere. The text is the button's description, so screen readers read
// it on focus without opening anything.
export function Info({ label, children }: { label: string; children: ReactNode }) {
  const id = useId();
  const [hover, setHover] = useState(false);
  const [pinned, setPinned] = useState(false);
  const box = useRef<HTMLSpanElement>(null);
  const tip = useRef<HTMLSpanElement>(null);
  const open = hover || pinned;
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => !box.current?.contains(e.target as Node) && (setPinned(false), setHover(false));
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && (setPinned(false), setHover(false));
    document.addEventListener('pointerdown', away);
    document.addEventListener('keydown', esc);
    return () => (document.removeEventListener('pointerdown', away), document.removeEventListener('keydown', esc));
  }, [open]);
  // Keep the tip inside the viewport: near the right edge it shifts left.
  useLayoutEffect(() => {
    const t = tip.current;
    if (!open || !t) return;
    t.style.translate = '';
    const over = t.getBoundingClientRect().right - (window.innerWidth - 12);
    if (over > 0) t.style.translate = `${-over}px`;
  }, [open]);
  return (
    <span ref={box} className="relative inline-flex align-middle" onPointerEnter={() => setHover(true)} onPointerLeave={() => setHover(false)}>
      {/* Not a <button>: a disabled fieldset, as on a read-only screen,
          would disable it too, and the explanation is still wanted there. */}
      <span
        role="button"
        tabIndex={0}
        aria-describedby={id}
        aria-expanded={open}
        onFocus={() => setHover(true)}
        onBlur={() => setHover(false)}
        onClick={() => setPinned(!pinned)}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setPinned(!pinned))}
        className="grid size-4 cursor-pointer place-items-center rounded-full text-muted shadow-field hover:bg-brand hover:text-on-brand aria-expanded:bg-brand aria-expanded:text-on-brand"
      >
        {/* The name is text, not aria-label, so it never reads as a field's label. */}
        {/* Drawn, not a glyph: a small "i" in most fonts reads as "1". */}
        <svg aria-hidden viewBox="0 0 16 16" className="size-3" fill="currentColor">
          <circle cx="8" cy="4.25" r="1.35" />
          <rect x="6.9" y="6.6" width="2.2" height="6.4" rx="1.1" />
        </svg>
        <span className="sr-only">About {label}</span>
      </span>
      <span
        ref={tip}
        id={id}
        role="tooltip"
        hidden={!open}
        className="absolute top-full left-0 z-30 mt-2 w-72 max-w-[calc(100vw-1.5rem)] rounded-card bg-tip px-3.5 py-3 text-left text-[0.8125rem] leading-relaxed font-normal tracking-normal text-on-tip normal-case shadow-float"
      >
        {children}
      </span>
    </span>
  );
}

// LabelInfo puts an Info right after a field's label without being inside
// the <label>, where its name would become part of the field's name. An
// invisible copy of the label text sets where it goes.
export function LabelInfo({ label, info }: { label: string; info?: ReactNode }) {
  if (!info) return null;
  return (
    <span className="pointer-events-none absolute top-0 left-0 z-10 flex h-5 items-center gap-1.5">
      <span aria-hidden className="invisible font-medium">
        {label}
      </span>
      <span className="pointer-events-auto">
        <Info label={label}>{info}</Info>
      </span>
    </span>
  );
}

// NotFound is a screen for an address or record that does not exist.
export function NotFound({ title = 'Page not found', back = ['/', 'Back to the dashboard'], children }: { title?: string; back?: [string, string]; children?: ReactNode }) {
  return (
    <Page title={title}>
      <p className="text-body">{children ?? 'Nothing lives at this address.'}</p>
      <p>
        <Link to={back[0]} className="font-medium text-heading underline">
          {back[1]}
        </Link>
      </p>
    </Page>
  );
}

// Hint explains a control, usually why it is disabled.
export function Hint({ children }: { children: ReactNode }) {
  return children ? <p className="text-sm text-body">{children}</p> : null;
}

// Pending stands in for data that has not arrived: the error if the
// request failed, otherwise a loading line.
export function Pending({ error }: { error: unknown }) {
  if (error) return <ErrorBox error={error} />;
  return (
    <p role="status" className="eyebrow text-body">
      Loading…
    </p>
  );
}

// Modal is a native modal dialog: the browser traps focus and makes the page
// behind it inert. The browser cannot restore focus to the opener once React
// has removed the dialog, so the opener is refocused here.
export function Modal({ title, onClose, children }: { title: string; onClose?: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current!;
    const opener = document.activeElement;
    d.showModal();
    // showModal focuses the first control; data-autofocus picks another.
    d.querySelector<HTMLElement>('[data-autofocus]')?.focus();
    return () => {
      d.close();
      // The opener can be gone (Discard leaves with the save bar); main is
      // the nearest place that keeps keyboard users on the screen.
      const back = opener instanceof HTMLElement && opener.isConnected ? opener : document.getElementById('main');
      back?.focus({ preventScroll: true });
    };
  }, []);
  return (
    <dialog
      ref={ref}
      aria-label={title}
      // Escape closes only dialogs that can be dismissed.
      onCancel={(e) => (e.preventDefault(), onClose?.())}
      className="m-auto w-[calc(100%-2rem)] max-w-md rounded-dialog bg-panel p-6 text-body shadow-float backdrop:bg-page/80"
    >
      <h2 className="mb-3">{title}</h2>
      {children}
    </dialog>
  );
}

// Confirm asks before an action that changes what production serves.
export function Confirm({
  title,
  action,
  variant = 'primary',
  onConfirm,
  onClose,
  children,
}: {
  title: string;
  action: string;
  variant?: 'primary' | 'danger';
  onConfirm: () => void;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <div className="flex flex-col gap-4">
        <div className="text-body">{children}</div>
        <div className="flex flex-wrap justify-end gap-2">
          {/* Cancel takes focus first, so Enter never confirms by accident. */}
          <Button data-autofocus onClick={onClose}>
            Cancel
          </Button>
          <Button variant={variant === 'danger' ? 'danger-solid' : 'primary'} onClick={() => (onClose(), onConfirm())}>
            {action}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// ConfirmButton is a button whose action runs only after Confirm.
export function ConfirmButton({
  title,
  action,
  variant = 'primary',
  onConfirm,
  confirm,
  children,
  ...props
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'title'> & {
  title: string;
  action: string;
  variant?: 'primary' | 'danger' | 'default';
  onConfirm: () => void;
  confirm: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant={variant} {...props} onClick={() => setOpen(true)}>
        {children}
      </Button>
      {open && (
        <Confirm title={title} action={action} variant={variant === 'danger' ? 'danger' : 'primary'} onConfirm={onConfirm} onClose={() => setOpen(false)}>
          {confirm}
        </Confirm>
      )}
    </>
  );
}

export function Badge({ children, tone = 'slate' }: { children: ReactNode; tone?: 'slate' | 'green' | 'amber' | 'red' }) {
  const colors = { slate: 'bg-soft text-heading', green: 'bg-success-wash text-success', amber: 'bg-warning-wash text-warning', red: 'bg-danger-wash text-danger' }[tone];
  return <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ${colors}`}>{children}</span>;
}

// Status surfaces are tinted washes with the tone's text, never colour alone:
// the words carry the meaning.
const wash = { green: 'bg-success-wash text-success', amber: 'bg-warning-wash text-warning', red: 'bg-danger-wash text-danger' };

// Notice reports what an action did or what to know before acting. Red is
// an alert, so a failed check reads as loudly as a form error.
// CanWrite says whether the signed-in role may change the draft. Policy
// screens read it so a viewer sees the policy without controls that the
// server would refuse.
export const CanWrite = createContext(true);

// Editable turns off every field and button inside it for a role that
// cannot change the draft.
export function Editable({ children }: { children: ReactNode }) {
  return (
    <fieldset disabled={!useContext(CanWrite)} className="contents">
      {children}
    </fieldset>
  );
}

// ReadOnlyNote says once per screen why nothing on it can be changed.
export function ReadOnlyNote() {
  return useContext(CanWrite) ? null : <Notice tone="amber">Your role can read the policy but not change it.</Notice>;
}

export function Notice({ children, tone = 'green' }: { children: ReactNode; tone?: 'green' | 'amber' | 'red' }) {
  return (
    <div role={tone === 'red' ? 'alert' : 'status'} className={`rounded-control p-3 text-sm ${wash[tone]}`}>
      {children}
    </div>
  );
}

// link, when given, maps an issue's path to the screen that fixes it.
// words names a config path for people when a screen has no better name:
// global.defaults.body_limit reads "global › defaults › body limit" and
// audiences[0] reads "audience 1".
export const words = (p: string) =>
  p
    .replace(/^config\./, '')
    .replace(/(\w+)\[(\d+)\]/g, (_, k: string, n: string) => `${/[^su]s$/.test(k) ? k.slice(0, -1) : k} ${Number(n) + 1}`)
    .replace(/\["([^"]+)"\]/g, ' $1')
    .replaceAll('_', ' ')
    .replaceAll('.', ' › ');

export function Issues({
  issues,
  tone = 'red',
  link,
  where,
  nested,
}: {
  issues: Issue[] | null | undefined;
  tone?: 'red' | 'amber';
  // nested drops the role and box when the list sits inside another alert.
  nested?: boolean;
  link?: ((path: string) => string | undefined) | undefined;
  // where names an issue's path in words; without it words does.
  where?: ((path: string) => string) | undefined;
}) {
  if (!issues?.length) return null;
  return (
    <ul role={nested ? undefined : tone === 'red' ? 'alert' : 'status'} className={nested ? '' : `rounded-control p-3 text-sm ${wash[tone]}`}>
      {issues.map((i, n) => (
        <li key={n}>
          {/* A message that already starts with its field, such as "password
              must be...", needs no label. */}
          {i.path && !i.message.toLowerCase().startsWith(words(i.path).toLowerCase()) && <span className="mr-1 font-medium">{(where ?? words)(i.path)}:</span>}
          {i.message}
          {i.path && link?.(i.path) && (
            <Link to={link(i.path)!} className="ml-1 font-medium underline">
              {link(i.path)!.startsWith('/rules/') ? 'Open the rule' : 'Open the page'}
            </Link>
          )}
        </li>
      ))}
    </ul>
  );
}

// ErrorBox shows an API problem with its field errors and failed tests.
export function ErrorBox({ error, link, where }: { error: unknown; link?: (path: string) => string | undefined; where?: (path: string) => string }) {
  if (!error) return null;
  const p = error instanceof Problem ? error : new Problem(0, error instanceof Error ? error.message : JSON.stringify(error));
  return (
    <div role="alert" className={`flex flex-col gap-2 rounded-control p-3 text-sm ${wash.red}`}>
      {/* Server messages start lowercase, to read inside logs. */}
      <p className="font-medium">{p.message.charAt(0).toUpperCase() + p.message.slice(1)}</p>
      {p.errors.length > 0 && <Issues issues={p.errors} link={link} where={where} nested />}
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

// Sort is a table's sort state: by is a column index; cols are the columns
// that can be sorted.
export interface Sort {
  by: number;
  desc: boolean;
  cols: number[];
  onSort: (col: number) => void;
}

// Table shows empty, when given, once the rows are known to be none. num
// lists the columns holding numbers, which align right like their cells.
// sort, when given, makes its columns' headers buttons that sort by them.
export function Table({ head, num = [], empty, sort, children }: { head: string[]; num?: number[]; empty?: ReactNode; sort?: Sort; children: ReactNode }) {
  const none = empty && Children.toArray(children).length === 0;
  // On phones each row stacks as a card and each cell shows its column name
  // from data-label, so pages keep writing plain cells.
  const ref = useRef<HTMLTableElement>(null);
  useLayoutEffect(() => {
    for (const tr of ref.current?.tBodies[0]?.rows ?? []) for (const td of tr.cells) if (td.colSpan === 1) td.dataset.label = head[td.cellIndex] ?? '';
  });
  return (
    <div className="overflow-x-auto rounded-card bg-panel shadow-card">
      <table ref={ref} className="data-table w-full text-left text-sm">
        <thead className="border-b border-line text-muted">
          <tr>
            {head.map((h, i) => {
              const sortable = sort?.cols.includes(i);
              const current = sort?.by === i;
              return (
                <th
                  key={h || i}
                  aria-sort={current ? (sort.desc ? 'descending' : 'ascending') : undefined}
                  className={`eyebrow px-3 py-2.5 align-bottom ${num.includes(i) ? 'text-right' : ''}`}
                >
                  {sortable ? (
                    <button type="button" onClick={() => sort!.onSort(i)} className={`eyebrow inline-flex items-center gap-1 hover:text-heading ${current ? 'text-heading' : ''}`}>
                      {h}
                      <span aria-hidden>{current ? (sort.desc ? '↓' : '↑') : '↕'}</span>
                    </button>
                  ) : (
                    h
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {children}
          {none && (
            <tr>
              <td colSpan={head.length} className="py-6 text-center whitespace-normal text-body">
                {empty}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// CodeMirror is loaded on first use, keeping about 400 kB out of the first
// page load; the placeholder holds the editor's place meanwhile.
const CodeMirror = lazy(() => import('./codemirror'));

// CodeEditor is CodeMirror 6, kept in sync with value when it changes from
// outside (for example after a reload).
export function CodeEditor(props: { value: string; onChange: (v: string) => void; label: string; language?: 'json' }) {
  return (
    <Suspense fallback={<div aria-busy className="h-32 rounded-control bg-panel shadow-field" />}>
      <CodeMirror {...props} />
    </Suspense>
  );
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
  // Unparsed text goes with the editor, so leaving the screen must not leave
  // the owner blocked on text nobody can see or fix any more.
  const validity = useRef(onValidity);
  useEffect(() => {
    validity.current = onValidity;
  });
  useEffect(() => () => validity.current?.(true), []);
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
        <p role="alert" className="text-sm text-danger">
          Not valid JSON: {bad}
        </p>
      )}
    </div>
  );
}

// Field is one documented key of a JSON block: its name and what it takes.
export type Field = [string, string];

// Reference documents a JSON block next to its editor: each key it accepts
// and a complete example. onUse, when given, replaces the block with the
// example, for starting from something that validates. open starts it
// expanded, for a block with nothing in it yet.
export function Reference({ fields, example, onUse, open }: { fields: Field[]; example: unknown; onUse?: (() => void) | undefined; open?: boolean }) {
  return (
    <details open={open} className="mt-3 rounded-control border border-line">
      <summary className="cursor-pointer px-3 py-2 text-sm font-medium text-heading">Fields and an example</summary>
      <div className="flex flex-col gap-3 border-t border-line p-3 text-sm">
        <dl className="grid gap-x-4 gap-y-2 sm:grid-cols-[max-content_1fr]">
          {fields.map(([name, about]) => (
            <div key={name} className="contents">
              {/* Long names such as max_auto_rollbacks_per_publish break on phones. */}
              <dt className="wrap-anywhere">
                <code>{name}</code>
              </dt>
              <dd className="text-body">{about}</dd>
            </div>
          ))}
        </dl>
        <pre>{JSON.stringify(example, null, 2)}</pre>
        {onUse && (
          <div>
            <Button onClick={onUse}>Replace with this example</Button>
          </div>
        )}
      </div>
    </details>
  );
}

// download saves data as a JSON file in the browser.
export function download(data: unknown, name: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

// who shows an audit actor ("user:alice", "token:…", "system:guard") as a
// person reads it: users by name, the rest as stored.
export const who = (actor: string) => (actor.startsWith('user:') ? actor.slice(5) : actor);

// statusName is a version's stored status in the words the UI uses: the
// active version is the live one.
export const statusName = (s: string) => ({ active: 'live', superseded: 'replaced', rolled_back: 'rolled back' })[s] ?? s;

export const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : '');

// ago is a time relative to now, for values whose freshness matters more
// than the exact time ("2 minutes ago"); pair it with when in a title.
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
export function ago(iso: string) {
  const s = (new Date(iso).getTime() - Date.now()) / 1000;
  for (const [unit, size] of [
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
  ] as const) {
    if (Math.abs(s) >= size) return relative.format(Math.round(s / size), unit);
  }
  return relative.format(Math.round(s), 'second');
}

// Rolling shows a figure whose digits roll to their new value, so a live
// count visibly climbs. Each digit is a 0 to 9 column (index.css .roll)
// moved by a tenth of its height per step. The columns are generated
// content, so copied text and screen readers get only the plain number.
export function Rolling({ text }: { text: string }) {
  const chars = [...text];
  return (
    // Tabular figures, so every digit column is one width.
    <span className="inline-flex tabular-nums">
      <span className="sr-only">{text}</span>
      <span aria-hidden className="inline-flex">
        {chars.map((c, i) => {
          // Keyed from the right, so units keep their column as the number grows.
          const key = chars.length - i;
          return /\d/.test(c) ? (
            <span key={key} className="inline-block h-[1lh] overflow-hidden">
              <span className="roll block transition-transform duration-700 ease-out motion-reduce:transition-none" style={{ transform: `translateY(${-10 * Number(c)}%)` }} />
            </span>
          ) : (
            <span key={key} data-c={c} className="whitespace-pre before:content-[attr(data-c)]" />
          );
        })}
      </span>
    </span>
  );
}

// Crash keeps a screen that throws while rendering from blanking the whole
// app: the nav stays, and the error says what broke. Keyed by path, so
// moving to another screen tries again.
export class Crash extends Component<{ children: ReactNode }, { error: unknown }> {
  state = { error: null as unknown };
  static getDerivedStateFromError(error: unknown) {
    return { error };
  }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex flex-col items-start gap-3">
        <h1>This screen failed to show</h1>
        <ErrorBox error={this.state.error} />
        <Button onClick={() => window.location.reload()}>Reload the page</Button>
      </div>
    );
  }
}
