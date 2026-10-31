import { useQuery } from '@tanstack/react-query';
import { useId, useState } from 'react';
import { api, useCan } from './api';
import { useOptionalDraft } from './draft';
import { phases, rulesOf } from './phases';
import { navigate } from './router';
import { Modal } from './ui';
import { autopilotQuery } from './pages/Autopilot';
import { notesQuery } from './pages/Memory';
import { useVersions } from './pages/Publish';

// An address or AS number, typed whole, opens that client's page. Edges
// name an IPv6 client by its masked /64 in RFC 5952 form, as Stats shows
// it, so it must be typed that way: only its case is normalized here.
const client = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]+\/64|AS\d+)$/i;

// Palette finds a rule, autopilot rule, route, version, user, case or note by name and opens it, from
// Cmd or Ctrl+K on any screen. It offers only what the role may open.
// Enter opens the highlighted option, the first unless arrows moved it.
export function Palette({ onClose }: { onClose: () => void }) {
  const can = useCan();
  const id = useId();
  const [text, setText] = useState('');
  const [at, setAt] = useState(0);
  const draft = useOptionalDraft();
  const versions = useVersions();
  // The Routes page's default range, so the list is often already loaded.
  const routes = useQuery({
    queryKey: ['routes', 25],
    queryFn: () => api<{ routes: { id: number; method: string; host: string; template: string }[] }>('GET', '/api/observed-routes?hours=25'),
    enabled: can('stats.read'),
  });
  const autopilot = useQuery({ ...autopilotQuery, enabled: can('autopilot.read') });
  const cases = useQuery({
    queryKey: ['autopilot', 'cases', ''],
    queryFn: () => api<{ id: number }[]>('GET', '/api/autopilot/cases'),
    enabled: can('autopilot.read'),
  });
  const notes = useQuery({ ...notesQuery(), enabled: can('autopilot.read') });
  const users = useQuery({ queryKey: ['users'], queryFn: () => api<{ id: string; username: string }[]>('GET', '/api/users'), enabled: can('users.manage') });
  const typed = text.trim();
  const q = typed.toLowerCase();
  const all = [
    // Rules come first: a rule is what an ID most often names.
    ...(draft
      ? phases.flatMap((p) => rulesOf(draft.config, p.key).map((r) => ({ label: r.id, kind: p.title.toLowerCase().replace(/s$/, ''), to: `/rules/${p.phase}/${encodeURIComponent(r.id)}` })))
      : []),
    // A live autopilot rule opens the case that made it.
    ...(autopilot.data?.rules ?? []).map((r) => ({ label: r.id, kind: 'autopilot rule', to: `/autopilot/cases/${r.case_id}` })),
    ...(routes.data?.routes ?? []).map((r) => ({ label: `${r.method} ${r.host}${r.template}`, kind: 'route', to: `/routes/${r.id}` })),
    ...(versions.data ?? []).map((v) => ({ label: `Version ${v.version}${v.message ? `: ${v.message}` : ''}`, kind: 'version', to: `/versions/${v.version}` })),
    ...(users.data ?? []).map((u) => ({ label: u.username, kind: 'user', to: '/users' })),
    ...(cases.data ?? []).map((c) => ({ label: `Case ${c.id}`, kind: 'case', to: `/autopilot/cases/${c.id}` })),
    ...(notes.data ?? []).map((n) => ({
      label: `Note ${n.id}: ${n.statement.length > 80 ? `${n.statement.slice(0, 79)}…` : n.statement}`,
      kind: 'note',
      to: `/autopilot/notes/${n.id}`,
    })),
    // Edges write AS numbers in capitals and IPv6 in lowercase.
    ...(can('stats.read') && client.test(typed)
      ? [{ label: typed, kind: 'client', to: `/subjects/${encodeURIComponent(/^as/i.test(typed) ? typed.toUpperCase() : typed.toLowerCase())}` }]
      : []),
  ];
  const words = q.split(/\s+/).filter(Boolean);
  // The text as a whole word at the start: "version 2" in "Version 2: …", not "Version 29".
  const word = new RegExp(`^${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\W|$)`);
  // Every word must be in the name. The exact name goes first, then names
  // that start with the text as a whole word, then names that start with it.
  const rank = (label: string) => {
    const l = label.toLowerCase();
    return l === q ? 3 : word.test(l) ? 2 : l.startsWith(q) ? 1 : 0;
  };
  const found = q
    ? all
        .filter((o) => words.every((w) => o.label.toLowerCase().includes(w)))
        .sort((a, b) => rank(b.label) - rank(a.label))
        .slice(0, 20)
    : [];
  const cur = Math.min(at, found.length - 1);
  const open = (to: string) => (onClose(), navigate(to));
  return (
    <Modal title="Find" onClose={onClose}>
      <input
        role="combobox"
        aria-label="Find"
        aria-expanded={found.length > 0}
        aria-controls={id}
        aria-autocomplete="list"
        aria-activedescendant={found.length ? `${id}-${cur}` : undefined}
        placeholder="A rule ID, a route, a version, a user, a case, a note, an IP or an IPv6 /64"
        className="w-full"
        value={text}
        onChange={(e) => (setText(e.target.value), setAt(0))}
        onKeyDown={(e) => {
          const step = { ArrowDown: 1, ArrowUp: -1 }[e.key];
          if (step) {
            e.preventDefault();
            setAt(Math.max(0, Math.min(found.length - 1, cur + step)));
          } else if (e.key === 'Enter' && found[cur]) {
            e.preventDefault();
            open(found[cur].to);
          }
        }}
      />
      <ul role="listbox" id={id} aria-label="Matches" className="mt-3 flex max-h-80 flex-col overflow-y-auto empty:hidden">
        {found.map((o, i) => (
          <li
            key={o.kind + o.to + o.label}
            id={`${id}-${i}`}
            role="option"
            aria-selected={i === cur}
            className="flex cursor-pointer items-baseline justify-between gap-3 rounded-control px-2 py-1.5 text-sm aria-selected:bg-soft"
            // Keeps focus in the field, so typing and arrows go on working.
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => open(o.to)}
          >
            <span className="min-w-0 wrap-anywhere text-heading">{o.label}</span>
            <span className="shrink-0 text-muted">{o.kind}</span>
          </li>
        ))}
      </ul>
      {q && found.length === 0 && <p className="mt-3 text-sm text-body">Nothing matches “{typed}”.</p>}
    </Modal>
  );
}
