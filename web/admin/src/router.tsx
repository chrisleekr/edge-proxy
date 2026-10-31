import { type AnchorHTMLAttributes, type MouseEvent, type ReactNode, useEffect, useSyncExternalStore } from 'react';

// A path router over the History API: the admin needs only exact paths and
// one numeric parameter, which a routing library would not simplify.

const here = () => window.location.pathname + window.location.search;

// Screens holding edits that leaving would lose register a message here.
const guards = new Set<{ message: string }>();
const leaveOK = () => [...guards].every((g) => confirm(g.message));

// Back and forward have already moved the URL when popstate fires, so a
// refusal puts the screen's URL back. Registered at load, this runs before
// the store below reads the URL.
let shown = here();
window.addEventListener('popstate', () => {
  if (here() === shown) return;
  if (leaveOK()) shown = here();
  else window.history.pushState(null, '', shown);
});

const subscribe = (cb: () => void) => {
  window.addEventListener('popstate', cb);
  return () => window.removeEventListener('popstate', cb);
};

export function usePath() {
  return useSyncExternalStore(subscribe, () => window.location.pathname);
}

// useSearch keeps a screen's choices, such as filters and the time range,
// in the address, so a view can be bookmarked and shared. set replaces the
// entry: changing a filter is not a step back should undo. An empty value
// removes its key.
export function useSearch() {
  const search = useSyncExternalStore(subscribe, () => window.location.search);
  const set = (changes: Record<string, string>) => {
    const p = new URLSearchParams(window.location.search);
    for (const [k, v] of Object.entries(changes)) {
      if (v) p.set(k, v);
      else p.delete(k);
    }
    window.history.replaceState(null, '', `${window.location.pathname}${p.size ? `?${p}` : ''}`);
    shown = here();
    window.dispatchEvent(new PopStateEvent('popstate'));
  };
  return [new URLSearchParams(search), set] as const;
}

// keep carries the picked time range on to a target that sets none, so it
// holds from screen to screen.
export function keep(to: string) {
  const range = new URLSearchParams(window.location.search).get('range');
  if (!range || /[?&]range=/.test(to)) return to;
  return `${to}${to.includes('?') ? '&' : '?'}range=${encodeURIComponent(range)}`;
}

// navigate asks every guard first unless force is set, which screens use
// when they have just saved their own edits.
export function navigate(to: string, { force = false } = {}) {
  if (!force && !leaveOK()) return;
  window.history.pushState(null, '', keep(to));
  shown = here();
  window.dispatchEvent(new PopStateEvent('popstate'));
  window.scrollTo(0, 0);
}

// useLeaveGuard asks before leaving the screen, in the app or the browser,
// while message is set.
export function useLeaveGuard(message: string | undefined) {
  useEffect(() => {
    if (!message) return;
    const g = { message };
    guards.add(g);
    return () => void guards.delete(g);
  }, [message]);
  useBeforeUnload(!!message);
}

// useBeforeUnload asks the browser to confirm a reload or close.
export function useBeforeUnload(when: boolean) {
  useEffect(() => {
    if (!when) return;
    const ask = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener('beforeunload', ask);
    return () => window.removeEventListener('beforeunload', ask);
  }, [when]);
}

// Link marks itself current on its own path; current overrides that for
// links that stand for a whole section.
// Extra props, such as a title or aria-label, go to the <a>.
export function Link({ to, children, current, ...props }: Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> & { to: string; children: ReactNode; current?: boolean }) {
  // Subscribed, so the href follows a range picked after render.
  useSyncExternalStore(subscribe, () => window.location.search);
  const onClick = (e: MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(to);
  };
  const exact = window.location.pathname === to.split('?')[0];
  return (
    <a {...props} href={keep(to)} onClick={onClick} aria-current={exact ? 'page' : current ? 'true' : undefined}>
      {children}
    </a>
  );
}
