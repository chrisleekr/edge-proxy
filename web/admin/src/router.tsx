import { type MouseEvent, type ReactNode, useEffect, useSyncExternalStore } from 'react';

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

// navigate asks every guard first unless force is set, which screens use
// when they have just saved their own edits.
export function navigate(to: string, { force = false } = {}) {
  if (!force && !leaveOK()) return;
  window.history.pushState(null, '', to);
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
export function Link({ to, children, className, current }: { to: string; children: ReactNode; className?: string; current?: boolean }) {
  const onClick = (e: MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(to);
  };
  const exact = window.location.pathname === to;
  return (
    <a href={to} onClick={onClick} className={className} aria-current={exact ? 'page' : current ? 'true' : undefined}>
      {children}
    </a>
  );
}
