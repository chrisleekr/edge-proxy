import { type MouseEvent, type ReactNode, useSyncExternalStore } from 'react';

// A path router over the History API: the admin needs only exact paths and
// one numeric parameter, which a routing library would not simplify.

const subscribe = (cb: () => void) => {
  window.addEventListener('popstate', cb);
  return () => window.removeEventListener('popstate', cb);
};

export function usePath() {
  return useSyncExternalStore(subscribe, () => window.location.pathname);
}

export function navigate(to: string) {
  window.history.pushState(null, '', to);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

export function Link({ to, children, className }: { to: string; children: ReactNode; className?: string }) {
  const onClick = (e: MouseEvent) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    e.preventDefault();
    navigate(to);
  };
  return (
    <a href={to} onClick={onClick} className={className} aria-current={window.location.pathname === to ? 'page' : undefined}>
      {children}
    </a>
  );
}
