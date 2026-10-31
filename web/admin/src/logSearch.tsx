import { useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { api, type Me } from './api';

// LogValues fill a LOG_SEARCH_URL template: a time window in epoch
// milliseconds, and a status code and host where the page has one.
export interface LogValues {
  from: number;
  to: number;
  status?: string | undefined;
  host?: string | undefined;
}

const placeholder = /\{(from|to|from_ms|to_ms|status|host)\}/g;

// logSearchURL fills the template with URL-encoded values. It is undefined
// when the template uses a placeholder this place has no value for, since
// a search without it would show other lines.
export function logSearchURL(template: string, v: LogValues): string | undefined {
  const values: Record<string, string | undefined> = {
    from: new Date(v.from).toISOString(),
    to: new Date(v.to).toISOString(),
    from_ms: String(v.from),
    to_ms: String(v.to),
    status: v.status,
    host: v.host,
  };
  let missing = false;
  const url = template.replace(placeholder, (_, name: string) => {
    const x = values[name];
    if (x === undefined) missing = true;
    return encodeURIComponent(x ?? '');
  });
  return missing ? undefined : url;
}

// useLogSearch builds links to the deployment's log store. Every link is
// undefined when LOG_SEARCH_URL is not set. The signed-in user is already
// fetched, so this reads the cached answer.
export function useLogSearch() {
  const me = useQuery({ queryKey: ['me'], queryFn: () => api<Me>('GET', '/api/auth/me'), retry: false });
  const template = me.data?.log_search_url;
  return (v: LogValues) => (template ? logSearchURL(template, v) : undefined);
}

// LogLink opens its lines in the log store, or is plain text without a link.
export const LogLink = ({ href, children }: { href: string | undefined; children: ReactNode }) =>
  href ? (
    <a href={href} target="_blank" rel="noreferrer" className="underline">
      {children}
    </a>
  ) : (
    <>{children}</>
  );
