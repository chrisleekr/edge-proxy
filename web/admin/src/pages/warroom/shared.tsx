import type { CSSProperties, ReactNode } from 'react';

// Colours mean the same everywhere on the war room: red needs a person;
// amber is the edge handling traffic, or a warning. Never the only cue: each
// figure also says what it is in words.
export const color = {
  red: '#ff6166',
  amber: '#f5b544',
  green: '#4fd97a',
  blue: '#4c9dff',
  heading: '#ededed',
  body: '#a1a1a1',
  muted: '#8f8f8f',
  // Outcome series.
  passed: '#6b6b6b',
  edge5xx: '#ffb3b5',
  e403: '#d9822b',
  e401: '#c9a7ff',
  other: '#5c7a99',
} as const;

// View is the time the board shows. Live: the last full 5 minutes as rates
// a minute, beside the hour before them. Period: totals of from to to, a
// picked range or a span dragged on the chart.
export interface View {
  live: boolean;
  from: number;
  to: number;
  // Finishes "Requests a minute by outcome, …": "last hour" or "12:05 to 12:40".
  inView: string;
}

export const fmt = (n: number) => Math.round(n).toLocaleString();

// short fits a large figure in a tile or chip: 47.8k, 1.2M.
export function short(n: number) {
  if (n >= 1e9) return `${(n / 1e9).toFixed(2).replace(/\.?0+$/, '')}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1).replace(/\.0$/, '')}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10_000 ? 0 : 1).replace(/\.0$/, '')}k`;
  return String(Math.round(n));
}

// between names the window a response covers, in UTC like the clock. It adds
// the date when the window spans over a day or starts before today.
export function between(fromIso: string, toIso: string) {
  const a = new Date(fromIso);
  const b = new Date(toIso);
  const dated = b.getTime() - a.getTime() > 86_400_000 || a.toISOString().slice(0, 10) < new Date().toISOString().slice(0, 10);
  const at = (d: Date) => {
    const day = dated ? `${d.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' })} ${d.getUTCDate()} ` : '';
    return `${day}${d.toISOString().slice(11, 16)}`;
  };
  return `${at(a)} to ${at(b)} UTC`;
}

export const share = (n: number, d: number, digits = 1) => (d > 0 ? `${((100 * n) / d).toFixed(digits)}%` : '—');

// Widget is one card. Expand lays it over the board until closed, by its
// button, the backdrop or Escape, which the page handles; the wall view
// never expands.
export function Widget({
  label,
  name,
  expanded,
  onExpand,
  wall,
  style,
  children,
}: {
  label: string;
  name: string;
  expanded: string | null;
  onExpand: (name: string | null) => void;
  wall: boolean;
  style?: CSSProperties;
  children: ReactNode;
}) {
  const on = expanded === name;
  return (
    <section aria-label={label} className={`wr-card ${on ? 'wr-expanded' : ''}`} style={style}>
      {!wall && (
        <button type="button" className="wr-btn wr-xbtn" aria-label={on ? 'Close, or press Esc' : 'Expand to fill the screen'} title={on ? 'Close, or press Esc' : 'Expand to fill the screen'} aria-pressed={on} onClick={() => onExpand(on ? null : name)}>
          {on ? '✕' : '⤢'}
        </button>
      )}
      {children}
    </section>
  );
}

// Head is a widget's title row, kept clear of the expand button.
export function Head({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 pr-[34px]">
      <h2 className="wr-h2">{title}</h2>
      {children}
    </div>
  );
}
