import { useCan } from '../api';
import { Link } from '../router';
import { Card, ErrorBox, Page, Table } from '../ui';
import { count, RangePicker, type Row, Spark, useRange } from './Fleet';

// Subject is one client the rate limits found over a limit, such as an IP,
// as the edges name it in their most limited clients.
export function Subject({ display }: { display: string }) {
  const r = useRange();
  const canRead = useCan()('config.read');
  // A key of several parts, such as an IP and a header, joins them with
  // spaces. Stats links the whole key, Find a single part.
  const mine = (t: { display: string }) => t.display === display || t.display.split(' ').includes(display);
  const rules = new Map<string, { rule: string; limited: number; would_limit: number }>();
  for (const row of r.rows)
    for (const t of row.top_limited ?? []) {
      if (!mine(t)) continue;
      const e = rules.get(t.rule) ?? { rule: t.rule, limited: 0, would_limit: 0 };
      e.limited += t.limited;
      e.would_limit += t.would_limit ?? 0;
      rules.set(t.rule, e);
    }
  const total = (row: Row) => (row.top_limited ?? []).filter(mine).reduce((n, t) => n + t.limited + (t.would_limit ?? 0), 0);
  return (
    <Page
      title={display}
      info="Each edge reports its 20 most limited clients across all rules each minute, counted from 1 in 16 limited requests, and admin keeps the 20 most limited of each rule in each bar, so these counts are estimates. A client limited only a little, or among many others, can be missing."
      actions={<RangePicker r={r} />}
    >
      <ErrorBox error={r.q.error} />
      <Card title="Rules that limited this client">
        {r.q.data && rules.size === 0 ? (
          <p className="text-body">No rule is known to have limited {display} {r.phrase}. The counts are a sampled estimate, so a client limited rarely may not show.</p>
        ) : (
          <div className="flex flex-col gap-3">
            <p className="flex items-center gap-2 text-sm text-body">
              <Spark rows={r.rows} from={r.from} to={r.to} value={total} />
              Requests over a limit {r.phrase}, a sampled estimate.
            </p>
            <Table head={['Rule', 'Blocked (estimate)', 'Over limit, log only (estimate)']} num={[1, 2]}>
              {[...rules.values()]
                .sort((a, b) => b.limited + b.would_limit - a.limited - a.would_limit)
                .map((x) => (
                  <tr key={x.rule}>
                    <td className="font-mono">
                      {canRead ? (
                        <Link to={`/rules/rate_limit/${encodeURIComponent(x.rule)}`} className="text-heading underline">
                          {x.rule}
                        </Link>
                      ) : (
                        x.rule
                      )}
                    </td>
                    <td className="text-right tabular-nums">{count(x.limited)}</td>
                    <td className="text-right tabular-nums">{count(x.would_limit)}</td>
                  </tr>
                ))}
            </Table>
          </div>
        )}
      </Card>
    </Page>
  );
}
