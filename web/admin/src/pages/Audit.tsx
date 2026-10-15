import { useInfiniteQuery, useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api, type Diff } from '../api';
import { Badge, Button, ErrorBox, Input, Page, Table, when } from '../ui';
import { DiffView } from './DiffView';

interface Event {
  seq: number;
  occurred_at: string;
  actor: string;
  action: string;
  target: string;
  // Fields read here; the rest is shown as JSON.
  details: { changes?: Diff; broken_at?: number; verified_to?: number } | null;
}

export function Audit() {
  const [filter, setFilter] = useState({ actor: '', action: '', target: '' });
  const q = useInfiniteQuery({
    queryKey: ['audit', filter],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => {
      const p = new URLSearchParams(filter);
      if (pageParam) p.set('before', String(pageParam));
      return api<Event[]>('GET', `/api/audit?${p}`);
    },
    // The API returns 100 rows per page, newest first.
    getNextPageParam: (last) => (last.length === 100 ? last.at(-1)?.seq : undefined),
  });
  // The leader's daily full verification is audited; its latest result is
  // the integrity badge, without re-reading the whole chain here.
  const lastCheck = useQuery({ queryKey: ['audit', 'last-verify'], queryFn: () => api<Event[]>('GET', '/api/audit?action=audit.verify') });
  const badge = lastCheck.data?.[0];
  const verify = useMutation({ mutationFn: () => api<{ ok: boolean; verified_to: number; broken_at?: number; reason?: string }>('POST', '/api/audit/verify') });
  const exportAll = async () => {
    const rows = await api('POST', '/api/audit/export');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' }));
    a.download = 'audit-export.json';
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const v = verify.data;
  return (
    <Page
      title="Audit log"
      actions={
        <>
          <Button onClick={() => verify.mutate()} disabled={verify.isPending}>
            Verify chain
          </Button>
          <Button onClick={() => void exportAll()}>Export with HMACs</Button>
        </>
      }
    >
      {badge && (
        <p role="status" aria-label="Audit integrity">
          {badge.details?.broken_at ? (
            <Badge tone="red">broken at event {badge.details.broken_at}</Badge>
          ) : (
            <Badge tone="green">verified to event {badge.details?.verified_to}</Badge>
          )}{' '}
          <span className="text-sm text-slate-600">checked {when(badge.occurred_at)}</span>
        </p>
      )}
      {v && (
        <p role="status" className={v.ok ? 'text-green-900' : 'font-medium text-red-900'}>
          {v.ok ? `Chain verified through event ${v.verified_to}.` : `Chain broken at event ${v.broken_at}: ${v.reason}`}
        </p>
      )}
      <ErrorBox error={verify.error ?? q.error} />
      <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => e.preventDefault()}>
        {(['actor', 'action', 'target'] as const).map((k) => (
          <Input key={k} label={`Filter by ${k}`} value={filter[k]} onChange={(e) => setFilter({ ...filter, [k]: e.target.value })} />
        ))}
      </form>
      <Table head={['#', 'When', 'Actor', 'Action', 'Target', 'Details']}>
        {q.data?.pages.flat().map((e) => (
          <tr key={e.seq}>
            <td className="px-3 py-2">{e.seq}</td>
            <td className="px-3 py-2 whitespace-nowrap">{when(e.occurred_at)}</td>
            <td className="px-3 py-2">{e.actor}</td>
            <td className="px-3 py-2 font-mono">{e.action}</td>
            <td className="px-3 py-2">{e.target}</td>
            <td className="px-3 py-2 text-xs">
              {e.details?.changes ? (
                <details>
                  <summary>Before and after</summary>
                  <DiffView diff={e.details.changes} />
                </details>
              ) : (
                <span className="font-mono break-all">{e.details ? JSON.stringify(e.details) : ''}</span>
              )}
            </td>
          </tr>
        ))}
      </Table>
      {q.hasNextPage && (
        <Button onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
          Older events
        </Button>
      )}
    </Page>
  );
}
