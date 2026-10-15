import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, type Diff, etag, type Json, type Version, type VersionDetail as Detail } from '../api';
import { draftKey, useDraft } from '../draft';
import { Link, navigate } from '../router';
import { Badge, Button, Card, ErrorBox, Input, Page, Table, when } from '../ui';
import { DiffView } from './DiffView';
import { useVersions } from './Publish';

const statusTone = (s: string) => (s === 'active' ? 'green' : s === 'canary' ? 'amber' : s === 'rolled_back' ? 'red' : 'slate');

export function Versions({ can }: { can: (p: string) => boolean }) {
  const q = useVersions();
  return (
    <Page title="Versions">
      <ErrorBox error={q.error} />
      {q.data && can('config.rollback') && <RevertToPrevious versions={q.data} />}
      <Table head={['Version', 'Status', 'Published', 'Author', 'Message', 'Changes', 'Guard']}>
        {q.data?.map((v) => (
          <tr key={v.version}>
            <td className="px-3 py-2">
              <Link to={`/versions/${v.version}`} className="underline">
                {v.version}
              </Link>
            </td>
            <td className="px-3 py-2">
              <Badge tone={statusTone(v.status)}>{v.status.replace('_', ' ')}</Badge>
              {v.source !== 'manual' && <span className="ml-1 text-xs text-slate-500">{v.source.replace('_', ' ')}</span>}
            </td>
            <td className="px-3 py-2 whitespace-nowrap">{when(v.published_at)}</td>
            <td className="px-3 py-2">{v.author}</td>
            <td className="px-3 py-2">{v.message}</td>
            <td className="px-3 py-2">{v.change_summary}</td>
            <td className="px-3 py-2">{v.guard_outcome?.decision.replace('_', ' ')}</td>
          </tr>
        ))}
      </Table>
    </Page>
  );
}

// RevertToPrevious is the one-click emergency revert: the
// version that was active before the current one, after a confirm.
function RevertToPrevious({ versions }: { versions: Version[] }) {
  const qc = useQueryClient();
  const active = versions.find((v) => v.status === 'active');
  const previous = active && versions.find((v) => v.version < active.version && v.status === 'superseded');
  const [reason, setReason] = useState('');
  const revert = useMutation({
    mutationFn: () => api<{ version: number }>('POST', `/api/versions/${previous!.version}/revert`, { reason }),
    onSuccess: (r) => Promise.all([qc.invalidateQueries({ queryKey: ['versions'] }), qc.invalidateQueries({ queryKey: draftKey })]).then(() => navigate(`/versions/${r.version}`)),
  });
  if (!active) return null;
  return (
    <div className="flex flex-wrap items-end gap-2 rounded border border-green-300 bg-green-50 p-3">
      <p className="mr-auto text-sm">
        Version {active.version} is active{active.message && `: ${active.message}`}.
      </p>
      {previous && (
        <>
          <Input label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
          <Button
            variant="danger"
            disabled={!reason || revert.isPending}
            onClick={() => confirm(`Publish version ${previous.version}'s config to every edge now?`) && revert.mutate()}
          >
            Revert to previous (version {previous.version})
          </Button>
          <ErrorBox error={revert.error} />
        </>
      )}
    </div>
  );
}

export function VersionDetail({ version, can }: { version: number; can: (p: string) => boolean }) {
  const qc = useQueryClient();
  const d = useDraft();
  const q = useQuery({ queryKey: ['version', version], queryFn: () => api<Detail>('GET', `/api/versions/${version}`) });
  const [reason, setReason] = useState('');
  const [override, setOverride] = useState('');
  const [canary, setCanary] = useState('');
  const done = () => Promise.all([qc.invalidateQueries({ queryKey: ['versions'] }), qc.invalidateQueries({ queryKey: draftKey })]);
  const revert = useMutation({
    mutationFn: () => api<{ version: number }>('POST', `/api/versions/${version}/revert`, { reason, override_reason: override, canary_percent: canary ? Number(canary) : 0 }),
    onSuccess: (r) => done().then(() => navigate(`/versions/${r.version}`)),
  });
  const copy = useMutation({
    mutationFn: () => api('POST', `/api/versions/${version}/copy-to-draft`, undefined, { 'If-Match': etag(d.draft.revision) }),
    onSuccess: () => done().then(() => navigate('/')),
  });
  const v = q.data;
  if (!v) return <ErrorBox error={q.error} />;
  return (
    <Page
      title={`Version ${v.version}`}
      actions={
        <>
          {v.version > 1 && <Button onClick={() => navigate(`/versions/compare?a=${v.version - 1}&b=${v.version}`)}>Compare with {v.version - 1}</Button>}
          <Button disabled={!can('config.write') || d.dirty || copy.isPending} onClick={() => copy.mutate()}>
            Copy to draft
          </Button>
        </>
      }
    >
      <Card>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-slate-600">Status</dt>
          <dd>
            <Badge tone={statusTone(v.status)}>{v.status.replace('_', ' ')}</Badge>
          </dd>
          <dt className="text-slate-600">Published</dt>
          <dd>
            {when(v.published_at)} by {v.author}
          </dd>
          <dt className="text-slate-600">Message</dt>
          <dd>{v.message}</dd>
          <dt className="text-slate-600">Source</dt>
          <dd>
            {v.source.replace('_', ' ')}
            {v.based_on !== null && ` of version ${v.based_on}`}
          </dd>
          {v.override_reason && (
            <>
              <dt className="text-slate-600">Override</dt>
              <dd>{v.override_reason}</dd>
            </>
          )}
          {v.guard_override_reason && (
            <>
              <dt className="text-slate-600">Guard override</dt>
              <dd>{v.guard_override_reason}</dd>
            </>
          )}
          {v.guard_outcome && (
            <>
              <dt className="text-slate-600">Guard</dt>
              <dd>
                {v.guard_outcome.decision.replace('_', ' ')} at {when(v.guard_outcome.at)}
              </dd>
            </>
          )}
        </dl>
      </Card>
      {v.status !== 'active' && v.status !== 'canary' && (
        <Card title="Revert to this version">
          <p className="mb-2 text-sm text-slate-600">
            Publishes a new version with this config to every edge at once, since it already ran in production. History is never rewritten.
          </p>
          <div className="flex max-w-lg flex-col gap-2">
            <Input label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            <Input label="Override reason (only past a blocking check)" value={override} onChange={(e) => setOverride(e.target.value)} />
            {can('canary.manage') && (
              <Input label="Canary percent (empty to revert everywhere now)" inputMode="decimal" value={canary} onChange={(e) => setCanary(e.target.value)} />
            )}
            <ErrorBox error={revert.error} />
            <Button variant="danger" disabled={!can('config.rollback') || !reason || revert.isPending} onClick={() => revert.mutate()}>
              Revert to version {v.version}
            </Button>
          </div>
        </Card>
      )}
      <ErrorBox error={copy.error} />
      <Card title="Config">
        <pre className="max-h-[32rem] overflow-auto text-xs">{JSON.stringify(v.config, null, 2)}</pre>
      </Card>
    </Page>
  );
}

export function Compare() {
  const params = new URLSearchParams(window.location.search);
  const [a, setA] = useState(params.get('a') ?? '');
  const [b, setB] = useState(params.get('b') ?? 'draft');
  const [raw, setRaw] = useState(false);
  const semantic = useQuery({ queryKey: ['diff', a, b], queryFn: () => api<{ diff: Diff; summary: string }>('GET', `/api/diff/${a}/${b}`), enabled: !!a && !!b && !raw });
  const text = useQuery({ queryKey: ['raw', a, b], queryFn: () => api<{ a: string; b: string }>('GET', `/api/diff/${a}/${b}?view=raw`), enabled: !!a && !!b && raw });
  return (
    <Page title="Compare versions">
      <div className="flex flex-wrap items-end gap-2">
        <Input label="From (version or draft)" value={a} onChange={(e) => setA(e.target.value)} />
        <Input label="To (version or draft)" value={b} onChange={(e) => setB(e.target.value)} />
        <label className="text-sm">
          <input type="checkbox" className="mr-1" checked={raw} onChange={(e) => setRaw(e.target.checked)} />
          Raw JSON
        </label>
      </div>
      <ErrorBox error={semantic.error ?? text.error} />
      {!raw && semantic.data && (
        <Card title={semantic.data.summary}>
          <DiffView diff={semantic.data.diff} />
        </Card>
      )}
      {raw && text.data && (
        <div className="grid gap-2 md:grid-cols-2">
          {[text.data.a, text.data.b].map((t, i) => (
            <pre key={i} className="max-h-[40rem] overflow-auto rounded border border-slate-200 bg-white p-2 text-xs">
              {t}
            </pre>
          ))}
        </div>
      )}
    </Page>
  );
}

// RuleHistory lists the published versions where a rule changed.
export function RuleHistory({ id }: { id: string }) {
  const q = useQuery({ queryKey: ['history', id], queryFn: () => api<{ version: number; author: string; published_at: string; rule: Json }[]>('GET', `/api/rules/${encodeURIComponent(id)}/history`) });
  if (!q.data?.length) return <ErrorBox error={q.error} />;
  return (
    <Card title="Published history">
      <ul className="flex flex-col gap-2 text-sm">
        {q.data.map((e) => (
          <li key={e.version}>
            <Link to={`/versions/${e.version}`} className="underline">
              Version {e.version}
            </Link>{' '}
            {when(e.published_at)} by {e.author}: {e.rule ? 'changed' : 'removed'}
          </li>
        ))}
      </ul>
    </Card>
  );
}
