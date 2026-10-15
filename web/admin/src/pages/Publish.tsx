import { skipToken, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, type Diff, etag, type Json, type Version } from '../api';
import { draftKey, useDraft } from '../draft';
import { Button, Card, ErrorBox, Input, JsonEditor, Page, when } from '../ui';
import { DiffView } from './DiffView';

export function useVersions() {
  return useQuery({ queryKey: ['versions'], queryFn: () => api<Version[]>('GET', '/api/versions') });
}

export function Publish({ can }: { can: (p: string) => boolean }) {
  const qc = useQueryClient();
  const d = useDraft();
  const versions = useVersions();
  const active = versions.data?.find((v) => v.status === 'active');
  const diff = useQuery({
    queryKey: ['diff', active?.version, 'draft', d.draft.revision],
    queryFn: active && d.draft.revision > 0 ? () => api<{ diff: Diff; summary: string }>('GET', `/api/diff/${active.version}/draft`) : skipToken,
  });
  const behind = !!active && d.draft.base_version !== active.version;
  const [message, setMessage] = useState('');
  const [canary, setCanary] = useState('');
  const [override, setOverride] = useState('');
  const guard = useQuery({ queryKey: ['guard'], queryFn: () => api<Json>('GET', '/api/settings/guard') });
  const [guardOverride, setGuardOverride] = useState<Json>();
  const [guardOK, setGuardOK] = useState(true);
  const [guardReason, setGuardReason] = useState('');
  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: draftKey }), qc.invalidateQueries({ queryKey: ['versions'] }), qc.invalidateQueries({ queryKey: ['canary'] })]);
  const publish = useMutation({
    mutationFn: () =>
      api<{ version: number }>(
        'POST',
        '/api/publish',
        {
          message,
          canary_percent: canary ? Number(canary) : 0,
          override_reason: override,
          ...(guardOverride !== undefined && { guard_override: guardOverride, guard_override_reason: guardReason }),
        },
        { 'If-Match': etag(d.draft.revision) },
      ),
    onSuccess: () => (setMessage(''), setCanary(''), setOverride(''), setGuardOverride(undefined), setGuardReason(''), refresh()),
  });
  return (
    <Page title="Publish">
      <Canary can={can} onChange={() => void refresh()} />
      {behind && <Rebase onDone={() => void refresh()} canWrite={can('config.write')} />}
      <Card title={active ? `Draft compared with active version ${active.version}` : 'Draft'}>
        {d.draft.revision === 0 && <p className="text-sm text-slate-600">Nothing saved yet. Save the draft to publish it.</p>}
        {diff.data && <DiffView diff={diff.data.diff} />}
        <ErrorBox error={diff.error} />
      </Card>
      <Card title="Publish the saved draft">
        <form
          className="flex max-w-lg flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            publish.mutate();
          }}
        >
          <Input label="Message" value={message} onChange={(e) => setMessage(e.target.value)} required />
          {can('canary.manage') && (
            <Input label="Canary percent (empty for all traffic)" inputMode="decimal" value={canary} onChange={(e) => setCanary(e.target.value)} />
          )}
          <Input label="Override reason (only to publish past a blocking check)" value={override} onChange={(e) => setOverride(e.target.value)} />
          <label className="text-sm">
            <input
              type="checkbox"
              className="mr-1"
              checked={guardOverride !== undefined}
              disabled={!guard.data}
              onChange={(e) => setGuardOverride(e.target.checked ? guard.data : undefined)}
            />
            Change the rollback guard for this publish
          </label>
          {guardOverride !== undefined && (
            <>
              <JsonEditor label="Guard for this publish" value={guardOverride} onChange={setGuardOverride} onValidity={setGuardOK} />
              <Input label="Why this publish needs a different guard" value={guardReason} onChange={(e) => setGuardReason(e.target.value)} required />
            </>
          )}
          <ErrorBox error={publish.error} />
          {publish.data && <p role="status">Published version {publish.data.version}.</p>}
          <Button type="submit" variant="primary" disabled={!can('config.publish') || d.dirty || behind || d.draft.revision === 0 || !guardOK || publish.isPending}>
            Publish
          </Button>
          {d.dirty && <p className="text-xs text-slate-500">Save or discard your changes first.</p>}
        </form>
      </Card>
    </Page>
  );
}

// Rebase shows the three-way view when a revert or rollback replaced the
// version this draft started from.
function Rebase({ onDone, canWrite }: { onDone: () => void; canWrite: boolean }) {
  const d = useDraft();
  const view = useQuery({
    queryKey: ['rebase', d.draft.revision],
    queryFn: () => api<{ base_version: number; active_version: number; draft_changes: Diff; active_changes: Diff; conflicts: string[] }>('GET', '/api/draft/rebase'),
  });
  const apply = useMutation({ mutationFn: () => api('POST', '/api/draft/rebase', undefined, { 'If-Match': etag(d.draft.revision) }), onSuccess: onDone });
  const v = view.data;
  return (
    <Card title="Rebase needed">
      <p className="mb-3 text-sm">The active version changed since this draft started. Publishing is blocked until the draft is rebased onto it.</p>
      <ErrorBox error={view.error} />
      {v && (
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <h3 className="mb-1 text-sm font-semibold">This draft changed (from version {v.base_version})</h3>
            <DiffView diff={v.draft_changes} />
          </div>
          <div>
            <h3 className="mb-1 text-sm font-semibold">Active version {v.active_version} changed</h3>
            <DiffView diff={v.active_changes} />
          </div>
          {v.conflicts.length > 0 && (
            <div role="alert" className="text-sm text-red-900 md:col-span-2">
              Conflicts, where the draft's change wins: {v.conflicts.join(', ')}
            </div>
          )}
        </div>
      )}
      <ErrorBox error={apply.error} />
      <Button className="mt-3" variant="primary" disabled={!canWrite || d.dirty || !v || apply.isPending} onClick={() => apply.mutate()}>
        Rebase the draft onto version {v?.active_version}
      </Button>
    </Card>
  );
}

function Canary({ can, onChange }: { can: (p: string) => boolean; onChange: () => void }) {
  const q = useQuery({ queryKey: ['canary'], queryFn: () => api<{ canary: { version: number; percent: number; started_at: string; step_started_at: string } | null }>('GET', '/api/canary'), refetchInterval: 30_000 });
  const [percent, setPercent] = useState('');
  const [reason, setReason] = useState('');
  const act = useMutation({ mutationFn: ([path, body]: [string, Json?]) => api('POST', `/api/canary/${path}`, body), onSuccess: onChange });
  const c = q.data?.canary;
  if (!c) return <ErrorBox error={q.error} />;
  const manage = can('canary.manage');
  return (
    <Card title={`Canary: version ${c.version} on ${c.percent}% of traffic`}>
      <p className="mb-3 text-sm text-slate-600">
        Started {when(c.started_at)}; this step started {when(c.step_started_at)}. Each step needs the guard's minimum time and requests before the next.
      </p>
      <div className="flex flex-wrap items-end gap-2">
        <Input label="Next percent" inputMode="decimal" value={percent} onChange={(e) => setPercent(e.target.value)} />
        <Button disabled={!manage || !percent} onClick={() => act.mutate(['step', { percent: Number(percent) }])}>
          Step up
        </Button>
        <Button variant="primary" disabled={!manage} onClick={() => act.mutate(['promote'])}>
          Promote to all traffic
        </Button>
        <Input label="Abort reason" value={reason} onChange={(e) => setReason(e.target.value)} />
        <Button variant="danger" disabled={!manage || !reason} onClick={() => act.mutate(['abort', { reason }])}>
          Abort
        </Button>
      </div>
      <ErrorBox error={act.error} />
    </Card>
  );
}
