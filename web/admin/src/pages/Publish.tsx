import { skipToken, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, useCan, type Diff, etag, type Json, type JsonObject, Problem, type GuardGate, type Version, type VersionDetail } from '../api';
import { draftKey, useDraft } from '../draft';
import { Button, Card, Check, Confirm, ConfirmButton, ErrorBox, Hint, Notice, Input, Page, ago, statusName } from '../ui';
import { GuardForm, guardWhere } from '../GuardForm';
import { outcomeSays } from '../guard';
import { DiffView, isEmpty } from './DiffView';

// canaryPercent reads a typed percent, "5" or "5%". Number() reads other
// text as NaN, which JSON sends as null and the server takes as 0: a publish
// to all traffic. So anything else is flagged before it is sent.
export function canaryPercent(text: string) {
  const pct = text.trim().replace(/%$/, '');
  return { pct, bad: pct !== '' && !(Number(pct) >= 0.01 && Number(pct) <= 99.99) };
}

// The server decides rollback only when a tripped signal is in rollback mode.
const canRollBack = (g: GuardGate) => g.enabled && g.max_auto_rollbacks_per_publish > 0 && Object.values(g.signals).some((x) => x.mode === 'rollback');

// guardAfter says what the guard does once a publish serves all traffic.
export const guardAfter = (g: GuardGate | undefined) =>
  !g
    ? ''
    : canRollBack(g)
      ? ' The guard watches it and rolls back if a rollback check trips.'
      : g.enabled
        ? ' The guard watches it but only alerts and never rolls back, so roll back yourself if needed.'
        : ' The guard is off, so nothing rolls it back automatically.';

// useVersions lists published versions for roles that can read config;
// for others it stays empty instead of asking and being refused.
export function useVersions() {
  return useQuery({ queryKey: ['versions'], queryFn: () => api<Version[]>('GET', '/api/versions'), enabled: useCan()('config.read') });
}

// useDraftDiff compares the saved draft with what traffic gets: the canary
// while one runs, since a canary publish bases the draft on it, otherwise
// the active version.
export function useDraftDiff() {
  const d = useDraft();
  const versions = useVersions();
  const against = versions.data?.find((v) => v.status === 'canary') ?? versions.data?.find((v) => v.status === 'active');
  const diff = useQuery({
    queryKey: ['diff', against?.version, 'draft', d.draft.revision],
    queryFn: against && d.draft.revision > 0 ? () => api<{ diff: Diff; summary: string }>('GET', `/api/diff/${against.version}/draft`) : skipToken,
  });
  return { against, diff };
}

// OverrideReason asks why to publish past the one check that can be
// overridden, and shows only once that check has blocked a publish.
export function OverrideReason({ error, value, onChange }: { error: unknown; value: string; onChange: (v: string) => void }) {
  if (!(error instanceof Problem && error.title === 'Issuer keys never fetched') && !value) return null;
  return (
    <Input
      label="Override reason"
      info="The reason is stored on the version and in the audit log."
      hint="Rules require tokens from an issuer whose keys admin has never fetched, such as when the identity provider is down. Edges reject those tokens until the keys arrive. Say why you publish anyway."
      value={value}
      onChange={(e) => onChange(e.target.value)}
      required
    />
  );
}

export function Publish({ can }: { can: (p: string) => boolean }) {
  const qc = useQueryClient();
  const d = useDraft();
  const versions = useVersions();
  const active = versions.data?.find((v) => v.status === 'active');
  // A publish to a canary bases the draft on the canary version while the
  // old one stays active: that draft is current, not behind, and the
  // useful comparison is with the canary.
  const running = versions.data?.find((v) => v.status === 'canary');
  const { against, diff } = useDraftDiff();
  const behind = !!active && d.draft.base_version !== active.version && d.draft.base_version !== running?.version;
  const [message, setMessage] = useState('');
  const [canary, setCanary] = useState('');
  const { pct, bad: badPct } = canaryPercent(canary);
  const [override, setOverride] = useState('');
  const guard = useQuery({ queryKey: ['guard'], queryFn: () => api<Json>('GET', '/api/settings/guard') });
  const [guardOverride, setGuardOverride] = useState<Json>();
  const [guardReason, setGuardReason] = useState('');
  const [confirming, setConfirming] = useState(false);
  // What the last rebase, promote or abort did, since its card goes away.
  const [notice, setNotice] = useState('');
  const refresh = () =>
    Promise.all([qc.invalidateQueries({ queryKey: draftKey }), qc.invalidateQueries({ queryKey: ['versions'] }), qc.invalidateQueries({ queryKey: ['canary'] })]);
  const publish = useMutation({
    mutationFn: () =>
      api<{ version: number }>(
        'POST',
        '/api/publish',
        {
          message,
          canary_percent: pct ? Number(pct) : 0,
          override_reason: override,
          ...(guardOverride !== undefined && { guard_override: guardOverride, guard_override_reason: guardReason }),
        },
        { 'If-Match': etag(d.draft.revision) },
      ),
    onSuccess: () => (setMessage(''), setCanary(''), setOverride(''), setGuardOverride(undefined), setGuardReason(''), setNotice(''), refresh()),
  });
  const blocked = !can('config.publish')
    ? 'Your role cannot publish.'
    : d.dirty
      ? 'Save or discard your changes first.'
      : d.draft.revision === 0
        ? 'Save the draft first.'
        : running
          ? `Version ${running.version} is in canary; promote or abort it first.`
          : behind
            ? 'Rebase the draft onto the live version first.'
            : badPct
              ? 'Canary percent must be a number from 0.01 to 99.99, such as 5, or empty for all traffic.'
              : undefined;
  return (
    <Page title="Publish">
      {/* A canary step or abort makes an earlier publish notice out of date. */}
      <Canary can={can} onChange={(note) => (publish.reset(), setNotice(note), void refresh())} />
      {behind && <Rebase onDone={(note) => (publish.reset(), setNotice(note), void refresh())} canWrite={can('config.write')} matches={!!diff.data && isEmpty(diff.data.diff)} />}
      {notice && !behind && <Notice>{notice}</Notice>}
      <Card title={against ? `Saved draft compared with ${statusName(against.status)} version ${against.version}` : 'Saved draft'}>
        {d.dirty && (
          <div className="mb-3">
            <Notice tone="amber">Your unsaved changes are not shown here or published. Save the draft to include them.</Notice>
          </div>
        )}
        {d.draft.revision === 0 && <p className="text-body">Nothing saved yet. Save the draft to publish it.</p>}
        {diff.isPending && d.draft.revision > 0 && !!against && <p className="eyebrow text-body">Loading…</p>}
        {diff.data && <DiffView diff={diff.data.diff} />}
        <ErrorBox error={diff.error} />
      </Card>
      <Card title="Publish the saved draft">
        <form
          className="flex max-w-lg flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            setConfirming(true);
          }}
        >
          <Input
            label="Message"
            hint="Shown in the version list."
            placeholder="such as Limit API calls per user"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            required
          />
          {can('canary.manage') && (
            <Input
              label="Canary percent"
              info="Clients are picked by a hash of their IP, so each one keeps seeing the same version. The rollback guard compares the canary with the live version, and each step up needs a minimum time and request count first."
              hint="Part of traffic to try it on first, 0.01 to 99.99, such as 5. Empty for all traffic."
              inputMode="decimal"
              value={canary}
              onChange={(e) => setCanary(e.target.value)}
            />
          )}
          <OverrideReason error={publish.error} value={override} onChange={setOverride} />
          <Check
            label="Change the rollback guard for this publish"
            checked={guardOverride !== undefined}
            disabled={!guard.data}
            onChange={(e) => setGuardOverride(e.target.checked ? guard.data : undefined)}
          />
          {guardOverride !== undefined && (
            <>
              <GuardForm value={guardOverride as JsonObject} onChange={setGuardOverride} />
              <Input label="Why this publish needs a different guard" value={guardReason} onChange={(e) => setGuardReason(e.target.value)} required />
            </>
          )}
          <ErrorBox error={publish.error} where={(p) => (p === 'guard_override_reason' ? 'Why this publish needs a different guard' : guardWhere(p))} />
          {publish.data && <Notice>Published version {publish.data.version}.</Notice>}
          <div className="flex flex-col items-start gap-2">
            <Button type="submit" variant="primary" disabled={!!blocked || publish.isPending}>
              {publish.isPending ? 'Publishing…' : pct ? `Publish to ${pct}% of traffic` : 'Publish to all traffic'}
            </Button>
            <Hint>{blocked ?? (diff.data && isEmpty(diff.data.diff) && against && `The draft matches version ${against.version}, so this publishes an identical version.`)}</Hint>
          </div>
        </form>
        {confirming && (
          <Confirm
            title={pct ? `Publish to ${pct}% of traffic?` : 'Publish to all traffic?'}
            action="Publish"
            onConfirm={() => publish.mutate()}
            onClose={() => setConfirming(false)}
          >
            {pct
              ? `Every edge starts serving the saved draft to ${pct}% of clients, picked by IP so each keeps the same version. The rest keep the live version. ${
                  guardOverride !== undefined || guard.data
                    ? canRollBack((guardOverride ?? guard.data) as GuardGate)
                      ? 'The guard compares the two and aborts the canary if a rollback check trips; otherwise you step up, promote or abort on this page.'
                      : 'The guard compares the two but only alerts and never aborts the canary, so watch it and step up, promote or abort it yourself on this page.'
                    : 'Step up, promote or abort it on this page.'
                }`
              : `Every edge starts serving the saved draft to every request.${guardAfter((guardOverride ?? guard.data) as GuardGate | undefined)}`}
          </Confirm>
        )}
      </Card>
    </Page>
  );
}

// Rebase shows the three-way view when a revert, rollback or aborted
// canary replaced the version this draft started from.
function Rebase({ onDone, canWrite, matches }: { onDone: (note: string) => void; canWrite: boolean; matches: boolean }) {
  const d = useDraft();
  const view = useQuery({
    queryKey: ['rebase', d.draft.revision],
    queryFn: () => api<{ base_version: number; active_version: number; draft_changes: Diff; active_changes: Diff; conflicts: string[] }>('GET', '/api/draft/rebase'),
  });
  const apply = useMutation({
    mutationFn: () => api('POST', '/api/draft/rebase', undefined, { 'If-Match': etag(d.draft.revision) }),
    onSuccess: () =>
      onDone(
        view.data && isEmpty(view.data.draft_changes)
          ? `The draft is now the same as version ${view.data.active_version}.`
          : `Rebased the draft onto version ${view.data?.active_version}. You can publish it now.`,
      ),
  });
  // Copying the base version keeps its content and bases it on the active
  // version: the way back to work that was rolled back.
  const keep = useMutation({
    mutationFn: (version: number) => api('POST', `/api/versions/${version}/copy-to-draft`, undefined, { 'If-Match': etag(d.draft.revision) }),
    onSuccess: (_, version) => onDone(`The draft now holds version ${version}'s config on top of version ${view.data?.active_version}. Fix it, then publish.`),
  });
  const v = view.data;
  const busy = !canWrite || d.dirty || !v || apply.isPending || keep.isPending;
  // What replaced the base, in words, from the version list.
  const all = useVersions().data;
  const base = all?.find((x) => x.version === v?.base_version);
  const live = all?.find((x) => x.version === v?.active_version);
  const why =
    base?.status === 'rolled_back'
      ? base.abort_reason
        ? `its canary was aborted (${base.abort_reason})`
        : 'the guard rolled it back'
      : live?.source === 'revert'
        ? `someone reverted to version ${live.based_on}`
        : 'another version replaced it';
  return (
    <Card
      title="Rebase needed"
      note={
        v
          ? `This draft started from version ${v.base_version}, but ${why}, so version ${v.active_version} is live now. Publishing is blocked until the draft is based on version ${v.active_version}.`
          : 'The live version changed since this draft started.'
      }
    >
      <ErrorBox error={view.error} />
      {v && (
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <h3 className="mb-1 text-sm font-semibold">Your draft's changes since version {v.base_version}</h3>
            <DiffView diff={v.draft_changes} />
          </div>
          <div>
            <h3 className="mb-1 text-sm font-semibold">
              Version {v.active_version} compared with version {v.base_version}
            </h3>
            <DiffView diff={v.active_changes} />
          </div>
          {v.conflicts.length > 0 && (
            <div className="md:col-span-2">
              <Notice tone="amber">Conflicts, where the draft's change wins: {v.conflicts.join(', ')}</Notice>
            </div>
          )}
        </div>
      )}
      <div className="mt-4 flex flex-col items-start gap-3">
        <ErrorBox error={apply.error ?? keep.error} />
        <div className="flex flex-col gap-1">
          <Button variant="primary" disabled={busy} onClick={() => apply.mutate()}>
            Rebase the draft onto version {v?.active_version}
          </Button>
          <Hint>
            {matches
              ? `The draft already matches version ${v?.active_version}, so this changes no rules or settings; it only lets you publish again.`
              : v && isEmpty(v.draft_changes)
                ? `The draft has no changes of its own since version ${v.base_version}, so this drops version ${v.base_version}'s changes: the draft becomes version ${v.active_version}.`
                : `Keeps your draft's changes since version ${v?.base_version} and takes everything else from version ${v?.active_version}.`}
          </Hint>
        </div>
        {/* Only offered while the draft has no edits of its own, which copying would lose. */}
        {v && isEmpty(v.draft_changes) && (
          <div className="flex flex-col gap-1">
            <Button disabled={busy} onClick={() => keep.mutate(v.base_version)}>
              Keep version {v.base_version}'s changes in the draft
            </Button>
            <Hint>
              Starts the draft from version {v.base_version}'s config on top of version {v.active_version}, to fix and publish it again.
            </Hint>
          </div>
        )}
        <Hint>{!canWrite ? 'Your role cannot change the draft.' : d.dirty ? 'Save or discard your changes first.' : undefined}</Hint>
      </div>
    </Card>
  );
}

// seconds reads a Go duration as the API writes it ("5m0s", "1h30m0s").
// ms is tried before m, so "500ms" is not 500 minutes.
const seconds = (d: string) => [...d.matchAll(/([\d.]+)(ms|h|m|s)/g)].reduce((n, [, v, u]) => n + Number(v) * { ms: 0.001, h: 3600, m: 60, s: 1 }[u as 'ms' | 'h' | 'm' | 's'], 0);

function Canary({ can, onChange }: { can: (p: string) => boolean; onChange: (note: string) => void }) {
  const q = useQuery({
    queryKey: ['canary'],
    queryFn: () => api<{ canary: { version: number; percent: number; started_at: string; step_started_at: string } | null }>('GET', '/api/canary'),
    refetchInterval: 30_000,
  });
  const versions = useVersions();
  const [percent, setPercent] = useState('');
  const [reason, setReason] = useState('');
  // A done step leaves no input behind to read as a new mistake.
  const act = useMutation({
    mutationFn: ([path, body]: [string, Json?]) => api('POST', `/api/canary/${path}`, body),
    onSuccess: (_, [path]) => {
      setPercent('');
      setReason('');
      const v = q.data?.canary?.version;
      onChange(path === 'promote' ? `Promoted version ${v} to all traffic.` : path === 'abort' ? `Aborted the canary. Version ${v} is rolled back.` : '');
    },
  });
  const globalGuard = useQuery({
    queryKey: ['guard'],
    queryFn: () => api<GuardGate>('GET', '/api/settings/guard'),
  });
  const c = q.data?.canary;
  // The server judges a canary with the publish's own guard override when it set one.
  const detail = useQuery({ queryKey: ['version', c?.version], queryFn: c ? () => api<VersionDetail>('GET', `/api/versions/${c.version}`) : skipToken });
  const g = detail.data && (detail.data.guard_override ?? globalGuard.data);
  // The server counts a step's requests from the minute it started; this
  // shows the same count so the wait is not a guess. It is display only.
  const since = c ? Math.floor(Date.parse(c.step_started_at) / 60_000) * 60_000 : 0;
  const seen = useQuery({
    queryKey: ['stats', 'step', c?.version, since],
    queryFn: c
      ? async () => {
          const rows = await api<{ minute: string; version: number; requests: number }[]>(
            'GET',
            `/api/stats?minutes=${Math.min(43_200, Math.ceil((Date.now() - since) / 60_000) + 1)}`,
          );
          return rows.filter((r) => r.version === c.version && Date.parse(r.minute) >= since).reduce((n, r) => n + r.requests, 0);
        }
      : skipToken,
    refetchInterval: 30_000,
  });
  if (!c) return <ErrorBox error={q.error} />;
  const manage = can('canary.manage');
  // An alert does not stop the canary, so it is repeated where the next step is taken.
  const listed = versions.data?.find((v) => v.version === c.version);
  const outcome = listed?.guard_outcome;
  const alert = outcome?.decision === 'alert' ? outcomeSays(outcome).join(' ') : '';
  // The server's rule, checked here too so a wrong number never reaches the
  // confirm dialog.
  const step = percent.trim().replace(/%$/, '');
  const next = Number(step);
  const badStep = !step ? 'Enter a percent.' : !(next > c.percent && next <= 99.99) ? `Enter a number above ${c.percent} and at most 99.99.` : undefined;
  // The guard's own gate, shown so nobody has to work it out: a minimum
  // time on this step and a minimum request count in it.
  const from = g && Date.parse(c.step_started_at) + seconds(g.step_min_time) * 1000;
  // The count's fetch time stands for now, which render must not read; it
  // refreshes every 30 seconds.
  const gateMet = !!g && from !== undefined && seen.data !== undefined && seen.dataUpdatedAt >= from && seen.data >= g.min_requests;
  // A failed read must not lock the buttons: the server's step check is the
  // real gate and its refusal shows in the error box.
  const ready = gateMet || detail.isError || globalGuard.isError || seen.isError;
  // The guard never rolls back a revert or its own rollback, and skips a disabled guard.
  const aborts = !!g && canRollBack(g) && listed !== undefined && listed.source !== 'revert' && listed.source !== 'guard_rollback';
  return (
    <Card
      title={`Canary: version ${c.version} on ${c.percent}% of traffic`}
      note={
        `Started ${ago(c.started_at)}${c.step_started_at !== c.started_at ? `; this step started ${ago(c.step_started_at)}` : ''}. ` +
        (!g || from === undefined
          ? "Each step needs the guard's minimum time and requests before the next."
          : gateMet
            ? `Ready: this step has seen ${seen.data.toLocaleString()} requests, over the ${g.min_requests.toLocaleString()} the guard needs, and has run long enough. Step up, promote or abort.`
            : `The guard watches each step before the next: step up or promote once this step has run until ${new Date(from).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}${seen.dataUpdatedAt < from ? ` (about ${Math.ceil((from - seen.dataUpdatedAt) / 60_000)} min)` : ''} and seen ${g.min_requests.toLocaleString()} requests` +
              (seen.data !== undefined ? ` (${seen.data.toLocaleString()} so far, counted each full minute).` : '.') +
              (aborts
                ? ' If a rollback check trips first, the guard aborts the canary itself. Abort works at any time.'
                : ' The guard only alerts on this canary and never aborts it, so watch it and abort it yourself if needed.'))
      }
    >
      <div className="flex flex-col gap-4">
        {alert && <Notice tone="amber">The guard raised an alert on this canary. {alert}</Notice>}
        <div className="flex flex-wrap items-end gap-2">
          <Input
            label="Next percent"
            placeholder={`above ${c.percent}, such as ${Math.min(99.99, c.percent * 2)}`}
            inputMode="decimal"
            value={percent}
            onChange={(e) => setPercent(e.target.value)}
          />
          <ConfirmButton
            variant="default"
            title={`Step up to ${step}%?`}
            action="Step up"
            confirm={`Version ${c.version} goes from ${c.percent}% to ${step}% of traffic on every edge.`}
            disabled={!manage || !ready || !!badStep || act.isPending}
            onConfirm={() => act.mutate(['step', { percent: next }])}
          >
            Step up
          </ConfirmButton>
          <ConfirmButton
            title="Promote to all traffic?"
            action="Promote"
            confirm={`${alert ? `The guard raised an alert on this canary. ${alert} ` : ''}Version ${c.version} becomes the live version for every request on every edge.`}
            disabled={!manage || !ready || act.isPending}
            onConfirm={() => act.mutate(['promote'])}
          >
            Promote to all traffic
          </ConfirmButton>
        </div>
        <Hint>{manage && percent && badStep}</Hint>
        <div className="flex flex-wrap items-end gap-2">
          <Input label="Abort reason" placeholder="Required" value={reason} onChange={(e) => setReason(e.target.value)} />
          <ConfirmButton
            variant="danger"
            title="Abort the canary?"
            action="Abort canary"
            confirm={`Version ${c.version} is rolled back and every edge returns to the live version for all traffic.`}
            disabled={!manage || !reason || act.isPending}
            onConfirm={() => act.mutate(['abort', { reason }])}
          >
            Abort
          </ConfirmButton>
        </div>
        <Hint>{!manage ? 'Your role cannot manage canaries.' : undefined}</Hint>
        <ErrorBox error={detail.error ?? globalGuard.error ?? seen.error} />
        <ErrorBox error={act.error} />
      </div>
    </Card>
  );
}
