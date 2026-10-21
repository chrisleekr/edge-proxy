import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { api, type Diff, etag, type Json, Problem, type GuardGate, type Version, type VersionDetail as Detail } from '../api';
import { draftKey, useDraft } from '../draft';
import { Link, navigate } from '../router';
import { Badge, Button, Card, Check, ConfirmButton, ErrorBox, Hint, Notice, Input, NotFound, Page, Pending, Table, download, statusName, when, who } from '../ui';
import { describe, DiffView, isEmpty } from './DiffView';
import { outcomeSays, whyKept } from '../guard';
import { canaryPercent, guardAfter, OverrideReason, useVersions } from './Publish';

const statusTone = (s: string) => (s === 'active' ? 'green' : s === 'canary' ? 'amber' : s === 'rolled_back' ? 'red' : 'slate');

// sourceName is how a version came to be published.
const sourceName = (s: string) => ({ manual: 'published', revert: 'revert', guard_rollback: 'guard rollback', import: 'import' })[s] ?? s;

export function Versions({ can }: { can: (p: string) => boolean }) {
  const q = useVersions();
  return (
    <Page
      title="Versions"
      info="Every publish is a numbered version that never changes. Revert publishes an old version's config again as a new version, so history is never rewritten. Copy to draft starts a new draft from it instead."
      actions={
        <>
          <Button onClick={() => navigate('/versions/compare')}>Compare versions</Button>
          {q.data?.some((v) => v.status === 'active') && <Export />}
        </>
      }
    >
      <ErrorBox error={q.error} />
      {q.data && can('config.rollback') && <RevertToPrevious versions={q.data} />}
      {q.isPending && <Pending error={null} />}
      {/* Author and changes sit under the column they explain, so the table fits a laptop screen. */}
      <Table head={['Version', 'Status', 'Published', 'Message', 'Guard']} empty={q.data && 'Nothing published yet. Save the draft, then publish it.'}>
        {q.data?.map((v) => (
          <tr key={v.version}>
            <td>
              {/* Padded so a one-digit number is still a 24px target. */}
              <Link to={`/versions/${v.version}`} className="-mx-2 -my-1 inline-block min-w-10 rounded-control px-2 py-1 font-medium text-heading underline hover:bg-soft">
                v{v.version}
              </Link>
            </td>
            <td>
              <Badge tone={statusTone(v.status)}>{statusName(v.status)}</Badge>
              {v.source !== 'manual' && <div className="text-sm text-body">{sourceName(v.source)}</div>}
            </td>
            <td className="min-w-28 whitespace-normal">
              {when(v.published_at)}
              <div className="text-body">by {who(v.author)}</div>
            </td>
            <td className="min-w-36 whitespace-normal">
              {v.message}
              {v.change_summary && <div className="text-body">{v.change_summary}</div>}
            </td>
            <td className="whitespace-normal">{v.guard_outcome && guardSays(v.guard_outcome.decision)}</td>
          </tr>
        ))}
      </Table>
      {can('config.publish') && <Import />}
    </Page>
  );
}

// guardSays is a guard decision in words.
const guardSays = (d: string) =>
  ({ ok: 'no problems seen', alert: 'raised an alert', rollback: 'rolled it back', insufficient_data: 'not enough traffic yet to judge' })[d] ?? d.replaceAll('_', ' ');

// Export downloads the active version: the envelope alone is the file an
// edge boots from when admin is unreachable; with its tests it imports
// into another admin. Each export is audited.
function Export() {
  const run = useMutation({
    mutationFn: async (kind: 'bootstrap' | 'full') => {
      const x = await api<{ envelope: { active: { version: number } }; tests: Json }>('GET', '/api/export');
      const v = x.envelope.active.version;
      if (kind === 'bootstrap') download(x.envelope, `bootstrap-v${v}.json`);
      else download(x, `policy-export-v${v}.json`);
    },
  });
  return (
    <>
      <Button title="The file an edge loads at start when admin is unreachable. Refresh it at least weekly." disabled={run.isPending} onClick={() => run.mutate('bootstrap')}>
        Download bootstrap file
      </Button>
      <Button title="The active version with its tests, to import into another admin." disabled={run.isPending} onClick={() => run.mutate('full')}>
        Export
      </Button>
      <ErrorBox error={run.error} />
    </>
  );
}

// Import publishes a file exported from another admin, such as staging,
// through every publish check here: validation, tests and keys.
function Import() {
  const qc = useQueryClient();
  const [file, setFile] = useState<{ name: string; config: Json; tests: Json } | { name: string; problem: string }>();
  const [message, setMessage] = useState('');
  const [override, setOverride] = useState('');
  const guard = useQuery({ queryKey: ['guard'], queryFn: () => api<GuardGate>('GET', '/api/settings/guard') });
  const run = useMutation({
    mutationFn: () =>
      api<{ version: number }>('POST', '/api/import', { ...(file && 'config' in file ? { config: file.config, tests: file.tests } : {}), message, override_reason: override }),
    onSuccess: (r) => Promise.all([qc.invalidateQueries({ queryKey: ['versions'] }), qc.invalidateQueries({ queryKey: draftKey })]).then(() => navigate(`/versions/${r.version}`)),
  });
  const read = async (f: File | undefined) => {
    run.reset();
    if (!f) return setFile(undefined);
    try {
      // An export holds { envelope: { active }, tests }; a bare
      // { config, tests } is accepted too.
      const j = JSON.parse(await f.text()) as { envelope?: { active?: Json }; config?: Json; tests?: Json };
      const config = j.envelope?.active ?? j.config;
      setFile(config ? { name: f.name, config, tests: j.tests ?? [] } : { name: f.name, problem: 'This file has no config: choose a file made with Export.' });
    } catch {
      setFile({ name: f.name, problem: 'This file is not JSON.' });
    }
  };
  const ready = file && 'config' in file;
  return (
    <Card title="Import" intro="Publish a file made with Export on another admin, such as staging. It goes through every publish check here, then serves all traffic at once.">
      <div className="flex max-w-lg flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-heading">Export file</span>
          <input type="file" accept="application/json,.json" onChange={(e) => void read(e.target.files?.[0])} />
        </label>
        {file && 'problem' in file && <Notice tone="red">{file.problem}</Notice>}
        <Input label="Message" placeholder="such as Promote staging policy" value={message} onChange={(e) => setMessage(e.target.value)} />
        <OverrideReason error={run.error} value={override} onChange={setOverride} />
        <ErrorBox error={run.error} />
        <div className="flex flex-col items-start gap-2">
          <ConfirmButton
            title="Publish the imported config?"
            action="Publish import"
            confirm={`Every edge starts serving the config from ${ready ? file.name : 'the file'} to every request.${guardAfter(guard.data)}`}
            disabled={!ready || !message || run.isPending}
            onConfirm={() => run.mutate()}
          >
            {run.isPending ? 'Publishing…' : 'Publish import'}
          </ConfirmButton>
          <Hint>{!ready ? 'Choose an export file.' : !message ? 'Give a message for the version list.' : undefined}</Hint>
        </div>
      </div>
    </Card>
  );
}

// RevertToPrevious is the one-click emergency revert: the
// version that was active before the current one, after a confirm.
function RevertToPrevious({ versions }: { versions: Version[] }) {
  const qc = useQueryClient();
  const active = versions.find((v) => v.status === 'active');
  const previous = active && versions.find((v) => v.version < active.version && v.status === 'superseded');
  // A revert is a publish, which the server refuses while a canary runs.
  const running = versions.find((v) => v.status === 'canary');
  const [reason, setReason] = useState('');
  const revert = useMutation({
    mutationFn: () => api<{ version: number }>('POST', `/api/versions/${previous!.version}/revert`, { reason }),
    onSuccess: (r) => Promise.all([qc.invalidateQueries({ queryKey: ['versions'] }), qc.invalidateQueries({ queryKey: draftKey })]).then(() => navigate(`/versions/${r.version}`)),
  });
  if (!active || !previous) return null;
  // While a canary runs a revert is refused, so only the way out is shown.
  if (running)
    return (
      <p className="rounded-control bg-soft p-3 text-sm">
        Version {running.version} is on trial as a canary, so reverting is off. To go back to version {active.version} alone, abort the canary on{' '}
        <Link to="/publish" className="underline">
          Publish
        </Link>
        .
      </p>
    );
  return (
    <div className="flex flex-wrap items-end gap-2 rounded-control bg-soft p-3">
      <p className="mr-auto text-sm">
        Version {active.version} is live{active.message && `: ${active.message}`}. If it causes problems, revert to the version before it.
      </p>
      <Input label="Reason" placeholder="Required, such as 5xx after publish" value={reason} onChange={(e) => setReason(e.target.value)} />
      <ConfirmButton
        variant="danger"
        title={`Revert to version ${previous.version}?`}
        action="Revert now"
        confirm={`Publishes version ${previous.version}'s config as a new version to every edge at once.`}
        disabled={!reason || revert.isPending}
        onConfirm={() => revert.mutate()}
      >
        Revert to previous (version {previous.version})
      </ConfirmButton>
      <ErrorBox error={revert.error} />
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
  const { pct, bad: badPct } = canaryPercent(canary);
  const running = useVersions().data?.find((x) => x.status === 'canary');
  const done = () => Promise.all([qc.invalidateQueries({ queryKey: ['versions'] }), qc.invalidateQueries({ queryKey: draftKey })]);
  const revert = useMutation({
    mutationFn: () => api<{ version: number }>('POST', `/api/versions/${version}/revert`, { reason, override_reason: override, canary_percent: pct ? Number(pct) : 0 }),
    onSuccess: (r) => done().then(() => navigate(`/versions/${r.version}`)),
  });
  const copy = useMutation({
    mutationFn: () => api('POST', `/api/versions/${version}/copy-to-draft`, undefined, { 'If-Match': etag(d.draft.revision) }),
    onSuccess: () => done().then(() => navigate('/rules')),
  });
  // What this version changed, so the page answers that without a compare.
  const changes = useQuery({
    queryKey: ['diff', version - 1, version],
    queryFn: () => api<{ diff: Diff }>('GET', `/api/diff/${version - 1}/${version}`),
    enabled: version > 1,
    staleTime: Infinity,
  });
  const v = q.data;
  if (!v) {
    if (q.error instanceof Problem && q.error.status === 404)
      return (
        <NotFound title={`Version ${version} not found`} back={['/versions', 'All versions']}>
          Nothing has been published as version {version}.
        </NotFound>
      );
    return <Pending error={q.error} />;
  }
  return (
    <Page
      title={`Version ${v.version}`}
      actions={
        <>
          {v.version > 1 && <Button onClick={() => navigate(`/versions/compare?a=${v.version - 1}&b=${v.version}`)}>Compare with {v.version - 1}</Button>}
          <ConfirmButton
            variant="default"
            title={`Replace the draft with version ${v.version}?`}
            action="Replace the draft"
            confirm={`The saved draft, including changes not yet published, is replaced by version ${v.version}'s config and tests. Nothing is published.`}
            disabled={!can('config.write') || d.dirty || copy.isPending}
            onConfirm={() => copy.mutate()}
          >
            Copy to draft
          </ConfirmButton>
        </>
      }
    >
      <Card>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-body">Status</dt>
          <dd>
            <Badge tone={statusTone(v.status)}>{statusName(v.status)}</Badge>
          </dd>
          <dt className="text-body">Published</dt>
          <dd>
            {when(v.published_at)} by {who(v.author)}
          </dd>
          <dt className="text-body">Message</dt>
          <dd>{v.message}</dd>
          <dt className="text-body">Source</dt>
          <dd>
            {sourceName(v.source)}
            {v.based_on !== null && ` of version ${v.based_on}`}
          </dd>
          {v.override_reason && (
            <>
              <dt className="text-body">Override</dt>
              <dd>{v.override_reason}</dd>
            </>
          )}
          {v.guard_override_reason && (
            <>
              <dt className="text-body">Guard override</dt>
              <dd>{v.guard_override_reason}</dd>
            </>
          )}
          {v.abort_reason && (
            <>
              <dt className="text-body">Abort reason</dt>
              <dd>{v.abort_reason}</dd>
            </>
          )}
          {v.guard_outcome && (
            <>
              <dt className="text-body">Guard</dt>
              <dd>
                {guardSays(v.guard_outcome.decision)}, {when(v.guard_outcome.at)}
                <ul className="mt-1 flex flex-col gap-0.5">
                  {outcomeSays(v.guard_outcome).map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                  {v.guard_outcome.decision === 'alert' && (v.status === 'active' || v.status === 'canary') && <li className="text-body">{whyKept(v.guard_outcome, v.source)}</li>}
                </ul>
              </dd>
            </>
          )}
        </dl>
      </Card>
      {v.status !== 'active' && v.status !== 'canary' && (
        <Card
          title="Revert to this version"
          intro="Publishes a new version with this config, to all traffic or first as a canary. History is never rewritten."
        >
          <div className="flex max-w-lg flex-col gap-3">
            {v.status === 'rolled_back' && (
              <Notice tone="amber">
                This version was rolled back. Reverting to it brings the same change back, and the guard never rolls back a revert, even as a canary: it only alerts. Try it as a canary and watch it yourself.
              </Notice>
            )}
            <Input label="Reason" placeholder="such as 5xx errors rose after the last publish" value={reason} onChange={(e) => setReason(e.target.value)} />
            <OverrideReason error={revert.error} value={override} onChange={setOverride} />
            {can('canary.manage') && (
              <Input
                label="Canary percent"
                hint="Part of traffic to try it on first, 0.01 to 99.99, such as 5. Empty for all traffic."
                inputMode="decimal"
                value={canary}
                onChange={(e) => setCanary(e.target.value)}
              />
            )}
            <ErrorBox error={revert.error} />
            <div className="flex flex-col items-start gap-2">
              <ConfirmButton
                variant="danger"
                title={`Revert to version ${v.version}?`}
                action="Revert now"
                confirm={
                  pct
                    ? `Publishes version ${v.version}'s config as a new version to ${pct}% of traffic.`
                    : `Publishes version ${v.version}'s config as a new version to every edge at once.`
                }
                disabled={!can('config.rollback') || !reason || badPct || !!running || revert.isPending}
                onConfirm={() => revert.mutate()}
              >
                Revert to version {v.version}
              </ConfirmButton>
              <Hint>
                {!can('config.rollback')
                  ? 'Your role cannot revert.'
                  : running
                    ? `Version ${running.version} is in canary; promote or abort it on Publish first.`
                    : !reason
                      ? 'Give a reason to revert.'
                      : badPct
                        ? 'Canary percent must be a number from 0.01 to 99.99, such as 5, or empty for all traffic.'
                        : undefined}
              </Hint>
            </div>
          </div>
        </Card>
      )}
      <ErrorBox error={copy.error} />
      {v.version > 1 && (
        <Card title={`Changes from version ${v.version - 1}`}>
          {changes.data ? <DiffView diff={changes.data.diff} /> : <Pending error={changes.error} />}
        </Card>
      )}
      {!!v.test_results?.length && (
        <Card title="Tests at publish">
          <ul className="flex flex-col gap-1 text-sm">
            {v.test_results.map((t) => (
              <li key={t.name}>
                <Badge tone={t.pass ? 'green' : 'red'}>{t.pass ? 'pass' : 'fail'}</Badge> {t.name}
                {t.failures && <span className="text-danger">: {t.failures.join('; ')}</span>}
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Card>
        <details>
          <summary className="cursor-pointer font-medium text-heading">Full config as JSON</summary>
          <pre className="mt-2 max-h-[32rem]">{JSON.stringify(v.config, null, 2)}</pre>
        </details>
      </Card>
    </Page>
  );
}

export function Compare() {
  const params = new URLSearchParams(window.location.search);
  // Both go into the API path, so only a version number or "draft" is taken.
  const side = (v: string | null) => (v && /^(\d+|draft)$/.test(v) ? v : undefined);
  const [a, setA] = useState(side(params.get('a')) ?? '');
  const [b, setB] = useState(side(params.get('b')) ?? 'draft');
  const [raw, setRaw] = useState(false);
  const versions = useVersions();
  // From starts at the active version: the usual question is what the
  // draft or a newer version changes.
  const active = versions.data?.find((v) => v.status === 'active');
  const from = a || (active ? String(active.version) : '');
  // The picked pair lives in the address, so the view can be shared.
  useEffect(() => {
    if (from) window.history.replaceState(null, '', `/versions/compare?a=${from}&b=${b}`);
  }, [from, b]);
  const semantic = useQuery({ queryKey: ['diff', from, b], queryFn: () => api<{ diff: Diff; summary: string }>('GET', `/api/diff/${from}/${b}`), enabled: !!from && !!b && !raw });
  const text = useQuery({ queryKey: ['raw', from, b], queryFn: () => api<{ a: string; b: string }>('GET', `/api/diff/${from}/${b}?view=raw`), enabled: !!from && !!b && raw });
  // Picked from what exists, so nobody has to know version numbers.
  const pick = (label: string, value: string, set: (v: string) => void) => (
    <label className="flex max-w-full flex-col gap-1 text-sm">
      <span className="font-medium text-heading">{label}</span>
      {/* Long version messages must not widen the page on phones. */}
      <select className="max-w-full" value={value} onChange={(e) => set(e.target.value)}>
        {!value && <option value="">Choose…</option>}
        <option value="draft">Draft</option>
        {versions.data?.map((v) => (
          <option key={v.version} value={v.version}>
            Version {v.version}
            {v.status === 'active' ? ' (live)' : ''}
            {v.message && `: ${v.message}`}
          </option>
        ))}
      </select>
    </label>
  );
  return (
    <Page title="Compare versions">
      <div className="flex flex-wrap items-end gap-x-4 gap-y-3">
        {pick('From', from, setA)}
        {pick('To', b, setB)}
        <div className="flex min-h-[2.125rem] items-center">
          <Check label="Raw JSON" checked={raw} onChange={(e) => setRaw(e.target.checked)} />
        </div>
      </div>
      <ErrorBox error={semantic.error ?? versions.error ?? text.error} />
      {!raw && semantic.data && (
        <Card title={isEmpty(semantic.data.diff) ? 'Changes' : describe(semantic.data.diff)}>
          <DiffView diff={semantic.data.diff} />
        </Card>
      )}
      {raw && text.data && <RawDiff a={text.data.a} b={text.data.b} />}
    </Page>
  );
}

// RawDiff shows both documents side by side and marks each line the other
// side lacks. ponytail: compared as sets of lines, not aligned, so a line
// that only moved is not marked; use the semantic view for moves.
function RawDiff({ a, b }: { a: string; b: string }) {
  const [la, lb] = [a.split('\n'), b.split('\n')];
  const [sa, sb] = [new Set(la), new Set(lb)];
  // The sign repeats the shading for anyone who cannot see the colour.
  const side = (lines: string[], other: Set<string>, mark: string, sign: string, label: string) => (
    <pre aria-label={label} className="max-h-[40rem]">
      {lines.map((l, i) => (
        <span key={i} className={`block ${other.has(l) ? '' : mark}`}>
          <span className="select-none">{other.has(l) ? '  ' : `${sign} `}</span>
          {l}
        </span>
      ))}
    </pre>
  );
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm text-body">
        Lines marked <span className="border-l-2 border-danger px-1 font-mono text-danger">−</span> are only in From; lines marked{' '}
        <span className="border-l-2 border-success px-1 font-mono text-success">+</span> are only in To.
      </p>
      <div className="grid gap-2 md:grid-cols-2">
        {side(la, sb, '-ml-1 border-l-2 border-danger pl-0.5 text-danger', '−', 'From')}
        {side(lb, sa, '-ml-1 border-l-2 border-success pl-0.5 text-success', '+', 'To')}
      </div>
    </div>
  );
}

// RuleHistory lists the published versions where a rule changed.
export function RuleHistory({ id }: { id: string }) {
  const q = useQuery({
    queryKey: ['history', id],
    queryFn: () => api<{ version: number; author: string; published_at: string; rule: Json }[]>('GET', `/api/rules/${encodeURIComponent(id)}/history`),
  });
  if (!q.data?.length) return <ErrorBox error={q.error} />;
  return (
    <Card title="Published history">
      <ul className="flex flex-col gap-2 text-sm">
        {/* Oldest first; a rule with nothing before it, or after a removal, was added. */}
        {q.data.map((e, i) => (
          <li key={e.version}>
            <Link to={`/versions/${e.version}`} className="underline">
              Version {e.version}
            </Link>{' '}
            {when(e.published_at)} by {who(e.author)}: {!e.rule ? 'removed' : q.data[i - 1]?.rule ? 'changed' : 'added'}
          </li>
        ))}
      </ul>
    </Card>
  );
}
