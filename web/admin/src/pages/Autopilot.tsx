import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { api, type Issue, type Json, Problem, useCan } from '../api';
import { draftKey, useOptionalDraft } from '../draft';
import { Decimal } from '../GuardForm';
import { Amount, Choice, Count, Errors, Labeled, Lines, timeUnits } from '../RuleForms';
import { Link, navigate, useLeaveGuard, useSearch } from '../router';
import { Badge, Button, Card, ConfirmButton, ErrorBox, Hint, Input, Modal, NotFound, Notice, Page, Pending, Table, ago, when, who } from '../ui';
import { count, type Range, RangePicker, ruleCounts, Spark, useRange } from './Fleet';
import { AdoptButton } from './Rules';

// The autopilot's home and its case pages. Every number comes from admin;
// expressions are the server's rendering, never parsed here.

export interface RuleView {
  id: string;
  kind: 'sensor' | 'enforce';
  state: string;
  expression: string;
  key: string[];
  limit: number;
  period: string;
  case_id: number;
  live_since: string | null;
  enforcing_since: string | null;
  expires_at: string | null;
  shadow_ratio: number | null;
  outcome: string | null;
  // What the rule's conditions fix: an exclusion promoted from it defaults to them.
  host: string;
  path_prefix: string;
}

// Exclusion is a client a person found legitimate on a host and path,
// which every autopilot rule proposed while it is active leaves out.
export interface Exclusion {
  id: number;
  subject: string;
  host: string;
  path_prefix: string;
  reason: string;
  rule_id: string | null;
  created_by: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  revoke_reason: string | null;
}

interface Spend {
  runs: number;
  unpriced_runs: number;
  configured_usd_micros: number;
  provider_usd_micros: number;
}

interface SpendDay {
  day: string;
  provider: string;
  model: string;
  runs: number;
  cases: number;
  unpriced_runs: number;
  configured_usd_micros: number;
  provider_usd_micros: number;
}

interface State {
  mode: string;
  agent_connected: boolean;
  runners: {
    id: string;
    version: string;
    providers: string[];
    last_seen: string;
  }[];
  credentials: Record<string, boolean>;
  warnings: string[];
  budgets: Record<'enforcing' | 'sensors' | 'cases_hour', { used: number; max: number }>;
  cases_open: number;
  rules: RuleView[];
  exclusions: Exclusion[];
  spend: Record<'last_24h' | 'last_7d', Spend>;
  spend_days: SpendDay[];
  precision: {
    model: string;
    prompt_sha256: string;
    correct: number;
    wrong: number;
  }[];
}

interface CaseRow {
  id: number;
  kind: string;
  rule: string | null;
  route_id: number | null;
  anomaly_id: number | null;
  question: string;
  state: string;
  attempts: number;
  verdict: string | null;
  summary: string;
  opened_by: string;
  created_at: string;
  closed_at: string | null;
}

interface Run {
  id: number;
  attempt: number;
  runner: string;
  provider: string;
  model: string;
  prompt_sha256: string;
  tools_sha256: string;
  started_at: string;
  finished_at: string | null;
  status: string | null;
  error_category: string | null;
  turns: number | null;
  tool_calls: number | null;
  input_tokens: number | null;
  output_tokens: number | null;
  cache_read_tokens: number | null;
  cache_write_tokens: number | null;
  configured_cost_usd_micros: number | null;
  provider_cost_usd_micros: number | null;
  telemetry_complete: boolean | null;
}

interface Proposal {
  id: number;
  action: string;
  rule_id: string | null;
  rule: { expression?: string };
  ttl_seconds: number | null;
  rationale: string;
  evidence: Json;
  checks: { name: string; ok: boolean; detail?: string }[];
  accepted: boolean;
}

interface Transition {
  rule_id: string;
  from_state: string;
  to_state: string;
  reason: string;
  actor: string;
  at: string;
}

interface ToolCall {
  run_id: number;
  seq: number;
  at: string;
  payload: {
    tool?: string;
    arguments?: Json;
    allowed?: boolean;
    duration_ms?: number;
    refusal?: string;
    result?: Json;
    // Set when admin withheld the answer from a reader without stats.read and config.read.
    hidden?: boolean;
    // The permissions the reader lacks, such as "needs stats.read and config.read".
    hidden_reason?: string;
    // Set in place of the call when its payload was too large to keep.
    cut?: boolean;
    bytes?: number;
    sha256?: string;
  };
}

interface CaseRead {
  case: CaseRow;
  runs: Run[];
  proposals: Proposal[];
  transitions: Transition[];
  tool_calls: ToolCall[];
  rules: RuleView[];
}

interface Settings {
  mode: string;
  model: string;
  sweep_model: string;
  protected_subjects: string[];
  [k: string]: Json;
}

interface Price {
  id: number;
  provider: string;
  model: string;
  input_usd_per_mtok: number;
  output_usd_per_mtok: number;
  cache_read_usd_per_mtok: number;
  cache_write_usd_per_mtok: number;
  effective_from: string;
  author: string;
}

export const autopilotQuery = {
  queryKey: ['autopilot'],
  queryFn: () => api<State>('GET', '/api/autopilot'),
  refetchInterval: 30_000,
};
const settingsQuery = {
  queryKey: ['autopilot', 'settings'],
  queryFn: () => api<Settings>('GET', '/api/settings/autopilot'),
};

const modes: Record<string, string> = {
  off: 'Off',
  observe: 'Observe: a person approves each block',
  auto: 'Auto: blocks once the measurements hold',
};
const states: Record<string, string> = {
  proposed: 'waiting to publish',
  observing: 'logging only',
  enforcing: 'blocking',
  rejected: 'rejected',
  expired: 'expired',
  retired: 'retired',
  rolled_back: 'rolled back',
  adopted: 'adopted',
};
const outcomes: Record<string, string> = {
  expired: 'ran out',
  retired: 'retired by a person',
  retired_by_review: 'retired by the daily review',
  rolled_back: 'rolled back by its guard',
  false_positive: 'marked a false positive',
  adopted: 'adopted as your rule',
  rejected: 'rejected before blocking',
};
const kinds: Record<string, string> = {
  anomaly: 'Anomaly',
  sweep: 'Hourly sweep',
  review: 'Daily review',
  investigate: 'Investigate',
};
const verdicts: Record<string, string> = {
  attack: 'Attack',
  benign: 'Benign',
  unsure: 'Unsure: needs a person',
};

// The policy's checks in words, by the reason code admin returns.
const checks: Record<string, string> = {
  not_overlay_shape: 'Well formed: name, TTL and cited sensor',
  site_wide: 'Not every request',
  fail_mode: 'Lets requests through if Valkey is down',
  key_needs_ip_or_jwt: 'Counts per IP or JWT claim',
  constant_or_host_key: 'Not one shared count',
  missing_key_rejects: 'Does not refuse requests without its key',
  ttl_over_max: 'TTL within the most allowed',
  lifetime_over_max: 'Lifetime within the most allowed',
  penalty_past_expiry: 'Penalty ends before the rule does',
  named_subjects: 'Names no client',
  duplicate: 'Not the same as a live rule',
  suppressed: 'Not a rule marked wrong recently',
  compile: 'Passes validation with every live rule',
  budget_enforcing: 'Within the enforce rule budget',
  budget_sensors: 'Within the sensor budget',
  observed_too_short: 'Logged long enough',
  block_share: 'Blocks little besides the attackers',
  crawler_subject: 'Blocks no verified crawler',
  protected_subject: 'Blocks no protected subject',
  attack_stopped: 'The attack is still going',
};

const usd = (micros: number) =>
  (micros / 1e6).toLocaleString('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: micros > 0 && micros < 10_000 ? 4 : 2,
  });
const n = (x: number | null | undefined) => (x ?? 0).toLocaleString();
const short = (d: string) => d.replace(/(\D)0s$/, '$1').replace(/(\D)0m$/, '$1');
const json = (v: Json) => JSON.stringify(v, null, 2);
const seconds = (x: number) => (x % 3600 === 0 ? `${x / 3600}h` : x % 60 === 0 ? `${x / 60}m` : `${x}s`);

// useTick re-renders every interval, so countdowns move between fetches.
function useTick(ms: number) {
  const [, set] = useState(0);
  useEffect(() => {
    const t = setInterval(() => set((x) => x + 1), ms);
    return () => clearInterval(t);
  }, [ms]);
}

// target says what a case is about, linked where it has a page.
function Target({ c }: { c: CaseRow }) {
  if (c.rule) return <span>rule {c.rule}</span>;
  if (c.route_id !== null)
    return (
      <Link to={`/routes/${c.route_id}`} className="underline">
        route {c.route_id}
      </Link>
    );
  if (c.anomaly_id !== null)
    return (
      <Link to="/notifications" className="underline">
        anomaly {c.anomaly_id}
      </Link>
    );
  return null;
}

// Investigate asks the autopilot about a rule, route or anomaly, and opens
// the case it starts.
export function Investigate({ target, name }: { target: { rule: string } | { route_id: number } | { anomaly_id: number }; name: string }) {
  const can = useCan();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState('');
  const start = useMutation({
    mutationFn: () =>
      api<{ id: number }>('POST', '/api/autopilot/cases', {
        ...target,
        question,
      }),
    onSuccess: (r) => (void qc.invalidateQueries({ queryKey: ['autopilot'] }), navigate(`/autopilot/cases/${r.id}`)),
  });
  if (!can('autopilot.manage')) return null;
  return (
    <>
      <Button onClick={() => setOpen(true)}>Investigate</Button>
      {open && (
        <Modal title={`Investigate ${name}`} onClose={() => setOpen(false)}>
          <form className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), start.mutate())}>
            <p>The autopilot's model reads the stats and may propose a rule. Every proposal passes admin's checks before it reaches an edge.</p>
            <label className="flex flex-col gap-1 text-sm">
              <span className="font-medium text-heading">Question, if any</span>
              <textarea rows={3} maxLength={2000} value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="such as: is someone guessing passwords?" />
            </label>
            <ErrorBox error={start.error} />
            <div className="flex flex-wrap justify-end gap-2">
              <Button data-autofocus onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={start.isPending}>
                Start investigating
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

export function Autopilot() {
  const q = useQuery(autopilotQuery);
  const can = useCan();
  const [search, setSearch] = useSearch();
  const find = search.get('rule') ?? '';
  const stats = can('stats.read');
  const range = useRange(stats);
  if (!q.data) return <Pending error={q.error} />;
  const st = q.data;
  return (
    <Page
      title="Autopilot"
      info="Adds short-lived rate limit rules against an attack while it runs. A language model investigates and proposes; admin checks every proposal and your budgets before a rule reaches an edge. Every autopilot rule expires."
      actions={
        <>
          <Link to="/autopilot/notes" className="rounded-control bg-panel px-3.5 py-1.5 text-sm font-medium text-heading shadow-field hover:bg-soft">
            Memory
          </Link>
          {stats && <RangePicker r={range} />}
        </>
      }
    >
      <Status st={st} canManage={can('settings.manage')} />
      <Input
        label="Find an autopilot rule"
        hint="Part of a live rule's ID, such as login. The cases list shows the cases on that exact rule ID."
        type="search"
        className="max-w-md"
        value={find}
        onChange={(e) => setSearch({ rule: e.target.value })}
      />
      <LiveRules rules={st.rules.filter((r) => r.id.includes(find.trim()))} find={find.trim()} range={stats ? range : undefined} />
      <Exclusions canManage={can('autopilot.manage')} />
      <Cases rule={find.trim()} />
      <SpendCard spend={st.spend} days={st.spend_days} />
      <Precision rows={st.precision} />
      <SettingsCard canManage={can('settings.manage')} />
      <Prices canManage={can('settings.manage')} />
    </Page>
  );
}

// Meter is a budget: how much of it is in use, in words and as a bar.
function Meter({ label, used, max }: { label: string; used: number; max: number }) {
  const full = max > 0 && used >= max;
  return (
    <div className="flex flex-col gap-1 text-sm">
      <span className="flex justify-between gap-2">
        <span className="font-medium text-heading">{label}</span>
        <span className={full ? 'text-warning' : 'text-body'}>
          {used} of {max}
          {full && ', full'}
        </span>
      </span>
      <span aria-hidden className="h-1.5 overflow-hidden rounded-full bg-soft">
        <span
          className={`block h-full ${full ? 'bg-warning' : 'bg-brand'}`}
          style={{
            width: `${max > 0 ? Math.min(100, (used / max) * 100) : 0}%`,
          }}
        />
      </span>
    </div>
  );
}

function Status({ st, canManage }: { st: State; canManage: boolean }) {
  const [off, setOff] = useState(false);
  const [done, setDone] = useState(false);
  return (
    <Card
      title="Status"
      info="A runner is the separate process that holds the model's credentials and runs each case. Admin opens cases only while a runner was seen in the last 2 minutes."
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <Badge tone={st.mode === 'off' ? 'red' : st.mode === 'observe' ? 'amber' : 'green'}>{modes[st.mode] ?? st.mode}</Badge>
          <span className="text-sm text-body">
            {st.cases_open} {st.cases_open === 1 ? 'case' : 'cases'} open
          </span>
          {canManage && st.mode !== 'off' && (
            <Button variant="danger" className="ml-auto" onClick={() => setOff(true)}>
              Turn autopilot off
            </Button>
          )}
        </div>
        {done && st.mode === 'off' && <Notice>Autopilot is off. Its rules are retired and leave the edges with the version just published.</Notice>}
        {st.mode === 'off' && !done && <p className="text-sm text-body">Off: autopilot opens no cases and publishes nothing. Turn it on in the settings below.</p>}
        {st.runners.length > 0 && (
          <ul className="flex flex-col gap-1 text-sm">
            {st.runners.map((r) => (
              <li key={r.id}>
                Runner <span className="font-medium text-heading">{r.id}</span> {r.version}, credentials for {r.providers.join(' and ') || 'no provider'}, seen{' '}
                <time title={when(r.last_seen)}>{ago(r.last_seen)}</time>
              </li>
            ))}
          </ul>
        )}
        {!st.agent_connected && (
          <Notice tone="amber">No runner seen in the last 2 minutes, so nothing new is investigated. Rules already live run until they expire.</Notice>
        )}
        {st.warnings.map((w) => (
          <Notice key={w} tone="amber">
            {w.charAt(0).toUpperCase() + w.slice(1)}.
          </Notice>
        ))}
        <div className="grid gap-4 sm:grid-cols-3">
          <Meter label="Enforce rules" used={st.budgets.enforcing.used} max={st.budgets.enforcing.max} />
          <Meter label="Sensors" used={st.budgets.sensors.used} max={st.budgets.sensors.max} />
          <Meter label="Cases started this hour" used={st.budgets.cases_hour.used} max={st.budgets.cases_hour.max} />
        </div>
      </div>
      {off && <KillSwitch onClose={() => setOff(false)} onDone={() => setDone(true)} />}
    </Card>
  );
}

// KillSwitch turns the autopilot off with a reason, which the audit log keeps.
function KillSwitch({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const qc = useQueryClient();
  const settings = useQuery(settingsQuery);
  const [reason, setReason] = useState('');
  const save = useMutation({
    mutationFn: () =>
      api('PUT', '/api/settings/autopilot', {
        ...settings.data,
        mode: 'off',
        reason,
      }),
    onSuccess: () => (void qc.invalidateQueries({ queryKey: ['autopilot'] }), onDone(), onClose()),
  });
  return (
    <Modal title="Turn autopilot off?" onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), save.mutate())}>
        <p>
          Every autopilot rule is retired and leaves the edges in one publish, and open cases are cancelled. Your own rules don't change. It stays off until someone turns it on in
          the settings.
        </p>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-heading">Reason</span>
          <textarea rows={3} maxLength={500} required value={reason} onChange={(e) => setReason(e.target.value)} placeholder="such as: it blocked a partner" />
          <span className="text-body">Kept in the audit log.</span>
        </label>
        <ErrorBox error={save.error ?? settings.error} />
        <div className="flex flex-wrap justify-end gap-2">
          <Button data-autofocus onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="danger-solid" disabled={!reason.trim() || !settings.data || save.isPending}>
            Turn autopilot off
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function LiveRules({ rules, find, range }: { rules: RuleView[]; find: string; range: Range | undefined }) {
  useTick(15_000);
  return (
    <Card
      title="Live rules"
      intro="The autopilot's rules on the edges or waiting to publish. A sensor only logs. An enforce rule logs first, then blocks once its counts hold."
      info="Each runs after your rules until it expires, and is renewed only while it is still needed."
    >
      {rules.length === 0 ? (
        <p className="text-body">{find ? `No live autopilot rule matches “${find}”.` : 'No autopilot rule is live.'}</p>
      ) : (
        <ul aria-label="Live autopilot rules" className="grid gap-3 md:grid-cols-2">
          {rules.map((r) => (
            <li key={r.id} className="flex flex-col gap-1.5 rounded-control p-3 text-sm shadow-field">
              <span className="flex flex-wrap items-baseline gap-2">
                <Link to={`/autopilot/cases/${r.case_id}`} className="font-mono font-medium text-heading underline">
                  {r.id}
                </Link>
                <Badge tone={r.state === 'enforcing' ? 'red' : r.state === 'observing' ? 'amber' : 'slate'}>
                  {r.kind === 'sensor' ? 'sensor' : 'enforce rule'}, {states[r.state] ?? r.state}
                </Badge>
              </span>
              <code className="wrap-anywhere text-body">{r.expression}</code>
              <span className="text-body">
                Over {n(r.limit)} per {short(r.period)} by {r.key.join(' + ')}
                {r.shadow_ratio !== null && `; while logging it was over the limit for ${+(r.shadow_ratio * 100).toFixed(2)}% of the requests it checked, an exact count`}
              </span>
              {range && <LiveCounts r={range} id={r.id} />}
              {r.expires_at && (
                <span className={new Date(r.expires_at) <= new Date() ? 'text-warning' : 'text-body'}>
                  Expires <time title={when(r.expires_at)}>{ago(r.expires_at)}</time>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

// LiveCounts is how often a live rule found a client over its limit in the
// range, while logging and while blocking. The text carries the numbers.
function LiveCounts({ r, id }: { r: Range; id: string }) {
  const c = ruleCounts(r.rows, id);
  return (
    <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-body">
      <span>Over its limit {r.phrase}:</span>
      <span className="flex items-center gap-1.5">
        <Spark rows={r.rows} from={r.from} to={r.to} value={(x) => ruleCounts([x], id).would_limit} />
        {count(c.would_limit)} while logging
      </span>
      <span className="flex items-center gap-1.5">
        <Spark rows={r.rows} from={r.from} to={r.to} value={(x) => ruleCounts([x], id).limited} />
        {count(c.limited)} blocking
      </span>
    </span>
  );
}

function Cases({ rule }: { rule: string }) {
  const q = useQuery({
    queryKey: ['autopilot', 'cases', rule],
    queryFn: () => api<CaseRow[]>('GET', `/api/autopilot/cases${rule ? `?rule=${encodeURIComponent(rule)}` : ''}`),
    refetchInterval: 30_000,
  });
  return (
    <Card title={rule ? `Cases on rule ${rule}` : 'Cases'} intro="The latest 20 questions the model answered or will answer, newest first.">
      {!q.data ? (
        <Pending error={q.error} />
      ) : (
        <Table head={['Case', 'Trigger', 'State', 'Verdict', 'Opened']} empty={rule ? `No case on rule ${rule}.` : 'No cases yet.'}>
          {q.data.slice(0, 20).map((c) => (
            <tr key={c.id} className="align-top">
              <td className="px-3 py-2.5">
                <Link to={`/autopilot/cases/${c.id}`} className="font-medium text-heading underline">
                  Case {c.id}
                </Link>
              </td>
              <td className="px-3 py-2.5 whitespace-normal">
                {kinds[c.kind] ?? c.kind} <Target c={c} />
              </td>
              <td className="px-3 py-2.5">{c.state}</td>
              <td className="px-3 py-2.5">{c.verdict ? (verdicts[c.verdict] ?? c.verdict) : ''}</td>
              <td className="px-3 py-2.5" title={when(c.created_at)}>
                {ago(c.created_at)} by {who(c.opened_by)}
              </td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

function SpendCard({ spend, days }: { spend: State['spend']; days: SpendDay[] }) {
  return (
    <Card
      title="Spend"
      intro="What finished runs cost, by when they started."
      info="At your prices is the token counts the runner reported times the price in effect when each run started: exact for your price table. The provider's figure is the runner's report of the provider's own estimate. A model with no price still runs."
    >
      <dl className="grid gap-4 sm:grid-cols-2">
        {(
          [
            ['Last 24 hours', spend.last_24h],
            ['Last 7 days', spend.last_7d],
          ] as const
        ).map(([label, s]) => (
          <div key={label} className="flex flex-col gap-0.5 text-sm">
            <dt className="eyebrow text-muted">{label}</dt>
            <dd className="text-2xl font-semibold text-heading tabular-nums">{usd(s.configured_usd_micros)}</dd>
            <dd className="text-body">
              at your prices, over {n(s.runs)} {s.runs === 1 ? 'run' : 'runs'}
              {s.unpriced_runs > 0 && `; ${n(s.unpriced_runs)} with no price are left out`}
            </dd>
            <dd className="text-body">{usd(s.provider_usd_micros)} by the provider's estimate</dd>
          </div>
        ))}
      </dl>
      <h3 className="mt-6 mb-2">By day and model</h3>
      <p className="mb-3 text-sm text-body">The last 14 days by UTC day. A retried case counts once in cases.</p>
      <Table head={['Day', 'Model', 'Runs', 'Cases', 'At your prices', 'Per case', "Provider's estimate"]} num={[2, 3, 4, 5, 6]} empty="No run finished in the last 14 days.">
        {days.map((d) => (
          <tr key={`${d.day} ${d.provider} ${d.model}`}>
            <td className="px-3 py-2.5 tabular-nums">{d.day}</td>
            <td className="px-3 py-2.5 whitespace-normal">
              {d.model} <span className="text-muted">on {d.provider}</span>
            </td>
            <td className="px-3 py-2.5 text-right tabular-nums">{n(d.runs)}</td>
            <td className="px-3 py-2.5 text-right tabular-nums">{n(d.cases)}</td>
            <td className="px-3 py-2.5 text-right tabular-nums">{usd(d.configured_usd_micros)}</td>
            <td className="px-3 py-2.5 text-right tabular-nums">{d.unpriced_runs > 0 ? `n/a: ${n(d.unpriced_runs)} unpriced` : usd(Math.round(d.configured_usd_micros / d.cases))}</td>
            <td className="px-3 py-2.5 text-right tabular-nums">{usd(d.provider_usd_micros)}</td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}

function Precision({ rows }: { rows: State['precision'] }) {
  return (
    <Card
      title="Precision"
      intro="How enforce rules that ended in the last 7 days turned out, per model and prompt. Exact counts."
      info="Right: it ran out after blocking, or a person adopted it. Wrong: its guard rolled it back, or a person marked it a false positive. Rules retired for another reason, or rejected before they blocked, are not counted. The prompt is named by the first characters of its SHA-256."
    >
      <Table head={['Model', 'Prompt', 'Right', 'Wrong', 'Share right']} num={[2, 3, 4]} empty="No enforce rule ended in the last 7 days.">
        {rows.map((r) => (
          <tr key={r.model + r.prompt_sha256}>
            <td className="px-3 py-2.5">{r.model}</td>
            <td className="px-3 py-2.5">
              <code title={r.prompt_sha256}>{r.prompt_sha256.slice(0, 12)}</code>
            </td>
            <td className="px-3 py-2.5 text-right tabular-nums">{r.correct}</td>
            <td className="px-3 py-2.5 text-right tabular-nums">{r.wrong}</td>
            <td className="px-3 py-2.5 text-right tabular-nums">{Math.round((r.correct / (r.correct + r.wrong)) * 100)}%</td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}

// issuesAt is a save's errors for one setting, and the items inside it.
const issuesAt = (error: unknown) => (path: string) => (error instanceof Problem ? error.errors.filter((i) => i.path === path || i.path.startsWith(`${path}[`)) : ([] as Issue[]));

// SettingsCard saves the autopilot settings on their own, outside the draft.
// Off goes through Turn autopilot off, which asks for a reason.
function SettingsCard({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery(settingsQuery);
  // Only changed fields, so a mode changed elsewhere (Turn autopilot off) is not saved back over.
  const [edit, setEdit] = useState<Partial<Settings>>();
  useLeaveGuard(edit ? 'The autopilot settings have changes that are not saved. Leave and lose them?' : undefined);
  const save = useMutation({
    mutationFn: () => api('PUT', '/api/settings/autopilot', { ...q.data, ...edit }),
    onSuccess: () => (setEdit(undefined), qc.invalidateQueries({ queryKey: ['autopilot'] })),
  });
  if (!q.data) return <Pending error={q.error} />;
  const v: Settings = { ...q.data, ...edit };
  const set = (k: string, x: Json) => setEdit({ ...edit, [k]: x });
  const at = issuesAt(save.error);
  const hours = timeUnits.slice(0, 3);
  const mins = timeUnits.slice(1, 3);
  const fieldErrors = save.error instanceof Problem && save.error.errors.length > 0;
  return (
    <Card title="Settings" intro="What the autopilot may do. Saved on their own, not with the draft, and audited; they apply from the next run, within 30 seconds.">
      <fieldset disabled={!canManage} className="flex flex-col gap-5 text-sm">
        <Labeled
          label="Mode"
          issues={at('mode')}
          hint={q.data.mode === 'off' ? 'Off: pick observe or auto to turn it on.' : 'To turn it off, use Turn autopilot off above, which asks for a reason.'}
        >
          <Choice value={v.mode} options={q.data.mode === 'off' ? ['off', 'observe', 'auto'] : ['observe', 'auto']} labels={modes} onChange={(m) => set('mode', m)} />
        </Labeled>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Labeled label="Enforce rules at once" hint="Proposed, logging or blocking, 0 to 50." issues={at('max_enforcing')}>
            <Count value={v.max_enforcing} onChange={(x) => set('max_enforcing', x)} />
          </Labeled>
          <Labeled label="Sensors at once" hint="Proposed or logging, 0 to 50." issues={at('max_sensors')}>
            <Count value={v.max_sensors} onChange={(x) => set('max_sensors', x)} />
          </Labeled>
          <Labeled label="Cases started an hour" hint="1 to 200." issues={at('cases_per_hour')}>
            <Count value={v.cases_per_hour} min={1} onChange={(x) => set('cases_per_hour', x)} />
          </Labeled>
          <Labeled label="Log before blocking for" hint="How long an enforce rule only logs, 1 minute to 1 hour." issues={at('observe_for')}>
            <Amount value={v.observe_for} units={mins} fallback="m" duration onChange={(x) => set('observe_for', x)} />
          </Labeled>
          <Labeled label="Default TTL" hint="A rule's TTL when the model sets none, and an enforce rule's renewal." issues={at('default_ttl')}>
            <Amount value={v.default_ttl} units={hours} fallback="m" duration onChange={(x) => set('default_ttl', x)} />
          </Labeled>
          <Labeled label="Longest TTL" hint="At most 24 hours; a sensor renews by this much." issues={at('max_ttl')}>
            <Amount value={v.max_ttl} units={hours} fallback="h" duration onChange={(x) => set('max_ttl', x)} />
          </Labeled>
          <Labeled
            label="Longest lifetime"
            hint="How long renewals may keep a rule, up to 30 days. A rule marked wrong is not proposed again for this long."
            issues={at('max_lifetime')}
          >
            <Amount value={v.max_lifetime} units={hours} fallback="h" duration onChange={(x) => set('max_lifetime', x)} />
          </Labeled>
          <Labeled
            label="Least time between publishes"
            hint="For publishes that add or renew rules, 30 seconds to 15 minutes. Removals don't wait."
            issues={at('min_publish_interval')}
          >
            <Amount value={v.min_publish_interval} units={mins} fallback="m" duration onChange={(x) => set('min_publish_interval', x)} />
          </Labeled>
          <div className="flex flex-col gap-1">
            <Decimal label="Most of the fleet one rule may block" value={v.max_block_share} kind="ratio" onChange={(x) => set('max_block_share', x)} />
            <span className="text-body">Besides its heavy subjects, 0.1% to 20%.</span>
            <Errors issues={at('max_block_share')} />
          </div>
          <Labeled label="Model" hint="For cases a person or an anomaly opens. An ID with claude runs on a claude credential, any other on openai." issues={at('model')}>
            <input value={v.model} onChange={(e) => set('model', e.target.value)} />
          </Labeled>
          <Labeled label="Sweep and review model" hint="For the hourly sweep and the daily review." issues={at('sweep_model')}>
            <input value={v.sweep_model} onChange={(e) => set('sweep_model', e.target.value)} />
          </Labeled>
        </div>
        <Lines
          label="Protected subjects"
          item="Protected subject"
          noun="protected subject"
          values={v.protected_subjects}
          onChange={(x) => set('protected_subjects', x)}
          at={at}
          path="protected_subjects"
          placeholder="such as 203.0.113.0/24"
          hint="IPs, CIDRs or AS numbers no autopilot rule may block, up to 200. Your own rules still apply to them."
        />
      </fieldset>
      <div className="mt-4 flex flex-col items-start gap-2">
        {fieldErrors ? (
          <p role="alert" className="text-sm text-danger">
            Not saved: fix the settings marked above.
          </p>
        ) : (
          <ErrorBox error={save.error} />
        )}
        {save.isSuccess && !edit && <Notice>Autopilot settings saved.</Notice>}
        <ConfirmButton
          variant="primary"
          title="Save autopilot settings?"
          action="Save autopilot settings"
          confirm="They apply from the autopilot's next run. Rules already live keep the expiry they have."
          disabled={!canManage || !edit || save.isPending}
          onConfirm={() => save.mutate()}
        >
          Save autopilot settings
        </ConfirmButton>
        {edit && <Button onClick={() => (setEdit(undefined), save.reset())}>Discard changes</Button>}
        <Hint>{!canManage ? 'Your role cannot change the autopilot settings.' : undefined}</Hint>
      </div>
    </Card>
  );
}

const priceFields = [
  ['input_usd_per_mtok', 'Input'],
  ['output_usd_per_mtok', 'Output'],
  ['cache_read_usd_per_mtok', 'Cache read'],
  ['cache_write_usd_per_mtok', 'Cache write'],
] as const;

// localNow is the current minute as a datetime-local value.
const localNow = () => {
  const d = new Date();
  d.setSeconds(0, 0);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
};

function Prices({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ['autopilot', 'prices'],
    queryFn: () => api<Price[]>('GET', '/api/autopilot/prices'),
  });
  const [p, setP] = useState<Record<string, string>>({
    provider: 'claude',
    model: '',
    from: localNow(),
  });
  const add = useMutation({
    mutationFn: () =>
      api('POST', '/api/autopilot/prices', {
        provider: p.provider,
        model: p.model,
        effective_from: p.from ? new Date(p.from).toISOString() : '',
        ...Object.fromEntries(priceFields.map(([k]) => [k, Number(p[k] ?? '')])),
      }),
    onSuccess: () => (setP({ provider: p.provider ?? 'claude', model: '', from: localNow() }), qc.invalidateQueries({ queryKey: ['autopilot'] })),
  });
  const at = issuesAt(add.error);
  const usdOf = (x: number) =>
    x.toLocaleString('en-US', {
      style: 'currency',
      currency: 'USD',
      maximumFractionDigits: 4,
    });
  return (
    <Card
      title="Model prices"
      intro="USD per million tokens. A run is priced at the price in effect when it started; a price is never changed, a new one takes over from its time."
    >
      {!q.data ? (
        <Pending error={q.error} />
      ) : (
        <Table head={['Model', 'Provider', ...priceFields.map(([, l]) => l), 'From', 'By']} num={[2, 3, 4, 5]} empty="No prices yet, so spend at your prices is $0.00.">
          {q.data.map((x) => (
            <tr key={x.id}>
              <td className="px-3 py-2.5">{x.model}</td>
              <td className="px-3 py-2.5">{x.provider}</td>
              {priceFields.map(([k]) => (
                <td key={k} className="px-3 py-2.5 text-right tabular-nums">
                  {usdOf(x[k])}
                </td>
              ))}
              <td className="px-3 py-2.5">{when(x.effective_from)}</td>
              <td className="px-3 py-2.5">{who(x.author)}</td>
            </tr>
          ))}
        </Table>
      )}
      {canManage && (
        <form className="mt-4 flex flex-col gap-3 text-sm" onSubmit={(e) => (e.preventDefault(), add.mutate())}>
          <h3 className="font-medium text-heading">Add a price</h3>
          <div className="flex flex-wrap items-start gap-4">
            <Labeled label="Provider" issues={at('provider')}>
              <Choice value={p.provider} options={['claude', 'openai']} labels={{}} onChange={(x) => setP({ ...p, provider: x ?? '' })} />
            </Labeled>
            <Labeled label="Model ID" issues={at('model')}>
              <input value={p.model} onChange={(e) => setP({ ...p, model: e.target.value })} placeholder="such as claude-opus-5-5" />
            </Labeled>
            {priceFields.map(([k, l]) => (
              <Labeled key={k} label={l} issues={at(k)}>
                <input type="number" inputMode="decimal" min={0} step="any" className="w-28" value={p[k] ?? ''} onChange={(e) => setP({ ...p, [k]: e.target.value })} />
              </Labeled>
            ))}
            <Labeled label="From" issues={at('effective_from')}>
              <input type="datetime-local" value={p.from} onChange={(e) => setP({ ...p, from: e.target.value })} />
            </Labeled>
          </div>
          {!(add.error instanceof Problem && add.error.errors.length) && <ErrorBox error={add.error} />}
          <div>
            <Button type="submit" disabled={add.isPending}>
              Add price
            </Button>
          </div>
        </form>
      )}
    </Card>
  );
}

// AutopilotCase reads one case as a story: what started it, what the model
// looked at and said, what admin's checks made of its proposals, what you
// can do about the rules it made, and what it cost.
export function AutopilotCase({ id }: { id: number }) {
  const q = useQuery({
    queryKey: ['autopilot', 'case', id],
    queryFn: () => api<CaseRead>('GET', `/api/autopilot/cases/${id}`),
    // An open case changes as the runner works on it, and a proposed rule
    // goes live on the next autopilot run, within 30 seconds.
    refetchInterval: (x) => {
      const d = x.state.data;
      return d && !['queued', 'running'].includes(d.case.state) && !d.rules.some((r) => r.state === 'proposed') ? 30_000 : 2_000;
    },
  });
  // The draft lists the live autopilot rules Adopt can copy. A rule that went
  // live after the draft loaded needs a fresh one.
  const qc = useQueryClient();
  const draft = useOptionalDraft();
  const published = (q.data?.rules ?? []).filter((r) => ['observing', 'enforcing'].includes(r.state)).map((r) => r.id);
  const missing = published.filter((id) => !draft?.draft.overlay.some((x) => x.id === id)).join(' ');
  const hasDraft = !!draft;
  // Once per change of the missing set, so a rule the draft can't show
  // doesn't refetch it in a loop.
  useEffect(() => {
    if (missing && hasDraft) void qc.invalidateQueries({ queryKey: draftKey });
  }, [missing, hasDraft, qc]);
  if (!q.data)
    return q.error instanceof Problem && q.error.status === 404 ? <NotFound title="Case not found" back={['/autopilot', 'Back to the autopilot']} /> : <Pending error={q.error} />;
  const { case: c, runs, proposals, tool_calls: calls, rules, transitions } = q.data;
  const evidence = proposals.filter((p) => p.evidence && typeof p.evidence === 'object' && Object.keys(p.evidence).length > 0);
  return (
    <Page title={`Case ${c.id}`} actions={<Replay id={c.id} last={runs.at(-1)} />}>
      <p className="-mt-3">
        <Link to="/autopilot" className="text-sm text-body underline">
          Autopilot
        </Link>
      </p>
      <Card title="Trigger">
        <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
          <dt className="text-body">What</dt>
          <dd className="text-heading">
            {kinds[c.kind] ?? c.kind} <Target c={c} />
          </dd>
          {c.question && (
            <>
              <dt className="text-body">Question</dt>
              <dd className="wrap-anywhere text-heading">{c.question}</dd>
            </>
          )}
          <dt className="text-body">Opened</dt>
          <dd>
            <time title={when(c.created_at)}>{ago(c.created_at)}</time> by {who(c.opened_by)}
          </dd>
          <dt className="text-body">State</dt>
          <dd>
            {c.state}
            {c.attempts > 1 && `, attempt ${c.attempts}`}
          </dd>
        </dl>
      </Card>
      <Card title="Evidence" intro="What the model cited for each rule it proposed, as it wrote it.">
        {evidence.length === 0 ? (
          <p className="text-body">{proposals.length ? 'The proposals cite no evidence.' : 'The model proposed nothing.'}</p>
        ) : (
          evidence.map((p) => (
            <div key={p.id} className="mb-3 flex flex-col gap-1 text-sm last:mb-0">
              <p className="text-heading">
                <span className="text-body">{p.accepted ? `For ${p.rule_id ?? 'its proposal'}: ` : 'For a refused proposal: '}</span>
                {p.rationale}
              </p>
              <pre className="wrap-anywhere whitespace-pre-wrap">{json(p.evidence)}</pre>
            </div>
          ))
        )}
      </Card>
      <Card title="Tool calls" intro="Every call the model made to admin, in order, with what admin answered.">
        {calls.length === 0 ? (
          <p className="text-body">No tool calls yet.</p>
        ) : (
          <ol className="flex flex-col gap-1 text-sm">
            {calls.map((t) => (
              <li key={`${t.run_id}-${t.seq}`}>
                {t.payload.cut ? (
                  <p className="rounded-control px-3 py-1.5 text-body shadow-field">
                    Too large to keep: {t.payload.bytes} bytes, SHA-256 <span className="font-mono wrap-anywhere">{t.payload.sha256}</span>
                    {runs.length > 1 && `, run ${t.run_id}`}
                  </p>
                ) : (
                  <details className="rounded-control shadow-field">
                    <summary className="cursor-pointer px-3 py-1.5">
                      <span className="font-mono text-heading">{t.payload.tool ?? 'call'}</span>
                      {t.payload.allowed === false && ' refused'}
                      <span className="text-body">
                        , {t.payload.duration_ms ?? 0} ms
                        {runs.length > 1 && `, run ${t.run_id}`}
                      </span>
                    </summary>
                    <div className="flex flex-col gap-2 border-t border-line p-3">
                      {/* A hidden connector call has no arguments: its query is part of the answer. */}
                      {t.payload.arguments !== undefined && (
                        <>
                          <p className="text-body">Arguments</p>
                          <pre className="wrap-anywhere whitespace-pre-wrap">{json(t.payload.arguments)}</pre>
                        </>
                      )}
                      <p className="text-body">{t.payload.refusal ? 'Refused' : 'Answer'}</p>
                      {t.payload.hidden ? (
                        <p className="text-body">Answer hidden: it {t.payload.hidden_reason}</p>
                      ) : (
                        <pre className="max-h-96 wrap-anywhere whitespace-pre-wrap">{t.payload.refusal ?? json(t.payload.result ?? null)}</pre>
                      )}
                    </div>
                  </details>
                )}
              </li>
            ))}
          </ol>
        )}
      </Card>
      <Card title="Verdict">
        {c.verdict ? (
          <div className="flex flex-col gap-1 text-sm">
            <p>
              <Badge tone={c.verdict === 'attack' ? 'red' : c.verdict === 'benign' ? 'green' : 'amber'}>{verdicts[c.verdict] ?? c.verdict}</Badge>
            </p>
            <p className="text-heading">{c.summary}</p>
          </div>
        ) : (
          <p className="text-body">{['queued', 'running'].includes(c.state) ? 'No verdict yet: the case is still open.' : `No verdict: the case ${c.state}.`}</p>
        )}
      </Card>
      <Card title="Policy checks" intro="Admin's checks on each proposal. A refused proposal never reaches an edge.">
        {proposals.length === 0 ? (
          <p className="text-body">No proposals.</p>
        ) : (
          <ul className="flex flex-col gap-4 text-sm">
            {proposals.map((p) => (
              <li key={p.id} className="flex flex-col gap-1">
                <span className="flex flex-wrap items-baseline gap-2">
                  <span className="font-medium text-heading">
                    {{
                      add_sensor: 'Add a sensor',
                      enforce: 'Enforce rule',
                      retire: 'Retire',
                    }[p.action] ?? p.action}
                  </span>
                  <Badge tone={p.accepted ? 'green' : 'red'}>{p.accepted ? 'accepted' : 'refused'}</Badge>
                  {p.rule_id && <span className="font-mono">{p.rule_id}</span>}
                  {p.ttl_seconds !== null && <span className="text-body">for {seconds(p.ttl_seconds)} unless renewed</span>}
                </span>
                {p.rule.expression && <code className="wrap-anywhere text-body">{p.rule.expression}</code>}
                <ul className="flex flex-col gap-0.5">
                  {p.checks.map((x) => (
                    <li key={x.name} className={x.ok ? 'text-body' : 'text-danger'}>
                      {x.ok ? 'Passed' : 'Failed'}: {checks[x.name] ?? x.name.replaceAll('_', ' ')}
                      {x.detail && ` (${x.detail})`}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Actions" intro="The rules this case made, and what you can do about each.">
        {rules.length === 0 ? (
          <p className="text-body">This case made no rule.</p>
        ) : (
          rules.map((r) => <RuleActions key={r.id} r={r} history={transitions.filter((t) => t.rule_id === r.id)} />)
        )}
      </Card>
      <Card title="Cost" info="Token counts are what the runner reported. At your prices is exact for your price table; the provider's figure is its own estimate.">
        {runs.length === 0 ? (
          <p className="text-body">No run yet.</p>
        ) : (
          <Table head={['Run', 'Model', 'Result', 'Tokens in', 'Out', 'Cache read', 'Cache write', 'At your prices', "Provider's estimate"]} num={[3, 4, 5, 6, 7, 8]}>
            {runs.map((r) => (
              <tr key={r.id} className="align-top">
                <td className="px-3 py-2.5 whitespace-normal">
                  {r.attempt > 1 ? `Attempt ${r.attempt}` : 'Run'} on {r.runner}, <time title={when(r.started_at)}>{ago(r.started_at)}</time>
                </td>
                <td className="px-3 py-2.5 whitespace-normal">
                  {r.model}
                  <br />
                  <code className="text-xs text-muted" title={`prompt SHA-256 ${r.prompt_sha256}`}>
                    prompt {r.prompt_sha256.slice(0, 12)}
                  </code>
                  <br />
                  <code className="text-xs text-muted" title={`tools SHA-256 ${r.tools_sha256}`}>
                    tools {r.tools_sha256.slice(0, 12)}
                  </code>
                </td>
                <td className="px-3 py-2.5 whitespace-normal">
                  {r.status ?? 'running'}
                  {r.error_category && `: ${r.error_category}`}
                  {r.turns !== null && `, ${r.turns} turns, ${r.tool_calls} tool calls`}
                  {r.telemetry_complete === false && ', some runner events missing'}
                </td>
                <td className="px-3 py-2.5 text-right tabular-nums">{n(r.input_tokens)}</td>
                <td className="px-3 py-2.5 text-right tabular-nums">{n(r.output_tokens)}</td>
                <td className="px-3 py-2.5 text-right tabular-nums">{n(r.cache_read_tokens)}</td>
                <td className="px-3 py-2.5 text-right tabular-nums">{n(r.cache_write_tokens)}</td>
                <td className="px-3 py-2.5 text-right tabular-nums">{r.configured_cost_usd_micros === null ? 'no price' : usd(r.configured_cost_usd_micros)}</td>
                <td className="px-3 py-2.5 text-right tabular-nums">{r.provider_cost_usd_micros === null ? 'none' : usd(r.provider_cost_usd_micros)}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </Page>
  );
}

// Replay shows the command that answers this case's recorded tool calls to
// another model, on the person's own machine. Admin calls no model for it.
function Replay({ id, last }: { id: number; last: Run | undefined }) {
  const [open, setOpen] = useState(false);
  const [provider, setProvider] = useState(last?.provider ?? 'claude');
  const [model, setModel] = useState(last?.model ?? '');
  const command = `npm run replay -- ${id} --provider ${provider} --model ${model.trim() || '<model>'} --admin ${window.location.origin} --token-file <token file>`;
  return (
    <>
      <Button onClick={() => setOpen(true)}>Replay with another model</Button>
      {open && (
        <Modal title="Replay with another model" onClose={() => setOpen(false)}>
          <div className="flex flex-col gap-4 text-sm">
            <p>Replay answers the model with what admin answered this case's run, and reports where its verdict, tokens and cost differ. It never proposes or records anything.</p>
            <label className="flex flex-col gap-1">
              <span className="font-medium text-heading">Provider</span>
              <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                <option value="claude">Claude</option>
                <option value="openai">OpenAI</option>
              </select>
            </label>
            <Input label="Model" value={model} onChange={(e) => setModel(e.target.value)} spellCheck={false} />
            <p className="text-body">Run it in the runner's autopilot directory:</p>
            <pre className="wrap-anywhere whitespace-pre-wrap rounded-control p-3 shadow-field">{command}</pre>
            <p className="text-body">
              The token file holds an API token with autopilot.read, stats.read and config.read, and autopilot.manage for a run with connector calls, so replay can read the
              recorded answers; the provider's key comes from the same variables as the runner's.
            </p>
            <div className="flex justify-end">
              <Button data-autofocus onClick={() => setOpen(false)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}

// RuleActions is one rule a case made: where it stands, how it got there,
// and Approve, Retire, Mark false positive and Adopt where they apply.
function RuleActions({ r, history }: { r: RuleView; history: Transition[] }) {
  const can = useCan();
  const qc = useQueryClient();
  const draft = useOptionalDraft();
  const [retiring, setRetiring] = useState<'retire' | 'false_positive'>();
  const [excluding, setExcluding] = useState(false);
  const approve = useMutation({
    mutationFn: () => api('POST', `/api/autopilot/rules/${encodeURIComponent(r.id)}/enforce`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['autopilot'] }),
  });
  const mode = useQuery(autopilotQuery).data?.mode;
  const live = ['proposed', 'observing', 'enforcing'].includes(r.state);
  const manage = can('autopilot.manage');
  // A refusal names its check first, such as observed_too_short: …
  const tooEarly = 'observed_too_short: ';
  const refusal =
    approve.error instanceof Problem && approve.error.message.startsWith(tooEarly)
      ? new Problem(approve.error.status, 'Too early to approve', `too early to approve: ${approve.error.message.slice(tooEarly.length)}`)
      : approve.error;
  return (
    <section aria-label={r.id} className="mb-4 flex flex-col gap-2 border-b border-line pb-4 text-sm last:mb-0 last:border-0 last:pb-0">
      <span className="flex flex-wrap items-baseline gap-2">
        <span className="font-mono font-medium text-heading">{r.id}</span>
        <Badge tone={r.state === 'enforcing' ? 'red' : live ? 'amber' : 'slate'}>
          {r.kind === 'sensor' ? 'sensor' : 'enforce rule'}, {states[r.state] ?? r.state}
        </Badge>
        {r.outcome && <span className="text-body">{outcomes[r.outcome] ?? r.outcome}</span>}
        {live && r.expires_at && (
          <span className="text-body">
            expires <time title={when(r.expires_at)}>{ago(r.expires_at)}</time>
          </span>
        )}
      </span>
      <code className="wrap-anywhere text-body">{r.expression}</code>
      {history.length > 0 && (
        <ol className="flex flex-col gap-0.5 text-body">
          {history.map((t, i) => (
            <li key={i}>
              <time title={when(t.at)}>{ago(t.at)}</time>: {states[t.from_state] ?? t.from_state} to {states[t.to_state] ?? t.to_state}, {t.reason.replaceAll('_', ' ')} (
              {who(t.actor)})
            </li>
          ))}
        </ol>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {/* In auto mode it blocks on its own once its counts hold. */}
        {manage && mode === 'observe' && r.kind === 'enforce' && r.state === 'observing' && (
          <Button variant="primary" disabled={approve.isPending} onClick={() => approve.mutate()}>
            Approve blocking
          </Button>
        )}
        {manage && live && (
          <>
            <Button onClick={() => setRetiring('retire')}>Retire</Button>
            <Button variant="danger" onClick={() => setRetiring('false_positive')}>
              Mark false positive
            </Button>
            {r.kind === 'sensor' && r.state !== 'enforcing' && <Button onClick={() => setExcluding(true)}>Exclude a client</Button>}
          </>
        )}
        {live && draft?.draft.overlay.some((x) => x.id === r.id) && <AdoptButton id={r.id} />}
      </div>
      {approve.isSuccess && <Notice>Approved: it blocks from the next autopilot run if its counts still hold.</Notice>}
      <ErrorBox error={refusal} />
      {retiring && <Retire id={r.id} falsePositive={retiring === 'false_positive'} onClose={() => setRetiring(undefined)} />}
      {excluding && <ExcludeDialog r={r} onClose={() => setExcluding(false)} />}
    </section>
  );
}

function Retire({ id, falsePositive, onClose }: { id: string; falsePositive: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState('');
  const retire = useMutation({
    mutationFn: () =>
      api('POST', `/api/autopilot/rules/${encodeURIComponent(id)}/retire`, {
        reason,
        false_positive: falsePositive,
      }),
    onSuccess: () => (void qc.invalidateQueries({ queryKey: ['autopilot'] }), onClose()),
  });
  const what = falsePositive
    ? 'It leaves the edges on the next autopilot run, the autopilot does not propose the same rule again for the longest lifetime, and precision counts it as wrong.'
    : 'It leaves the edges on the next autopilot run.';
  return (
    <Modal title={falsePositive ? `Mark ${id} a false positive?` : `Retire ${id}?`} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), retire.mutate())}>
        <p>{what}</p>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-heading">Reason</span>
          <textarea rows={3} maxLength={500} required value={reason} onChange={(e) => setReason(e.target.value)} />
          <span className="text-body">Kept with the rule's history and in the audit log.</span>
        </label>
        <ErrorBox error={retire.error} />
        <div className="flex flex-wrap justify-end gap-2">
          <Button data-autofocus onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="danger-solid" disabled={!reason.trim() || retire.isPending}>
            {falsePositive ? 'Mark false positive' : 'Retire'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

const expiries = [
  ['720h', '30 days'],
  ['168h', '7 days'],
  ['2160h', '90 days'],
  ['', 'Never'],
] as const;

// ExcludeDialog promotes a client a sensor flagged to an exclusion. The
// sensor is retired with it, so the next sweep can watch the route again
// without the client.
function ExcludeDialog({ r, onClose }: { r: RuleView; onClose: () => void }) {
  const qc = useQueryClient();
  const range = useRange(useCan()('stats.read'));
  // Its most limited clients, only when the key starts with ip, which admin
  // puts first: then the display's first part is the client's address.
  const clients = new Map<string, number>();
  for (const row of r.key[0] === 'ip' ? range.rows : [])
    for (const t of row.top_limited ?? []) {
      if (t.rule !== r.id) continue;
      const ip = t.display.split(' ')[0]!;
      clients.set(ip, (clients.get(ip) ?? 0) + t.limited + (t.would_limit ?? 0));
    }
  const top = [...clients].sort((a, b) => b[1] - a[1]).slice(0, 5);
  const [subject, setSubject] = useState('');
  const [host, setHost] = useState(r.host);
  const [path, setPath] = useState(r.path_prefix);
  const [reason, setReason] = useState('');
  const [ttl, setTtl] = useState<string>('720h');
  const add = useMutation({
    mutationFn: () => api('POST', '/api/autopilot/exclusions', { subject, host, path_prefix: path, reason, rule_id: r.id, ...(ttl && { ttl }) }),
    onSuccess: () => (void qc.invalidateQueries({ queryKey: ['autopilot'] }), onClose()),
  });
  return (
    <Modal title={`Exclude a client from ${r.id}`} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={(e) => (e.preventDefault(), add.mutate())}>
        <p>
          Autopilot rules proposed from now on leave this client out on this host and path. This sensor is retired now, so the next sweep can watch the route
          again without the client. Your own rules still apply to it.
        </p>
        {top.length > 0 && (
          <div className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-heading">Over its limit most {range.phrase}, a sampled estimate</span>
            <ul className="flex flex-wrap gap-2">
              {top.map(([ip, n]) => (
                <li key={ip}>
                  <Button onClick={() => setSubject(ip)}>
                    {ip}: {count(n)}
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        )}
        <Input label="Client" hint="An IP, or a CIDR of at least /24 for IPv4 or /48 for IPv6." required value={subject} onChange={(e) => setSubject(e.target.value)} />
        <Input label="Host" required value={host} onChange={(e) => setHost(e.target.value)} />
        <Input label="Path prefix" hint="Empty for the whole host." value={path} onChange={(e) => setPath(e.target.value)} />
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-heading">Reason</span>
          <textarea rows={3} maxLength={500} required value={reason} onChange={(e) => setReason(e.target.value)} />
          <span className="text-body">Kept with the exclusion and in the audit log.</span>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-heading">Expires</span>
          <select value={ttl} onChange={(e) => setTtl(e.target.value)}>
            {expiries.map(([v, l]) => (
              <option key={l} value={v}>
                {l}
              </option>
            ))}
          </select>
        </label>
        <ErrorBox error={add.error} />
        <div className="flex flex-wrap justify-end gap-2">
          <Button data-autofocus onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={!subject.trim() || !host.trim() || !reason.trim() || add.isPending}>
            Exclude
          </Button>
        </div>
      </form>
    </Modal>
  );
}

const exclusionsQuery = { queryKey: ['autopilot', 'exclusions'], queryFn: () => api<Exclusion[]>('GET', '/api/autopilot/exclusions') };

// Exclusions lists the clients people found legitimate, active and ended
// in the last 30 days, with Revoke for the active ones.
function Exclusions({ canManage }: { canManage: boolean }) {
  const q = useQuery(exclusionsQuery);
  const [revoking, setRevoking] = useState<Exclusion>();
  const ended = (e: Exclusion) => e.revoked_at !== null || (e.expires_at !== null && new Date(e.expires_at) <= new Date());
  return (
    <Card
      title="Exclusions"
      intro="Clients a person found legitimate on a host and path. Every autopilot rule proposed while one is active leaves the client out; your own rules still apply to it."
      info="Add one from a sensor's case with Exclude a client. A revoked or expired exclusion stops applying to new rules, and the sensors that carry it are retired within a minute; enforce rules that carry it run until they end."
    >
      {!q.data ? (
        <Pending error={q.error} />
      ) : q.data.length === 0 ? (
        <p className="text-body">No exclusions in the last 30 days.</p>
      ) : (
        <Table head={['Client', 'Where', 'Reason', 'Added', 'Ends', '']}>
          {q.data.map((e) => (
            <tr key={e.id} className="align-top">
              <td className="px-3 py-2.5 font-mono">{e.subject}</td>
              <td className="px-3 py-2.5">
                {e.host}
                {e.path_prefix}
              </td>
              <td className="min-w-48 px-3 py-2.5 whitespace-normal">{e.reason}</td>
              <td className="px-3 py-2.5" title={when(e.created_at)}>
                {ago(e.created_at)} by {who(e.created_by)}
              </td>
              <td className="px-3 py-2.5">
                {e.revoked_at ? (
                  <span title={e.revoke_reason ?? ''}>
                    revoked {ago(e.revoked_at)} by {who(e.revoked_by ?? '')}
                  </span>
                ) : e.expires_at ? (
                  <span title={when(e.expires_at)}>
                    {ended(e) ? 'expired' : 'expires'} {ago(e.expires_at)}
                  </span>
                ) : (
                  'never'
                )}
              </td>
              <td className="px-3 py-2.5">{canManage && !ended(e) && <Button onClick={() => setRevoking(e)}>Revoke</Button>}</td>
            </tr>
          ))}
        </Table>
      )}
      {revoking && <RevokeExclusion e={revoking} onClose={() => setRevoking(undefined)} />}
    </Card>
  );
}

function RevokeExclusion({ e, onClose }: { e: Exclusion; onClose: () => void }) {
  const qc = useQueryClient();
  const [reason, setReason] = useState('');
  const revoke = useMutation({
    mutationFn: () => api('POST', `/api/autopilot/exclusions/${e.id}/revoke`, { reason }),
    onSuccess: () => (void qc.invalidateQueries({ queryKey: ['autopilot'] }), onClose()),
  });
  return (
    <Modal title={`Revoke the exclusion of ${e.subject}?`} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={(ev) => (ev.preventDefault(), revoke.mutate())}>
        <p>New autopilot rules count this client again. Sensors that leave it out are retired within a minute; enforce rules that leave it out run until they end.</p>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-heading">Reason</span>
          <textarea rows={3} maxLength={500} required value={reason} onChange={(ev) => setReason(ev.target.value)} />
          <span className="text-body">Kept with the exclusion and in the audit log.</span>
        </label>
        <ErrorBox error={revoke.error} />
        <div className="flex flex-wrap justify-end gap-2">
          <Button data-autofocus onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="danger-solid" disabled={!reason.trim() || revoke.isPending}>
            Revoke
          </Button>
        </div>
      </form>
    </Modal>
  );
}
