import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type ReactNode, useState } from 'react';
import { api, type Json, type JsonObject } from '../api';
import { useOptionalDraft } from '../draft';
import { Decimal } from '../GuardForm';
import { LogLink, useLogSearch } from '../logSearch';
import { Link, useLeaveGuard } from '../router';
import { Amount, Choice, Count, setField, timeUnits, without } from '../RuleForms';
import { Badge, Button, Card, Check, ConfirmButton, ErrorBox, Notice, Page, Pending, Table, ago, when } from '../ui';
import { Investigate } from './Autopilot';

// Notifications shows the anomalies admin found in the edges' stats and
// edits when each signal notifies, by default and per rule. The server
// checks the settings on save; its errors show by the Save button.

export interface Anomaly {
  id: number;
  signal: string;
  rule: string;
  phase: string;
  severity: string;
  state: 'pending' | 'firing' | 'resolved';
  started_at: string;
  fired_at: string | null;
  resolved_at: string | null;
  notified_at: string | null;
  summary: string;
  // The newest autopilot case opened for it, and why admin holds it back.
  case_id: number | null;
  case_state: string | null;
  case_verdict: string | null;
  withheld: '' | 'own_rule' | 'investigating' | 'benign';
}

const withheldWords = {
  own_rule: 'Not sent: the autopilot works its own rules',
  investigating: 'Not yet: the autopilot is investigating',
  benign: 'Not sent: the autopilot found it benign',
};

type Signal = JsonObject & { mode?: string; severity?: string };
type Kind = 'ratio' | 'factor' | 'ms' | 'count';
type Threshold = { key: string; label: string; kind: Kind };
// Where a signal applies: the fleet, or rules of these phases.
type Scope = 'fleet' | string[];

const num = (s: Signal, k: string) => (typeof s[k] === 'number' ? s[k] : undefined);
const pct = (x: number | undefined) => (x === undefined ? '…' : `${+(x * 100).toFixed(4)}%`);
const times = (x: number | undefined) => (x === undefined ? '…' : `${x}×`);
const atLeast = (s: Signal) => num(s, 'min_requests') ?? '…';

const factor = (label: string): Threshold => ({ key: 'factor', label, kind: 'factor' });
const floor: Threshold = { key: 'floor', label: 'Never below', kind: 'ratio' };
const least = (label: string): Threshold => ({ key: 'min_requests', label, kind: 'count' });
const events = (label: string): Threshold => ({ key: 'min_events', label, kind: 'count' });
const withEvents = (s: Signal) => ` With at least ${num(s, 'min_events') ?? 0} of them.`;

const all = ['config', 'rate_limit', 'request_headers'];
const outcomes = ['config', 'request_headers'];
const limits = ['rate_limit'];
// Rules that refuse requests: rate limits, and config rules with a block setting.
const blocking = ['config', 'rate_limit'];

// Each signal as the server checks it; when it trips, in words from the
// form's own values.
const signals: { name: string; label: string; scope: Scope; fields: Threshold[]; trips: (s: Signal) => string }[] = [
  {
    name: 'traffic_drop',
    label: 'Traffic dropped',
    scope: 'fleet',
    fields: [factor('Times fewer'), least('Least requests expected')],
    trips: (s) => `Trips when requests fall below 1/${num(s, 'factor') ?? '…'} of the baseline's rate, when the baseline gives at least ${atLeast(s)} for the window.`,
  },
  {
    name: 'traffic_surge',
    label: 'Traffic surged',
    scope: 'fleet',
    fields: [factor('Times more'), least('Least requests')],
    trips: (s) => `Trips when requests rise above ${times(num(s, 'factor'))} the baseline's rate, with at least ${atLeast(s)}.`,
  },
  {
    name: 'edge_5xx_ratio',
    label: 'Edge 5xx',
    scope: 'fleet',
    fields: [factor('Times the baseline share'), floor, least('Least requests'), events('Least 5xx')],
    trips: (s) => `Trips when 5xx the edge sends itself are over ${times(num(s, 'factor'))} their baseline share and over ${pct(num(s, 'floor'))} of requests.${withEvents(s)}`,
  },
  {
    name: 'upstream_5xx_ratio',
    label: 'Upstream 5xx',
    scope: 'fleet',
    fields: [factor('Times the baseline share'), floor, least('Least requests'), events('Least 5xx')],
    trips: (s) => `Trips when 5xx from the upstream are over ${times(num(s, 'factor'))} their baseline share and over ${pct(num(s, 'floor'))} of requests.${withEvents(s)}`,
  },
  {
    name: 'auth_failure_ratio',
    label: 'Auth failures',
    scope: 'fleet',
    fields: [factor('Times the baseline share'), floor, least('Least requests'), events('Least failed checks')],
    trips: (s) => `Trips when requests failing their token check are over ${times(num(s, 'factor'))} their baseline share and over ${pct(num(s, 'floor'))} of requests.${withEvents(s)}`,
  },
  {
    name: 'p99_latency',
    label: 'p99 latency',
    scope: 'fleet',
    fields: [factor('Times the baseline p99'), { key: 'floor_ms', label: 'Never below', kind: 'ms' }, least('Least requests')],
    trips: (s) => `Trips when p99 latency is over ${times(num(s, 'factor'))} the baseline's and over ${num(s, 'floor_ms') ?? '…'}ms.`,
  },
  {
    name: 'rule_stopped_matching',
    label: 'Rule stopped matching',
    scope: all,
    fields: [least('Least matches expected')],
    trips: (s) => `Trips when a rule matches nothing, though its baseline share of requests gives it at least ${atLeast(s)} for the window.`,
  },
  {
    name: 'rule_match_surge',
    label: 'Rule matches surged',
    scope: all,
    fields: [factor('Times more'), least('Least matches')],
    trips: (s) => `Trips when a rule matches over ${times(num(s, 'factor'))} its baseline share of requests, at least ${atLeast(s)} times.`,
  },
  {
    name: 'rule_edge_5xx_ratio',
    label: 'Edge 5xx on a rule',
    scope: outcomes,
    fields: [factor('Times the baseline share'), floor, least('Least matches'), events('Least 5xx')],
    trips: (s) => `Trips when 5xx the edge sends are over ${times(num(s, 'factor'))} their baseline share of a rule's requests, over ${times(num(s, 'factor'))} their share of all requests, and over ${pct(num(s, 'floor'))}.${withEvents(s)}`,
  },
  {
    name: 'rule_upstream_5xx_ratio',
    label: 'Upstream 5xx on a rule',
    scope: outcomes,
    fields: [factor('Times the baseline share'), floor, least('Least matches'), events('Least 5xx')],
    trips: (s) => `Trips when 5xx from the upstream are over ${times(num(s, 'factor'))} their baseline share of a rule's requests, over ${times(num(s, 'factor'))} their share of all requests, and over ${pct(num(s, 'floor'))}.${withEvents(s)}`,
  },
  {
    name: 'rule_auth_failure_ratio',
    label: 'Auth failures on a rule',
    scope: ['config'],
    fields: [factor('Times the baseline share'), floor, least('Least matches'), events('Least failed checks')],
    trips: (s) => `Trips when failed token checks are over ${times(num(s, 'factor'))} their baseline share of a config rule's requests, over ${times(num(s, 'factor'))} their share of all requests, and over ${pct(num(s, 'floor'))}.${withEvents(s)}`,
  },
  {
    name: 'rule_block_spike',
    label: 'Rule blocking more',
    scope: blocking,
    fields: [factor('Times the baseline share'), floor, least('Least requests checked')],
    trips: (s) => `Trips when a rate limit rule, or a config rule set to block, blocks over ${times(num(s, 'factor'))} its baseline share of the requests it checks and over ${pct(num(s, 'floor'))}.`,
  },
  {
    name: 'rule_would_block',
    label: 'Log-only rule would block',
    scope: blocking,
    fields: [least('Least requests it would block')],
    trips: (s) => `Trips when a rule that isn't blocking (set to log only, or under the kill switch) would block at least ${atLeast(s)} requests.`,
  },
  {
    name: 'rule_fail_mode',
    label: 'Rule in fail mode',
    scope: limits,
    fields: [least('Least requests')],
    trips: (s) => `Trips when at least ${atLeast(s)} requests take a rule's fail mode because Valkey did not answer.`,
  },
  {
    name: 'rule_subject_dominates',
    label: 'One client gets most blocks',
    scope: limits,
    fields: [{ key: 'max_share', label: 'Most share for one client', kind: 'ratio' }, least('Least blocks')],
    trips: (s) => `Trips when one client gets over ${pct(num(s, 'max_share'))} of a rule's blocks, with at least ${atLeast(s)} blocks.`,
  },
];

export const label = (name: string) => signals.find((s) => s.name === name)?.label ?? name.replaceAll('_', ' ');
// The fleet signal each rule signal is listed under. A rule signal fires
// only when the rule is out of line with the fleet, so under a firing fleet
// signal it shows where that signal is concentrated, not a cause.
const parentOf: Record<string, string> = {
  rule_edge_5xx_ratio: 'edge_5xx_ratio',
  rule_upstream_5xx_ratio: 'upstream_5xx_ratio',
  rule_auth_failure_ratio: 'auth_failure_ratio',
  rule_match_surge: 'traffic_surge',
  rule_stopped_matching: 'traffic_drop',
};

// groupAnomalies puts each open rule anomaly under its open fleet anomaly,
// so one fleet problem reads as one line. Order is kept.
export function groupAnomalies(list: Anomaly[]) {
  const open = (a: Anomaly) => a.state !== 'resolved';
  const fleet = new Map(list.filter((a) => !a.rule && open(a)).map((a) => [a.signal, a]));
  const under = new Map<number, Anomaly[]>();
  const top: Anomaly[] = [];
  for (const a of list) {
    const p = a.rule && open(a) ? fleet.get(parentOf[a.signal] ?? '') : undefined;
    if (p) under.set(p.id, [...(under.get(p.id) ?? []), a]);
    else top.push(a);
  }
  return top.map((a) => ({ a, under: under.get(a.id) ?? [] }));
}

// anomaliesQuery is shared with the dashboard, which lists the firing ones.
export const anomaliesQuery = {
  queryKey: ['anomalies'],
  queryFn: () => api<{ alertmanager: boolean; anomalies: Anomaly[] }>('GET', '/api/anomalies'),
  refetchInterval: 30_000,
};

const modes = { notify: 'Notify', off: 'Off' };
const severities = { critical: 'Critical', warning: 'Warning', info: 'Info' };
const phaseNames: Record<string, string> = { config: 'config', rate_limit: 'rate limit', request_headers: 'request header' };

// where names a settings path in the page's words, for the server's errors.
function where(path: string) {
  const [, rule, name] = /^rules\.(.+)\.(\w+)/.exec(path) ?? [];
  if (rule && name) return `${label(name)} for rule ${rule}`;
  const sig = /^signals\.(\w+)/.exec(path)?.[1];
  if (sig) return label(sig);
  return { window: 'Window', baseline: 'Baseline', fire_after: 'Notify after or Resolve after', rules: 'Per-rule settings' }[path] ?? path;
}

function SignalFields({ name, value, onChange }: { name: string; value: Signal; onChange: (v: Signal) => void }) {
  const sig = signals.find((s) => s.name === name)!;
  const set = (k: string, v: Json) => onChange(setField(value, k, v));
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-4">
        <label className="flex items-center gap-2">
          <span className="text-body">
            <span className="sr-only">{sig.label}, </span>When it trips
          </span>
          <Choice value={value.mode} options={Object.keys(modes)} labels={modes} onChange={(m) => set('mode', m)} />
        </label>
        {value.mode !== 'off' && (
          <label className="flex items-center gap-2">
            <span className="text-body">
              <span className="sr-only">{sig.label}, </span>Severity
            </span>
            <Choice value={value.severity} options={Object.keys(severities)} labels={severities} onChange={(v) => set('severity', v)} />
          </label>
        )}
      </div>
      {value.mode !== 'off' && (
        <>
          <p className="text-body">{sig.trips(value)}</p>
          <div className="flex flex-wrap gap-4">
            {sig.fields.map((f) =>
              f.kind === 'count' ? (
                <label key={f.key} className="flex flex-col gap-1">
                  <span className="text-body">{f.label}</span>
                  <Count value={value[f.key]} min={1} onChange={(v) => set(f.key, v)} />
                </label>
              ) : (
                <Decimal key={f.key} label={f.label} value={value[f.key]} kind={f.kind} onChange={(v) => set(f.key, v)} />
              ),
            )}
          </div>
        </>
      )}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-medium text-heading">{label}</span>
      {children}
      <span className="text-body">{hint}</span>
    </label>
  );
}

// RuleSettings lists each rule's own signal settings and adds new ones,
// starting from the default. Rules come from the draft; a setting for a
// rule the draft no longer has is kept and marked.
function RuleSettings({ value, onChange }: { value: JsonObject; onChange: (v: JsonObject) => void }) {
  const draft = useOptionalDraft();
  const c = draft?.config;
  const rules = [
    ...(c?.config_rules ?? []).map((r) => ({ id: r.id, phase: 'config' })),
    ...(c?.rate_limit_rules ?? []).map((r) => ({ id: r.id, phase: 'rate_limit' })),
    ...(c?.request_header_rules ?? []).map((r) => ({ id: r.id, phase: 'request_headers' })),
  ];
  const per = (value.rules ?? {}) as Record<string, Record<string, Signal>>;
  const defaults = (value.signals ?? {}) as Record<string, Signal>;
  const [rule, setRule] = useState<string>();
  const [signal, setSignal] = useState<string>();
  const phaseOf = (id: string) => rules.find((r) => r.id === id)?.phase;
  const fits = (id: string | undefined) => signals.filter((s) => s.scope !== 'fleet' && id !== undefined && s.scope.includes(phaseOf(id) ?? '') && !per[id]?.[s.name]);
  const setRules = (r: Record<string, Record<string, Signal>>) => onChange({ ...value, rules: r });
  const put = (id: string, name: string, s: Signal | undefined) => {
    const next = { ...(per[id] ?? {}) };
    if (s) next[name] = s;
    else delete next[name];
    setRules(Object.keys(next).length ? { ...per, [id]: next } : (without(per, id) as Record<string, Record<string, Signal>>));
  };
  return (
    <div className="flex flex-col gap-3">
      {Object.keys(per).length === 0 && <p className="text-body">No rule has its own settings: every rule uses the defaults above.</p>}
      <ul className="flex flex-col divide-y divide-line rounded-control shadow-field empty:hidden">
        {Object.entries(per).flatMap(([id, sigs]) =>
          Object.entries(sigs).map(([name, s]) => (
            <li key={`${id} ${name}`} className="flex flex-col gap-2 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium text-heading">
                  {label(name)} for rule {id}{' '}
                  {phaseOf(id) ? <Badge>{phaseNames[phaseOf(id)!]}</Badge> : <Badge tone="amber">not in the draft</Badge>}
                </span>
                <Button onClick={() => put(id, name, undefined)}>Use the default</Button>
              </div>
              <SignalFields name={name} value={s} onChange={(v) => put(id, name, v)} />
            </li>
          )),
        )}
      </ul>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-body">Rule</span>
          <Choice value={rule} options={rules.map((r) => r.id)} labels={Object.fromEntries(rules.map((r) => [r.id, `${r.id} (${phaseNames[r.phase]})`]))} onChange={(v) => (setRule(v), setSignal(undefined))} />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-body">Signal</span>
          <Choice value={signal} options={fits(rule).map((s) => s.name)} labels={Object.fromEntries(signals.map((s) => [s.name, s.label]))} onChange={setSignal} />
        </label>
        <Button disabled={!rule || !signal} onClick={() => (put(rule!, signal!, { ...(defaults[signal!] ?? { mode: 'notify', severity: 'warning' }) }), setSignal(undefined))}>
          Give this rule its own setting
        </Button>
      </div>
    </div>
  );
}

function Settings({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['notifications'], queryFn: () => api<JsonObject>('GET', '/api/settings/notifications') });
  const [edit, setEdit] = useState<JsonObject>();
  useLeaveGuard(edit !== undefined ? 'The notification settings have changes that are not saved. Leave and lose them?' : undefined);
  const save = useMutation({
    mutationFn: () => api('PUT', '/api/settings/notifications', edit),
    onSuccess: () => (setEdit(undefined), qc.invalidateQueries({ queryKey: ['notifications'] })),
  });
  if (!q.data) return <Pending error={q.error} />;
  const value = edit ?? q.data;
  const set = (k: string, v: Json) => setEdit(setField(value, k, v));
  const defaults = (value.signals ?? {}) as Record<string, Signal>;
  const short = timeUnits.slice(1, 3);
  const group = (fleet: boolean) =>
    signals
      .filter((s) => (s.scope === 'fleet') === fleet)
      .map(({ name, label }) => (
        <li key={name} className="flex flex-col gap-2 p-3">
          <span className="font-medium text-heading">{label}</span>
          <SignalFields name={name} value={defaults[name] ?? {}} onChange={(v) => set('signals', { ...defaults, [name]: v })} />
        </li>
      ));
  return (
    <>
      <Card
        title="Defaults"
        intro="Every minute, admin compares the last window with the baseline before it and checks each signal below. Saved on its own, not with the draft."
        info="A signal trips only with enough requests to judge. An anomaly notifies after it trips several checks in a row, and resolves after it passes several in a row."
      >
        <fieldset disabled={!canManage} className="flex flex-col gap-5 text-sm">
          <Check
            label="Notify on anomalies"
            hint={value.enabled === true ? 'On: each signal below notifies as set.' : 'Off: nothing is checked, and anything open resolves at the next check.'}
            checked={value.enabled === true}
            onChange={(e) => set('enabled', e.target.checked)}
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Window" hint="How much recent traffic each check looks at, such as 5 minutes.">
              <Amount value={value.window} units={short} fallback="m" duration onChange={(v) => set('window', v)} />
            </Field>
            <Field label="Baseline" hint="The traffic before the window it is compared with, such as 1 hour.">
              <Amount value={value.baseline} units={timeUnits.slice(0, 2)} fallback="m" duration onChange={(v) => set('baseline', v)} />
            </Field>
            <Field label="Notify after" hint="Checks in a row that must trip, so a one-minute blip never notifies.">
              <Count value={value.fire_after} min={1} onChange={(v) => set('fire_after', v)} />
            </Field>
            <Field label="Resolve after" hint="Checks in a row that must pass before it resolves.">
              <Count value={value.resolve_after} min={1} onChange={(v) => set('resolve_after', v)} />
            </Field>
          </div>
          <h3 className="font-medium text-heading">Whole fleet</h3>
          <ul className="flex flex-col divide-y divide-line rounded-control shadow-field">{group(true)}</ul>
          <h3 className="font-medium text-heading">Each rule</h3>
          <ul className="flex flex-col divide-y divide-line rounded-control shadow-field">{group(false)}</ul>
        </fieldset>
      </Card>
      <Card title="Per-rule settings" intro="A rule's own setting replaces the default for that rule and signal, for example to turn off a noisy alert or raise its severity.">
        <fieldset disabled={!canManage} className="flex flex-col gap-3 text-sm">
          <RuleSettings value={value} onChange={setEdit} />
        </fieldset>
      </Card>
      <div className="flex flex-col items-start gap-2">
        <ErrorBox error={save.error} where={where} />
        {save.isSuccess && !edit && <Notice>Notification settings saved.</Notice>}
        <ConfirmButton
          variant="primary"
          title="Save notification settings?"
          action="Save notification settings"
          confirm="They apply from the next check, about a minute from now, without a publish."
          disabled={!canManage || !edit || save.isPending}
          onConfirm={() => save.mutate()}
        >
          Save notification settings
        </ConfirmButton>
        {edit !== undefined && (
          <Button onClick={() => (setEdit(undefined), save.reset())}>Discard changes</Button>
        )}
      </div>
    </>
  );
}

const tone = (a: Anomaly) => (a.state === 'resolved' ? 'green' : a.state === 'pending' ? 'slate' : a.severity === 'info' ? 'slate' : a.severity === 'critical' ? 'red' : 'amber');
export const stateWords = (a: Anomaly) => (a.state === 'resolved' ? 'Resolved' : a.state === 'pending' ? 'Pending' : 'Firing');

// LogsOf links an anomaly's time to the deployment's log store, when
// LOG_SEARCH_URL is set and needs no value an anomaly lacks.
function LogsOf({ a, now }: { a: Anomaly; now: number }) {
  const href = useLogSearch()({ from: Date.parse(a.started_at), to: a.resolved_at ? Date.parse(a.resolved_at) : now });
  return (
    href && (
      <span className="text-sm text-body">
        <LogLink href={href}>Search the logs</LogLink>
      </span>
    )
  );
}

function Anomalies() {
  const q = useQuery(anomaliesQuery);
  if (!q.data) return <Pending error={q.error} />;
  return (
    <div className="flex flex-col gap-3">
      {!q.data.alertmanager && <Notice tone="amber">ALERTMANAGER_URL is not set, so anomalies are shown here and nowhere else.</Notice>}
      <Table head={['Anomaly', 'Severity', 'State', 'Started', 'Sent to Alertmanager']} empty="No anomalies in the last 7 days.">
        {groupAnomalies(q.data.anomalies).map(({ a, under }) => (
          <tr key={a.id} className="align-top">
            {/* Summaries wrap, so the table fits a laptop screen. */}
            <td className="min-w-72 px-3 py-2.5 whitespace-normal">
              <span className="font-medium text-heading">
                {label(a.signal)}
                {a.rule && ` for rule ${a.rule}`}
              </span>
              <p className="text-body">{a.summary}</p>
              {a.case_id !== null && (
                <p className="text-body">
                  <Link to={`/autopilot/cases/${a.case_id}`} className="underline">
                    Autopilot case {a.case_id}
                  </Link>
                  : {a.case_verdict ?? (a.case_state === 'queued' || a.case_state === 'running' ? 'investigating' : a.case_state)}
                </p>
              )}
              <LogsOf a={a} now={q.dataUpdatedAt} />
              {a.state !== 'resolved' && (
                <div className="mt-1">
                  <Investigate target={{ anomaly_id: a.id }} name={`${label(a.signal)}${a.rule ? ` for rule ${a.rule}` : ''}`} />
                </div>
              )}
              {under.length > 0 && (
                <div className="mt-2 border-l border-line pl-3">
                  <p className="text-body">Rules where it is concentrated:</p>
                  <ul className="flex flex-col gap-1">
                    {under.map((k) => (
                      <li key={k.id}>
                        <span className="font-medium text-heading">
                          {label(k.signal)} for rule {k.rule}
                        </span>
                        : <span className="text-body">{k.summary}</span> <Badge tone={tone(k)}>{stateWords(k)}</Badge>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </td>
            <td className="px-3 py-2.5">{severities[a.severity as keyof typeof severities] ?? a.severity}</td>
            <td className="px-3 py-2.5">
              <Badge tone={tone(a)}>{stateWords(a)}</Badge>
              {a.resolved_at && <p className="text-body" title={when(a.resolved_at)}>{ago(a.resolved_at)}</p>}
            </td>
            <td className="px-3 py-2.5" title={when(a.started_at)}>
              {ago(a.started_at)}
            </td>
            <td className="px-3 py-2.5" title={when(a.notified_at)}>
              {a.notified_at ? ago(a.notified_at) : a.state === 'pending' ? 'Not yet: pending' : a.withheld ? withheldWords[a.withheld] : 'Not sent'}
            </td>
          </tr>
        ))}
      </Table>
    </div>
  );
}

export function Notifications({ canManage }: { canManage: boolean }) {
  return (
    <Page title="Notifications" info="Anomalies admin found in the edges' stats, and when each signal notifies. Firing anomalies are sent to Alertmanager, which routes them.">
      <Anomalies />
      <Settings canManage={canManage} />
    </Page>
  );
}
