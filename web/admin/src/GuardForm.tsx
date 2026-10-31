import type { ReactNode } from 'react';
import type { Json, JsonObject } from './api';
import { Amount, Choice, Count, setField, timeUnits } from './RuleForms';
import { Check } from './ui';

// GuardForm edits rollback guard settings as fields, for Settings and for a
// single publish. The server checks them on save; its errors show there.

type Signal = JsonObject & { mode?: string };
type Kind = 'ratio' | 'factor' | 'ms' | 'duration';
type Threshold = { key: string; label: string; kind: Kind };

const modes = { rollback: 'Roll back', alert: 'Alert only', off: 'Off' };

// num is a number field or undefined, for sentences built from the form.
const num = (s: Signal, k: string) => (typeof s[k] === 'number' ? s[k] : undefined);
const pct = (x: number | undefined) => (x === undefined ? '…' : `${+(x * 100).toFixed(4)}%`);
const times = (x: number | undefined) => (x === undefined ? '…' : `${x}×`);

// Each signal with its thresholds and a sentence of when it trips, from
// the guard's own comparison: relative ones need the new version over
// factor times the old one's value and over the floor.
const signals: { name: string; label: string; fields: Threshold[]; trips: (s: Signal) => string }[] = [
  {
    name: 'fleet_adoption',
    label: 'Edges loading the version',
    fields: [
      { key: 'min_ratio', label: 'Least share of edges', kind: 'ratio' },
      { key: 'after', label: 'Allowed time to load', kind: 'duration' },
    ],
    trips: (s) => `Trips when under ${pct(num(s, 'min_ratio'))} of live edges have loaded the version once the allowed time has passed.`,
  },
  {
    name: 'edge_5xx_ratio',
    label: 'Edge 5xx',
    fields: [
      { key: 'factor', label: 'Times the old share', kind: 'factor' },
      { key: 'floor', label: 'Never below', kind: 'ratio' },
    ],
    trips: (s) => `Trips when 5xx the edge sends itself are over ${times(num(s, 'factor'))} their share on the old version and over ${pct(num(s, 'floor'))} of requests.`,
  },
  {
    name: 'upstream_5xx_ratio',
    label: 'Upstream 5xx',
    fields: [
      { key: 'factor', label: 'Times the old share', kind: 'factor' },
      { key: 'floor', label: 'Never below', kind: 'ratio' },
    ],
    trips: (s) => `Trips when 5xx from upstreams are over ${times(num(s, 'factor'))} their share on the old version and over ${pct(num(s, 'floor'))} of requests.`,
  },
  {
    name: 'changed_rule_limited_ratio',
    label: 'A changed rate limit rule blocking',
    fields: [
      { key: 'max_ratio', label: 'Cap on requests blocked', kind: 'ratio' },
      { key: 'max_vs_shadow', label: 'Times its log only count', kind: 'factor' },
    ],
    trips: (s) =>
      `Trips when a rule this version added or changed blocks over ${pct(num(s, 'max_ratio'))} of the requests it checks, or over ${times(num(s, 'max_vs_shadow'))} the share it found over its limit while set to log only.`,
  },
  {
    name: 'unchanged_rule_limited_ratio',
    label: 'An unchanged rate limit rule blocking',
    fields: [{ key: 'factor', label: 'Times the old share', kind: 'factor' }],
    trips: (s) => `Trips when a rule this version did not change blocks over ${times(num(s, 'factor'))} the share it blocked on the old version.`,
  },
  {
    name: 'p99_latency',
    label: 'p99 latency',
    fields: [
      { key: 'factor', label: 'Times the old p99', kind: 'factor' },
      { key: 'floor_ms', label: 'Never below', kind: 'ms' },
    ],
    trips: (s) => `Trips when p99 latency is over ${times(num(s, 'factor'))} the old version's and over ${num(s, 'floor_ms') ?? '…'}ms.`,
  },
  {
    name: 'auth_failure_ratio',
    label: 'Auth failures',
    fields: [
      { key: 'factor', label: 'Times the old share', kind: 'factor' },
      { key: 'floor', label: 'Never below', kind: 'ratio' },
    ],
    trips: (s) => `Trips when requests failing their token check are over ${times(num(s, 'factor'))} their share on the old version and over ${pct(num(s, 'floor'))} of requests.`,
  },
];

// Decimal is a number with a fraction; a ratio shows and takes a percent.
export function Decimal({ label, value, onChange, kind }: { label: string; value: Json; onChange: (v: number | undefined) => void; kind: Exclude<Kind, 'duration'> }) {
  const percent = kind === 'ratio';
  const shown = typeof value === 'number' ? +(percent ? value * 100 : value).toFixed(4) : '';
  return (
    <label className="flex flex-col gap-1">
      <span className="text-body">{label}</span>
      <span className="flex items-center gap-1">
        <input
          type="number"
          inputMode="decimal"
          min={kind === 'factor' ? 1 : 0}
          max={percent ? 100 : undefined}
          step="any"
          className="w-28"
          value={shown}
          onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value) / (percent ? 100 : 1))}
        />
        {{ ratio: '%', factor: '×', ms: 'ms' }[kind]}
      </span>
    </label>
  );
}

// Field is a label, so its number input is named by it; a unit picker
// beside the number keeps its own "Unit" name.
function Field({ label, hint, children }: { label: string; hint: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-medium text-heading">{label}</span>
      {children}
      <span className="text-body">{hint}</span>
    </label>
  );
}

// guardWhere names a guard setting's path in the form's words, for the
// server's errors.
export function guardWhere(path: string) {
  const sig = signals.find((x) => path === `signals.${x.name}` || path.startsWith(`signals.${x.name}.`));
  if (sig) return sig.label;
  return { window: 'Watch for, Check every or Least time per canary step', min_requests: 'Least requests or Automatic rollbacks' }[path] ?? path;
}

// guardWords names one guard setting and its value as the form shows them,
// for the audit log's before and after.
const top: Record<string, string> = {
  enabled: 'Watch new versions',
  window: 'Watch for',
  min_requests: 'Least requests to judge',
  evaluate_every: 'Check every',
  step_min_time: 'Least time per canary step',
  max_auto_rollbacks_per_publish: 'Automatic rollbacks per publish',
};
export function guardWords(path: string, value: string | undefined) {
  const [, name, key] = /^signals\.(\w+)\.(\w+)$/.exec(path) ?? [];
  const sig = signals.find((x) => x.name === name);
  const label = sig ? `${sig.label}, ${key === 'mode' ? 'when it trips' : (sig.fields.find((f) => f.key === key)?.label ?? key ?? '').toLowerCase()}` : (top[path] ?? path);
  const v = value === undefined ? 'unset' : value.replace(/^"(.*)"$/, '$1');
  return [label, key === 'mode' ? (modes[v as keyof typeof modes] ?? v) : v] as const;
}

export function GuardForm({ value, onChange, disabled }: { value: JsonObject; onChange: (v: JsonObject) => void; disabled?: boolean }) {
  const set = (k: string, v: Json) => onChange(setField(value, k, v));
  const all = (value.signals ?? {}) as Record<string, Signal>;
  const setSignal = (name: string, k: string, v: Json) => set('signals', { ...all, [name]: setField(all[name] ?? {}, k, v) });
  const short = timeUnits.slice(1, 3);
  return (
    <fieldset disabled={disabled} className="flex flex-col gap-5 text-sm">
      <Check
        label="Watch new versions"
        hint={value.enabled === true ? 'On: every canary and full publish is watched, and each check below acts as set.' : 'Off: nothing is rolled back or alerted on automatically.'}
        checked={value.enabled === true}
        onChange={(e) => set('enabled', e.target.checked)}
      />
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Watch for" hint="After a full publish, how long the guard watches it; during a canary, how much recent traffic each check looks at.">
          <Amount value={value.window} units={short} fallback="m" duration onChange={(v) => set('window', v)} />
        </Field>
        <Field label="Least requests to judge" hint="No decision until the new and the old version each have this many requests.">
          <Count value={value.min_requests} min={1} onChange={(v) => set('min_requests', v)} />
        </Field>
        <Field label="Check every" hint="How often the guard compares the two versions.">
          <Amount value={value.evaluate_every} units={short} fallback="s" duration onChange={(v) => set('evaluate_every', v)} />
        </Field>
        <Field label="Least time per canary step" hint="How long each canary step runs before you can step up or promote.">
          <Amount value={value.step_min_time} units={short} fallback="m" duration onChange={(v) => set('step_min_time', v)} />
        </Field>
        <Field label="Automatic rollbacks per publish" hint="After this many, a check set to roll back only alerts. A revert is never rolled back.">
          <Count value={value.max_auto_rollbacks_per_publish} onChange={(v) => set('max_auto_rollbacks_per_publish', v)} />
        </Field>
      </div>
      <div className="flex flex-col gap-1">
        <h3 className="font-medium text-heading">Checks</h3>
        <p className="text-body">Each compares the new version with the old one: during a canary over the same minutes, after a full publish against the minutes before it. Roll back stops a canary, or publishes the old version again.</p>
      </div>
      <ul className="flex flex-col divide-y divide-line rounded-control shadow-field">
        {signals.map(({ name, label, fields, trips }) => {
          const s = all[name] ?? {};
          return (
            <li key={name} className="flex flex-col gap-2 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium text-heading">{label}</span>
                <label className="flex items-center gap-2">
                  <span className="text-body">
                    <span className="sr-only">{label}, </span>When it trips
                  </span>
                  <Choice value={s.mode} options={Object.keys(modes)} labels={modes} onChange={(m) => setSignal(name, 'mode', m)} />
                </label>
              </div>
              {s.mode !== 'off' && (
                <>
                  <p className="text-body">{trips(s)}</p>
                  <div className="flex flex-wrap gap-4">
                    {fields.map((f) =>
                      f.kind === 'duration' ? (
                        <label key={f.key} className="flex flex-col gap-1">
                          <span className="text-body">{f.label}</span>
                          <Amount value={s[f.key]} units={short} fallback="m" duration onChange={(v) => setSignal(name, f.key, v)} />
                        </label>
                      ) : (
                        <Decimal key={f.key} label={f.label} value={s[f.key]} kind={f.kind} onChange={(v) => setSignal(name, f.key, v)} />
                      ),
                    )}
                  </div>
                </>
              )}
            </li>
          );
        })}
      </ul>
    </fieldset>
  );
}
