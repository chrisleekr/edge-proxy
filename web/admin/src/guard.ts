// Guard outcomes in words, shared by the dashboard, versions and publish.

import type { Version } from './api';

type Signal = { value: number; baseline: number; mode: string; tripped: boolean; detail?: string };
type Outcome = NonNullable<Version['guard_outcome']>;

// trippedSignals lists a guard outcome's tripped signals by name.
const trippedSignals = (signals: Record<string, unknown> | undefined) =>
  Object.entries((signals ?? {}) as Record<string, Signal>).filter(([, s]) => s.tripped);

// against names what a version was compared with. Outcomes stored before
// the guard recorded its baseline only say that there was one.
const against = (o: { baseline_version?: number | undefined }) => (o.baseline_version ? `version ${o.baseline_version}` : 'the version it was compared with');

// signalSays is a tripped guard signal in words, with its own numbers.
function signalSays(name: string, s: Signal, on: string) {
  const p = (x: number) => `${(100 * x).toFixed(2)}%`;
  switch (name) {
    case 'edge_5xx_ratio':
      return `Edge 5xx were ${p(s.value)} of requests, against ${p(s.baseline)} on ${on}`;
    case 'upstream_5xx_ratio':
      return `Upstream 5xx were ${p(s.value)} of requests, against ${p(s.baseline)} on ${on}`;
    case 'auth_failure_ratio':
      return `Auth failures were ${p(s.value)} of requests, against ${p(s.baseline)} on ${on}`;
    // Latency is counted in ranges, so both numbers are a range's top.
    case 'p99_latency':
      return `p99 latency was up to ${s.value}ms, against up to ${s.baseline}ms on ${on}`;
    case 'unchanged_rule_limited_ratio':
      return `Rule ${s.detail ?? ''}, which this version did not change, blocked ${p(s.value)} of the requests it checked, against ${p(s.baseline)} on ${on}`;
    // It trips over the cap, or far over what the rule found while it only
    // logged; baseline is the cap, so the value says which.
    case 'changed_rule_limited_ratio':
      return `Rule ${s.detail ?? ''}, changed in this version, blocked ${p(s.value)} of the requests it checked, ${s.value > s.baseline ? `over the ${p(s.baseline)} cap` : 'far more than it found over its limit while set to log only'}`;
    case 'fleet_adoption':
      return `Only ${p(s.value)} of edges loaded it, under the ${p(s.baseline)} needed`;
    default:
      return `${name.replaceAll('_', ' ')} was ${s.value}, against ${s.baseline} on ${on}`;
  }
}

// outcomeSays is each tripped signal of an outcome as a sentence.
export const outcomeSays = (o: Pick<Outcome, 'signals' | 'baseline_version'>) => trippedSignals(o.signals).map(([name, s]) => `${signalSays(name, s, against(o))}.`);

// whyKept says why an alert left a version in place: its tripped checks
// only alert, or the guard may not roll this version back.
export function whyKept(o: Outcome, source: string) {
  if (!trippedSignals(o.signals).some(([, s]) => s.mode === 'rollback')) return 'Those checks only raise an alert, so the version stays; Settings, Rollback guard sets which ones roll back.';
  return source === 'revert' || source === 'guard_rollback'
    ? 'The guard never rolls back a revert or a rollback, so the version stays.'
    : 'This publish has no automatic rollbacks left (Automatic rollbacks per publish, under Settings), so the version stays.';
}
