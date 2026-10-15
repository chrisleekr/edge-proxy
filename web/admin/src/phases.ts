import type { Config, Phase, Rule } from './api';

// Each phase's rule list in the config, and the fields a new rule starts with.
export const phases: { phase: Phase; key: 'config_rules' | 'rate_limit_rules' | 'request_header_rules'; title: string; blank: Omit<Rule, 'id' | 'expression'> }[] = [
  { phase: 'config', key: 'config_rules', title: 'Config rules', blank: { settings: {} } },
  {
    phase: 'rate_limit',
    key: 'rate_limit_rules',
    title: 'Rate limit rules',
    blank: { algorithm: 'sliding_window', limit: 100, period: '1m', key: ['ip'], on_missing_key: 'fallback_ip', action: 'block', fail_mode: 'open' },
  },
  { phase: 'request_headers', key: 'request_header_rules', title: 'Request header rules', blank: { ops: [] } },
];

export const phaseOf = (p: string | undefined) => phases.find((x) => x.phase === p);

export const rulesOf = (c: Config, key: (typeof phases)[number]['key']) => c[key] ?? [];
