import type { Config, Phase, Rule } from './api';
import type { Field } from './ui';

// Each phase's rule list in the config, what it is for, the fields a new
// rule starts with, and a reference for its Then block. Examples must pass
// validation against a config with no CORS policies, locales or issuers.
export const phases: {
  phase: Phase;
  key: 'config_rules' | 'rate_limit_rules' | 'request_header_rules';
  title: string;
  intro: string;
  info: string;
  blank: Omit<Rule, 'id' | 'expression'>;
  fields: Field[];
  example: Omit<Rule, 'id' | 'expression'>;
}[] = [
  {
    phase: 'config',
    key: 'config_rules',
    title: 'Config rules',
    intro: 'Choose per-route settings such as auth, CORS and upstream timeout. Every matching rule applies; a later rule overrides an earlier one, setting by setting.',
    info: 'Runs first, before the token is checked and the locale is picked, so these rules cannot match on JWT claims or the locale. The other two phases can.',
    blank: { settings: {} },
    fields: [
      ['auth', 'JWT requirement: {"mode": "none" | "optional" | "required"}. Add "accepted": ["issuer-id"] to accept other issuers than the defaults on the Issuers page.'],
      ['cors_policy', 'Name of a policy on the CORS page. "" turns CORS off for these requests.'],
      ['upstream_timeout', 'How long to wait for the upstream, such as "10s".'],
      ['body_limit', 'Largest request body in bytes, such as 1048576 for 1 MiB.'],
      ['locale', 'true to detect the locale. Needs supported locales under Settings.'],
      ['responses', 'Templates to use for these requests, by kind, such as {"rate_limited": "my-429"}.'],
      ['ratelimit_headers', 'true to send RateLimit and RateLimit-Policy response headers.'],
    ],
    example: { settings: { upstream_timeout: '10s', body_limit: 1048576, ratelimit_headers: true } },
  },
  {
    phase: 'rate_limit',
    key: 'rate_limit_rules',
    title: 'Rate limit rules',
    intro: 'Limit how often matching requests get through.',
    info: 'Each rule keeps one counter per key in Valkey, shared by every edge, so a limit of 100 means 100 across the fleet. A request is checked against every site-wide rule and up to 5 others, blocking rules first, in one Valkey call.',
    blank: { algorithm: 'sliding_window', limit: 100, period: '1m', key: ['ip'], on_missing_key: 'fallback_ip', action: 'log', fail_mode: 'open' },
    fields: [
      ['algorithm', 'fixed_window, sliding_window (smooth, good for logins), token_bucket (allows bursts, good for APIs) or leaky_bucket.'],
      ['limit, period', 'Requests allowed per period: 1 to 1,000,000,000 per "1s" to "24h".'],
      ['burst', 'Bucket size. Required for token_bucket and leaky_bucket, not allowed for the others.'],
      ['key', '1 to 5 parts that make one counter: ip, jwt_claim:<name>, header:<name>, cookie:<name>, query:<name>, host, method, country, asnum, locale, or constant alone. Header, cookie, query, host and method need ip or jwt_claim with them.'],
      ['on_missing_key', 'When a key part is absent: skip the rule, fallback_ip, or reject the request.'],
      ['action', 'block, or log to only count what would be limited. Start with log and watch Stats.'],
      ['penalty', 'Optional, "1s" to "24h": once over the limit, stay blocked this long.'],
      ['fail_mode', 'When Valkey cannot answer: open lets requests through, closed answers 503, local counts on each edge.'],
    ],
    example: { algorithm: 'token_bucket', limit: 600, period: '1m', burst: 100, key: ['jwt_claim:sub', 'ip'], on_missing_key: 'fallback_ip', action: 'log', penalty: '5m', fail_mode: 'open' },
  },
  {
    phase: 'request_headers',
    key: 'request_header_rules',
    title: 'Request header rules',
    intro: 'Shape the headers the upstream receives: set, append, remove, copy, rename or forward them.',
    info: 'Runs last, just before the request goes upstream. Headers the edge manages, such as X-Forwarded-For and X-Edge-*, are always set from trusted values; these rules cannot change them.',
    blank: { ops: [{ op: 'set' }] },
    fields: [
      ['set, append', '{"op": "set", "name": "x-tenant", "value": "acme"}. Append adds a value instead of replacing.'],
      ['remove', '{"op": "remove", "name": "cookie"}'],
      ['copy, rename', '{"op": "copy", "from": "x-old", "to": "x-new"}'],
      ['forward', '{"op": "forward", "mode": "allowlist", "names": ["accept", "authorization"]}. Mode is all, allowlist or denylist.'],
      ['value placeholders', '{{client_ip}}, {{request_id}}, {{country}}, {{locale}}, {{header:<name>}} and {{jwt_claim:<name>}}, filled in per request.'],
    ],
    example: {
      ops: [
        { op: 'set', name: 'x-client-ip', value: '{{client_ip}}' },
        { op: 'rename', from: 'x-legacy-id', to: 'x-request-ref' },
        { op: 'remove', name: 'x-debug' },
      ],
    },
  },
];

export const phaseOf = (p: string | undefined) => phases.find((x) => x.phase === p);

export const rulesOf = (c: Config, key: (typeof phases)[number]['key']) => c[key] ?? [];
