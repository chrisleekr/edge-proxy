import { useState, type ReactNode } from 'react';
import type { Config, Issue, Json, JsonObject, Phase, RuleChoices } from './api';
import { Button, Info, LabelInfo } from './ui';

// The forms fill in a rule's fields from choices the server lists; the
// server's check, shown under each field, is the only validation.

// at returns the issues for a field path relative to the rule, such as
// "limit" or "key[1]", including those for anything inside it.
export type At = (field: string) => Issue[];

// Plain-language names for server values. A value the server adds later
// shows as itself until it gets one here.
export const say: Record<string, string> = {
  fixed_window: 'Fixed window: counts per clock period, the simplest',
  sliding_window: 'Sliding window: smooth, good for logins',
  token_bucket: 'Token bucket: allows short bursts, good for APIs',
  leaky_bucket: 'Leaky bucket: a steady rate with room for a burst',
  ip: 'Client IP',
  jwt_claim: 'JWT claim',
  header: 'Request header',
  cookie: 'Cookie',
  query: 'Query argument',
  host: 'Hostname',
  method: 'Request method',
  country: 'Country',
  asnum: 'AS number',
  locale: 'Locale',
  constant: 'All requests together',
  skip: 'Skip this rule for the request',
  fallback_ip: 'Count by client IP instead',
  reject: 'Reject the request',
  block: 'Block: answer 429 once over the limit',
  log: 'Log only: count what would be blocked, block nothing',
  open: 'Let requests through, uncounted',
  closed: 'Answer 503',
  local: 'Count on each edge, with the limit split across edges',
  none: 'No token needed',
  optional: 'Verify a token if one is sent',
  required: 'Require a valid token',
  set: 'Set a header, replacing its value',
  append: 'Add a value to a header',
  remove: 'Remove a header',
  copy: 'Copy a header to another name',
  rename: 'Rename a header',
  forward: 'Forward only some headers',
  all: 'All headers',
  allowlist: 'Only the headers listed',
  denylist: 'All headers except those listed',
  'application/json': 'JSON',
  'application/problem+json': 'JSON problem details, the standard error format for APIs',
  'text/html; charset=utf-8': 'HTML page',
  'text/plain; charset=utf-8': 'Plain text',
};
// kindWhen says when the edge sends each kind of response itself.
export const kindWhen: Record<string, string> = {
  bad_request: 'The request came from outside the trusted proxies or without the ingress secret, has a bad client IP header, a disallowed method or an ambiguous path, sent its body too slowly, or lacks a rate limit key part with Reject.',
  unauthorized: 'A route needs a token and the request has none, or its token does not verify.',
  payload_too_large: 'The request body is over the body limit.',
  rate_limited: 'A rate limit rule set to block, or the per-IP backstop, found the request over its limit.',
  bad_gateway: 'The upstream could not be reached or failed mid-response.',
  unavailable: 'A rule set to answer 503 could not reach Valkey, the edge has no config loaded yet, or it hit an internal error.',
  overloaded: 'The edge already has as many requests or streams in flight as the deployment allows.',
  gateway_timeout: 'The upstream did not answer within the upstream timeout.',
};
const named: Record<string, string> = { header: 'such as x-api-key', cookie: 'such as session', query: 'such as user_id', jwt_claim: 'such as sub' };

// Errors shows the server's problems for one field, next to it.
// name starts each message when one place shows several fields' issues.
export function Errors({ issues, name }: { issues: Issue[]; name?: string }) {
  if (!issues.length) return null;
  return (
    <ul role="alert" className="text-sm text-danger">
      {issues.map((i, n) => (
        <li key={n}>
          {name && `${name} `}
          {i.message}
        </li>
      ))}
    </ul>
  );
}

export function Labeled({ label, hint, info, issues, children }: { label: string; hint?: ReactNode; info?: ReactNode; issues: Issue[]; children: ReactNode }) {
  return (
    <div className="relative flex flex-col gap-1 text-sm">
      <LabelInfo label={label} info={info} />
      <label className="flex flex-col gap-1">
        <span className="font-medium text-heading">{label}</span>
        {children}
      </label>
      {hint && <span className="text-body">{hint}</span>}
      <Errors issues={issues} />
    </div>
  );
}

// Choice is a select of server values. A current value the list lacks, such
// as a deleted CORS policy, stays visible so its error makes sense. Unset
// gets a marker no value can contain, since "" is a value for CORS.
const unsetMark = '\u0000';
export function Choice({
  value,
  options,
  onChange,
  empty,
  labels = say,
}: {
  value: string | undefined;
  options: string[];
  onChange: (v: string | undefined) => void;
  empty?: string;
  labels?: Record<string, string>;
}) {
  const all = value !== undefined && !options.includes(value) ? [...options, value] : options;
  return (
    <select className="max-w-md" value={value ?? unsetMark} onChange={(e) => onChange(e.target.value === unsetMark ? undefined : e.target.value)}>
      {(empty !== undefined || value === undefined) && <option value={unsetMark}>{empty ?? 'Pick one'}</option>}
      {all.map((o) => (
        <option key={o} value={o}>
          {options.includes(o) ? (labels[o] ?? o) : `${o} (does not exist)`}
        </option>
      ))}
    </select>
  );
}

// A whole number; empty means the field is left out.
export function Count({ value, onChange, min = 0, placeholder }: { value: Json; onChange: (v: number | undefined) => void; min?: number; placeholder?: string }) {
  return (
    <input
      type="number"
      inputMode="numeric"
      min={min}
      step={1}
      className="max-w-40"
      placeholder={placeholder}
      value={typeof value === 'number' ? value : ''}
      onChange={(e) => onChange(e.target.value === '' ? undefined : Math.trunc(Number(e.target.value)))}
    />
  );
}

// Amounts with a unit, largest first. Durations are Go duration strings,
// which the server writes like "1m0s" or "1.5s".
export const timeUnits: [string, string, number][] = [
  ['h', 'hours', 3_600_000],
  ['m', 'minutes', 60_000],
  ['s', 'seconds', 1000],
  ['ms', 'milliseconds', 1],
];
export const sizeUnits: [string, string, number][] = [
  ['MiB', 'MiB', 1 << 20],
  ['KiB', 'KiB', 1 << 10],
  ['B', 'bytes', 1],
];
const goUnit: Record<string, number> = { h: 3_600_000, m: 60_000, s: 1000, ms: 1, us: 1e-3, µs: 1e-3, ns: 1e-6 };
const toMillis = (v: string) => {
  let total = 0;
  const rest = v.replace(/(\d+(?:\.\d+)?)(ms|us|µs|ns|h|m|s)/g, (_, n: string, u: string) => ((total += Number(n) * goUnit[u]!), ''));
  return rest === '' && v !== '' ? total : undefined;
};

// Amount shows the value as a number and a unit, never free text. It opens
// on the largest unit the value is a whole number of, so "1m0s" shows as 1
// minutes, then keeps that unit while it still fits: re-picking it on every
// keystroke would turn 60 seconds into 1 minute and the next digit into 15m.
export function Amount({
  value,
  onChange,
  units,
  fallback,
  duration,
}: {
  value: Json;
  onChange: (v: Json) => void;
  units: [string, string, number][];
  fallback: string;
  duration: boolean;
}) {
  const base = duration ? (typeof value === 'string' ? toMillis(value) : undefined) : typeof value === 'number' ? value : undefined;
  const largest = (b: number | undefined) => (b !== undefined && units.find(([, , n]) => b > 0 && b % n === 0)?.[0]) || undefined;
  const sizeOf = (u: string) => units.find(([x]) => x === u)![2];
  const [picked, setPicked] = useState(() => largest(base) ?? fallback);
  // A value from outside, such as a reverted draft, may not fit the kept unit.
  const unit = base === undefined || base % sizeOf(picked) === 0 ? picked : (largest(base) ?? picked);
  const size = sizeOf(unit);
  const amount = base === undefined ? '' : base / size;
  const write = (n: string, u: string) => {
    if (n === '') return onChange(undefined);
    const k = Math.trunc(Number(n));
    onChange(duration ? `${k}${u}` : k * sizeOf(u));
  };
  return (
    <span className="flex max-w-md gap-2">
      <input type="number" inputMode="numeric" min={0} step={1} className="w-28" value={amount} onChange={(e) => write(e.target.value, unit)} />
      <select aria-label="Unit" value={unit} onChange={(e) => (setPicked(e.target.value), amount !== '' && write(String(amount), e.target.value))}>
        {units.map(([u, label]) => (
          <option key={u} value={u}>
            {label}
          </option>
        ))}
      </select>
    </span>
  );
}

// Lines edits a list of strings one input per item, so the server's
// problem with item 2 shows under item 2. item names each input, such as
// "Allowed site 1"; noun names the add and remove buttons.
export function Lines({
  label,
  item,
  noun,
  values,
  onChange,
  at,
  path,
  hint,
  placeholder,
}: {
  label: string;
  item: string;
  noun: string;
  values: Json;
  onChange: (v: string[]) => void;
  at: At;
  path: string;
  hint?: ReactNode;
  placeholder?: string;
}) {
  const list = Array.isArray(values) ? (values as string[]) : [];
  return (
    <fieldset className="flex flex-col gap-2 text-sm">
      <legend className="font-medium text-heading">{label}</legend>
      {hint && <span className="text-body">{hint}</span>}
      {list.map((v, i) => (
        <div key={i} className="flex flex-col gap-1">
          <span className="flex flex-wrap items-center gap-2">
            <input aria-label={`${item} ${i + 1}`} className="max-w-md flex-1" placeholder={placeholder} value={v} onChange={(e) => onChange(list.map((x, j) => (j === i ? e.target.value : x)))} />
            <Button aria-label={`Remove ${noun} ${i + 1}`} onClick={() => onChange(list.filter((_, j) => j !== i))}>
              Remove
            </Button>
          </span>
          <Errors issues={at(`${path}[${i}]`)} />
        </div>
      ))}
      <div>
        <Button onClick={() => onChange([...list, ''])}>
          + Add {/^[aeiou]/i.test(noun) ? 'an' : 'a'} {noun}
        </Button>
      </div>
      <Errors issues={at(path).filter((x) => x.path === path)} />
    </fieldset>
  );
}

export const without = (o: JsonObject, ...keys: string[]): JsonObject => Object.fromEntries(Object.entries(o).filter(([k]) => !keys.includes(k)));
export const setField = (o: JsonObject, k: string, v: Json) => (v === undefined ? without(o, k) : { ...o, [k]: v });

export function RuleForm(props: { phase: Phase; value: JsonObject; onChange: (v: JsonObject) => void; choices: RuleChoices; config: Config; at: At }) {
  if (props.phase === 'rate_limit') return <RateLimitForm {...props} />;
  if (props.phase === 'config') return <SettingsForm {...props} />;
  return <HeaderOpsForm {...props} />;
}

// Buckets take a burst; the window algorithms refuse one.
const bursty = ['token_bucket', 'leaky_bucket'];

function RateLimitForm({ value: v, onChange, choices, at }: { value: JsonObject; onChange: (v: JsonObject) => void; choices: RuleChoices; at: At }) {
  const set = (k: string, x: Json) => onChange(setField(v, k, x));
  const key = Array.isArray(v.key) ? (v.key as string[]) : [];
  const setKey = (k: string[]) => set('key', k);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1 text-sm">
        <span className="font-medium text-heading">Allow</span>
        <span className="flex flex-wrap items-center gap-2">
          <label className="contents">
            <span className="sr-only">Limit</span>
            <Count value={v.limit} min={1} placeholder="such as 100" onChange={(x) => set('limit', x)} />
          </label>
          <span>requests every</span>
          <label className="contents">
            <span className="sr-only">Period</span>
            <Amount value={v.period} units={timeUnits.slice(0, 3)} fallback="m" duration onChange={(x) => set('period', x)} />
          </label>
        </span>
        <span className="text-body">Such as 100 requests every 1 minute. Periods run from 1 second to 24 hours.</span>
        <Errors issues={at('limit')} name="Limit" />
        <Errors issues={at('period')} name="Period" />
      </div>
      <Labeled label="Algorithm" info="All four count in Valkey and read time from Valkey, so every edge agrees. Fixed window resets on the clock and lets a client send twice the limit across a boundary; sliding window smooths that out. The buckets allow a burst, then a steady rate." issues={at('algorithm')}>
        <Choice
          value={v.algorithm as string | undefined}
          options={choices.algorithms}
          onChange={(a) => {
            // A burst left behind by a bucket would make a window rule fail.
            const next = setField(v, 'algorithm', a);
            onChange(bursty.includes(a ?? '') ? { ...next, burst: typeof v.burst === 'number' ? v.burst : (v.limit ?? 1) } : without(next, 'burst'));
          }}
        />
      </Labeled>
      {bursty.includes(v.algorithm as string) && (
        <Labeled label="Burst" hint="How many requests may come at once on top of the steady rate, such as 20." issues={at('burst')}>
          <Count value={v.burst} min={1} onChange={(x) => set('burst', x)} />
        </Labeled>
      )}
      <div className="flex flex-col gap-2 text-sm">
        <span className="flex items-center gap-1.5">
          <span className="font-medium text-heading">Count separately for each</span>
          <Info label="Count separately for each">
            What makes one client different from another. A header, cookie or query value is chosen by the client, who could change it to dodge the limit, so it
            needs Client IP or a JWT claim with it. IPv6 addresses are counted per /64.
          </Info>
        </span>
        {key.map((part, i) => {
          const [kind, name] = part.includes(':') ? [part.slice(0, part.indexOf(':')), part.slice(part.indexOf(':') + 1)] : [part, ''];
          const isNamed = choices.key_kinds.find((k) => k.name === kind)?.named;
          const change = (k: string, n: string) => setKey(key.map((p, j) => (j === i ? (choices.key_kinds.find((x) => x.name === k)?.named ? `${k}:${n}` : k) : p)));
          return (
            <div key={i} className="flex flex-col gap-1">
              <span className="flex flex-wrap items-center gap-2">
                <select aria-label={`Count by, part ${i + 1}`} value={kind} onChange={(e) => change(e.target.value, '')}>
                  {choices.key_kinds.map((k) => (
                    <option key={k.name} value={k.name}>
                      {say[k.name] ?? k.name}
                    </option>
                  ))}
                </select>
                {isNamed && <input aria-label={`${say[kind]} name, part ${i + 1}`} placeholder={named[kind]} value={name} onChange={(e) => change(kind, e.target.value)} />}
                {key.length > 1 && <Button onClick={() => setKey(key.filter((_, j) => j !== i))}>Remove</Button>}
              </span>
              <Errors issues={at(`key[${i}]`)} />
            </div>
          );
        })}
        {key.length < choices.max_key_parts && (
          <div>
            <Button onClick={() => setKey([...key, 'ip'])}>+ Add a part</Button>
          </div>
        )}
        <span className="text-body">
          Each different value gets its own count. Client IP is the usual choice; a header, cookie or query argument needs Client IP or a JWT claim with it.
        </span>
        <Errors issues={at('key').filter((i) => i.path === 'key')} />
      </div>
      {/* Client IP and All requests are always there, so the choice only matters with another part, or to show a problem with it. */}
      {(key.some((p) => p !== 'ip' && p !== 'constant') || at('on_missing_key').length > 0) && (
        <Labeled
          label="When a part is missing from the request"
          info="Such as a header the client did not send. Skip lets the request through unchecked by this rule. Count by client IP keeps it limited. Reject answers 400."
          issues={at('on_missing_key')}>
          <Choice value={v.on_missing_key as string | undefined} options={choices.on_missing_keys} onChange={(x) => set('on_missing_key', x)} />
        </Labeled>
      )}
      <Labeled
        label="Over the limit"
        info="Block answers 429 with Retry-After. Log only lets the request through and counts it under Over limit, log only in Stats, so you can see who it would block before it blocks anyone."
        hint="Start with Log only and watch Stats before you block." issues={at('action')}>
        <Choice value={v.action as string | undefined} options={choices.actions} onChange={(x) => set('action', x)} />
      </Labeled>
      <Labeled
        label="Penalty"
        hint="Optional. Once over the limit, a client stays blocked this long, 1 second to 24 hours, even if it slows down. Leave empty for none. A log only rule ignores it until it is set to block."
        issues={at('penalty')}>
        <Amount value={v.penalty} units={timeUnits.slice(0, 3)} fallback="m" duration onChange={(x) => set('penalty', x)} />
      </Labeled>
      <Labeled
        label="When Valkey cannot answer"
        info="When Valkey is down or slow. Let requests through keeps traffic flowing unlimited. Answer 503 protects the upstream but turns users away. Count on each edge uses that edge's memory at the limit divided by the number of edges. A log only rule never answers 503."
        issues={at('fail_mode')}>
        <Choice value={v.fail_mode as string | undefined} options={choices.fail_modes} onChange={(x) => set('fail_mode', x)} />
      </Labeled>
    </div>
  );
}

const yesNo = { true: 'Yes', false: 'No' };

function SettingsForm({ value, onChange, choices, config, at }: { value: JsonObject; onChange: (v: JsonObject) => void; choices: RuleChoices; config: Config; at: At }) {
  const s = (value.settings ?? {}) as JsonObject;
  const set = (k: string, x: Json) => onChange({ ...value, settings: setField(s, k, x) });
  const auth = s.auth as { mode?: string; accepted?: string[] } | undefined;
  const issuers = (config.auth.issuers ?? []).map((i) => (i as { id: string }).id);
  const cors = Object.keys((config.global.cors_policies as JsonObject | undefined) ?? {});
  const templates = Object.entries((config.global.responses as Record<string, { status?: number }> | undefined) ?? {});
  const responses = (s.responses ?? {}) as Record<string, string>;
  const flag = (k: string) => (s[k] === undefined ? undefined : s[k] === true ? 'true' : 'false');
  const unset = 'Not set by this rule';
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-body">Anything not set here keeps the value from earlier matching rules or the defaults under Settings.</p>
      <Labeled
        label="Token check"
        info="Checks a JWT bearer token against the issuers' keys. Optional lets requests without a token through, but a token that is sent and fails still gets 401. Required answers 401 to any request without a valid token."
        issues={at('settings.auth')}>
        <Choice value={auth?.mode} options={choices.auth_modes} empty={unset} onChange={(m) => set('auth', m === undefined ? undefined : m === 'none' ? { mode: m } : { ...auth, mode: m })} />
      </Labeled>
      {auth && auth.mode !== 'none' && issuers.length > 0 && (
        <fieldset className="flex flex-col gap-1 text-sm">
          <legend className="font-medium text-heading">Accept tokens from</legend>
          {issuers.map((id) => (
            <label key={id} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={auth.accepted?.includes(id) ?? false}
                onChange={(e) => {
                  const next = e.target.checked ? [...(auth.accepted ?? []), id] : (auth.accepted ?? []).filter((x) => x !== id);
                  set('auth', next.length ? { ...auth, accepted: next } : { mode: auth.mode! });
                }}
              />
              {id}
            </label>
          ))}
          <span className="text-body">Tick none to accept the default issuers from the Issuers page.</span>
        </fieldset>
      )}
      <Labeled label="CORS policy" issues={at('settings.cors_policy')}>
        <Choice
          value={s.cors_policy as string | undefined}
          options={['', ...cors]}
          labels={{ '': 'Off for these requests' }}
          empty={unset}
          onChange={(x) => set('cors_policy', x)}
        />
      </Labeled>
      <Labeled label="Upstream timeout" hint="How long to wait for the upstream. Leave empty to keep the default." issues={at('settings.upstream_timeout')}>
        <Amount value={s.upstream_timeout} units={timeUnits} fallback="s" duration onChange={(x) => set('upstream_timeout', x)} />
      </Labeled>
      <Labeled label="Largest request body" hint="Leave empty to keep the default." issues={at('settings.body_limit')}>
        <Amount value={s.body_limit} units={sizeUnits} fallback="MiB" duration={false} onChange={(x) => set('body_limit', x)} />
      </Labeled>
      <Labeled label="Detect the locale" hint="Needs supported locales under Settings." issues={at('settings.locale')}>
        <Choice value={flag('locale')} options={['true', 'false']} labels={yesNo} empty={unset} onChange={(x) => set('locale', x === undefined ? undefined : x === 'true')} />
      </Labeled>
      <Labeled label="Send RateLimit headers" hint="RateLimit and RateLimit-Policy on responses." issues={at('settings.ratelimit_headers')}>
        <Choice
          value={flag('ratelimit_headers')}
          options={['true', 'false']}
          labels={yesNo}
          empty={unset}
          onChange={(x) => set('ratelimit_headers', x === undefined ? undefined : x === 'true')}
        />
      </Labeled>
      <fieldset className="flex flex-col gap-2 text-sm">
        <legend className="font-medium text-heading">Response templates</legend>
        <span className="text-body">
          Which template answers each kind of error for these requests. Only templates with the right status are listed; templates are on the Templates page.
        </span>
        <div className="grid gap-2 sm:grid-cols-[max-content_1fr] sm:items-center">
          {choices.response_kinds.map(({ name: k, status }) => (
            <label key={k} className="contents">
              <code title={kindWhen[k]}>
                {k.replaceAll('_', ' ')} ({status})
              </code>
              {/* A template answers only with its own status, so others are not offered. */}
              <Choice
                value={responses[k]}
                options={templates.filter(([, t]) => t.status === status).map(([n]) => n)}
                labels={{}}
                empty="Not set by this rule"
                onChange={(x) => {
                  const next = setField(responses, k, x);
                  set('responses', Object.keys(next).length ? next : undefined);
                }}
              />
            </label>
          ))}
        </div>
        <Errors issues={at('settings.responses')} />
      </fieldset>
    </div>
  );
}

// Each operation keeps only the fields it uses, so a switch from set to
// rename leaves nothing behind for the server to refuse.
const opFields: Record<string, string[]> = {
  set: ['name', 'value'],
  append: ['name', 'value'],
  remove: ['name'],
  copy: ['from', 'to'],
  rename: ['from', 'to'],
  forward: ['mode', 'names'],
};

function HeaderOpsForm({ value, onChange, choices, at }: { value: JsonObject; onChange: (v: JsonObject) => void; choices: RuleChoices; at: At }) {
  const ops = (Array.isArray(value.ops) ? value.ops : []) as JsonObject[];
  const setOps = (o: JsonObject[]) => onChange({ ...value, ops: o });
  const setOp = (i: number, o: JsonObject) => setOps(ops.map((x, j) => (j === i ? o : x)));
  const move = (i: number, by: number) => {
    const next = [...ops];
    [next[i], next[i + by]] = [next[i + by]!, next[i]!];
    setOps(next);
  };
  const text = (i: number, k: string, label: string, placeholder: string, hint?: string) => (
    <Labeled label={label} hint={hint} issues={at(`ops[${i}].${k}`)}>
      <input
        className="max-w-md"
        placeholder={placeholder}
        value={(ops[i]![k] as string | undefined) ?? ''}
        onChange={(e) => setOp(i, setField(ops[i]!, k, e.target.value || undefined))}
      />
    </Labeled>
  );
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-body">Operations run top to bottom.</p>
      {ops.length === 0 && <p className="text-sm text-body">No operations yet.</p>}
      {ops.map((op, i) => (
        <fieldset key={i} className="flex flex-col gap-3 rounded-control border border-line p-3">
          <legend className="px-1 text-sm font-medium text-heading">Operation {i + 1}</legend>
          <span className="flex flex-wrap items-center gap-2">
            <select
              aria-label={`Operation ${i + 1}`}
              value={op.op as string}
              onChange={(e) => {
                const keep = opFields[e.target.value] ?? [];
                setOp(i, { op: e.target.value, ...Object.fromEntries(Object.entries(op).filter(([k]) => keep.includes(k))) });
              }}
            >
              {choices.header_ops.map((o) => (
                <option key={o} value={o}>
                  {say[o] ?? o}
                </option>
              ))}
            </select>
            <Button onClick={() => move(i, -1)} disabled={i === 0}>
              Move up
            </Button>
            <Button onClick={() => move(i, 1)} disabled={i === ops.length - 1}>
              Move down
            </Button>
            <Button onClick={() => setOps(ops.filter((_, j) => j !== i))}>Remove</Button>
          </span>
          <Errors issues={at(`ops[${i}]`).filter((x) => x.path === `ops[${i}]` || x.path === `ops[${i}].op`)} />
          {(op.op === 'set' || op.op === 'append' || op.op === 'remove') && text(i, 'name', 'Header name', 'such as x-tenant')}
          {(op.op === 'set' || op.op === 'append') &&
            text(
              i,
              'value',
              'Value',
              'such as acme or {{client_ip}}',
              'Filled in per request: {{client_ip}}, {{request_id}}, {{country}}, {{locale}}, {{header:name}}, {{jwt_claim:name}}.',
            )}
          {(op.op === 'copy' || op.op === 'rename') && (
            <>
              {text(i, 'from', 'From header', 'such as x-old')}
              {text(i, 'to', 'To header', 'such as x-new')}
            </>
          )}
          {op.op === 'forward' && (
            <>
              <Labeled label="Forward" issues={at(`ops[${i}].mode`)}>
                <Choice value={op.mode as string | undefined} options={choices.forward_modes} onChange={(m) => setOp(i, setField(m === 'all' ? without(op, 'names') : op, 'mode', m))} />
              </Labeled>
              {op.mode !== 'all' && (
                <Labeled label="Headers" hint="Names separated by commas, such as accept, authorization." issues={at(`ops[${i}].names`)}>
                  <input
                    className="max-w-md"
                    value={((op.names as string[] | undefined) ?? []).join(', ')}
                    onChange={(e) => {
                      const names = e.target.value.split(',').map((n) => n.trim());
                      // Keep a trailing empty entry while typing, so the comma stays.
                      setOp(i, setField(op, 'names', names.length === 1 && names[0] === '' ? undefined : names));
                    }}
                  />
                </Labeled>
              )}
            </>
          )}
        </fieldset>
      ))}
      <div>
        <Button onClick={() => setOps([...ops, { op: 'set' }])}>+ Add an operation</Button>
      </div>
    </div>
  );
}
