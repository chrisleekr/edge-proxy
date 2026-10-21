import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type ReactNode, useContext, useState } from 'react';
import { api, type Config, type Issue, type Json, type JsonObject, type Schema } from '../api';
import { useDraft } from '../draft';
import { useLeaveGuard } from '../router';
import { GuardForm, guardWhere } from '../GuardForm';
import { Amount, Choice, Count, Errors, kindWhen, Labeled, Lines, setField, sizeUnits, timeUnits, without } from '../RuleForms';
import { Button, CanWrite, Card, Check, CodeEditor, ConfirmButton, Editable, ErrorBox, type Field, Hint, Input, JsonEditor, Notice, Page, Pending, ReadOnlyNote, Reference } from '../ui';

// The section forms edit the draft directly. The draft's own check, run by
// the server on every edit, puts each problem under its field and keeps
// Save off until there are none; nothing here validates.

const useSchema = () => useQuery({ queryKey: ['schema'], queryFn: () => api<Schema>('GET', '/api/expr/schema'), staleTime: Infinity });

// q quotes a name as the server's issue paths do, such as responses["web"].
const q = (name: string) => JSON.stringify(name);

// only keeps the issues for exactly this path, not those inside it.
const only = (issues: Issue[], path: string) => issues.filter((i) => i.path === path);

// Section is a form with JSON as a fallback. The form cannot show text
// that does not parse, so the JSON must be valid to go back to it.
function Section<T>({
  title,
  label,
  get,
  set,
  intro,
  info,
  children,
}: {
  title: string;
  label: string;
  get: (c: Config) => T;
  set: (c: Config, v: T) => Config;
  intro: ReactNode;
  info?: ReactNode;
  children: ReactNode;
}) {
  const d = useDraft();
  const canWrite = useContext(CanWrite);
  const [asJSON, setAsJSON] = useState(false);
  return (
    <Card title={title} intro={intro} info={info}>
      {asJSON ? (
        <JsonEditor key={d.discards} label={label} value={get(d.config)} onChange={(v) => d.setConfig((c) => set(c, v))} onValidity={(ok) => d.markInvalid(label, !ok)} />
      ) : (
        <Editable>
          <div className="flex flex-col gap-4">{children}</div>
        </Editable>
      )}
      {canWrite && (
        <div className="mt-4">
          <Button disabled={d.invalid.includes(label)} onClick={() => setAsJSON(!asJSON)}>
            {asJSON ? 'Use the form' : `Edit ${title} as JSON`}
          </Button>
        </div>
      )}
    </Card>
  );
}

function Text({ label, hint, issues, value, onChange, placeholder }: { label: string; hint?: ReactNode; issues: Issue[]; value: Json; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <Labeled label={label} hint={hint} issues={issues}>
      <input className="max-w-md" placeholder={placeholder} value={typeof value === 'string' ? value : ''} onChange={(e) => onChange(e.target.value)} />
    </Labeled>
  );
}

// contentLabel names a content type in a word for an entry's summary.
const contentLabel = (t: Json) =>
  typeof t !== 'string' ? undefined : t.startsWith('application/problem+json') ? 'JSON problem' : t.startsWith('application/json') ? 'JSON' : t.startsWith('text/html') ? 'HTML' : t.startsWith('text/plain') ? 'text' : t;

// AddNamed adds an entry to a map keyed by name. A name already in the map
// would replace that entry, so it is refused here rather than lost.
function AddNamed({ label, button, example, taken, onAdd }: { label: string; button: string; example: string; taken: string[]; onAdd: (name: string) => void }) {
  const [name, setName] = useState('');
  const exists = taken.includes(name);
  return (
    <div className="flex flex-col gap-2 border-t border-line pt-4">
      <Input label={label} hint={`Lowercase letters, digits, - and _, such as ${example}. It cannot be changed later.`} className="max-w-sm" value={name} onChange={(e) => setName(e.target.value)} />
      <Hint>{exists && `“${name}” already exists. Pick another name.`}</Hint>
      <div>
        <Button disabled={!name || exists} onClick={() => (onAdd(name), setName(''))}>
          {button}
        </Button>
      </div>
    </div>
  );
}

// Entry frames one named entry with its name's problems and a remove button.
// It starts closed, showing one summary line, so a long list stays easy to
// scan.
function Entry({
  title,
  summary,
  usedBy,
  problems,
  issues,
  remove,
  onRemove,
  children,
}: {
  title: string;
  summary: ReactNode;
  usedBy: string[];
  problems: boolean;
  issues: Issue[];
  remove: string;
  onRemove: () => void;
  children: ReactNode;
}) {
  // Opens on a problem and then stays open, so fixing the last problem
  // never folds the form away mid-edit; the person closes it.
  const [open, setOpen] = useState(problems);
  if (problems && !open) setOpen(true);
  return (
    <details open={open} onToggle={(e) => setOpen(e.currentTarget.open)} className="group rounded-control border border-line">
      <summary className="flex cursor-pointer list-none flex-wrap [&::-webkit-details-marker]:hidden items-baseline gap-x-3 gap-y-0.5 rounded-control px-4 py-3 hover:bg-soft">
        <span aria-hidden className="text-muted transition-transform group-open:rotate-90">
          ▸
        </span>
        <span className="font-mono text-sm font-medium text-heading">{title}</span>
        <span className="text-sm text-body">{summary}</span>
        <span className={`text-sm ${usedBy.length ? 'text-body' : 'text-warning'}`}>{usedBy.length ? `used by ${usedBy.join(', ')}` : 'not used'}</span>
        {problems && <span className="text-sm text-danger">has problems</span>}
      </summary>
      <div className="flex flex-col gap-4 border-t border-line p-4">
        <Errors issues={issues} />
        {children}
        <div>
          <ConfirmButton variant="danger" title={`${remove}?`} action={remove} confirm="It leaves the draft. Anything that uses it shows a problem until changed." onConfirm={onRemove}>
            {remove}
          </ConfirmButton>
        </div>
      </div>
    </details>
  );
}

// configRules lists the config rules with their settings, for "used by".
const configRules = (c: Config) => (c.config_rules ?? []).map((r) => ({ id: r.id, settings: r.settings ?? {} }));

type Templates = Record<string, JsonObject>;

export function Templates() {
  const d = useDraft();
  const schema = useSchema();
  if (!schema.data) return <Pending error={schema.error} />;
  const { response_kinds: kinds, content_types } = schema.data.rules;
  const all = (d.config.global.responses ?? {}) as Templates;
  const names = Object.keys(all).sort();
  const setAll = (t: Templates) => d.setConfig((c) => ({ ...c, global: { ...c.global, responses: t } }));
  // A template answers only with the status of the kinds it is used for.
  const statuses = [...new Set(kinds.map((k) => k.status))].sort();
  const statusLabels = Object.fromEntries(statuses.map((s) => [String(s), `${s}, for ${kinds.filter((k) => k.status === s).map((k) => k.name.replaceAll('_', ' ')).join(' and ')}`]));
  const defaults = (d.config.global.defaults.responses ?? {}) as Record<string, string>;
  return (
    <Page title="Templates">
      <ReadOnlyNote />
      <Section
        title="Response templates"
        label="Response templates"
        get={(c) => c.global.responses}
        set={(c, v) => ({ ...c, global: { ...c.global, responses: v } })}
        intro="Responses the edge sends itself, such as the 429 for a rate limit. Name one for each kind below, or in a config rule's response templates."
        info="The edge answers some requests without asking the upstream: bad requests, missing tokens, rate limits, timeouts. A template sets the status, content type and body of that answer. Every one is sent with Cache-Control: no-store."
      >
        {names.length === 0 && <p className="text-body">No templates yet.</p>}
        {names.map((name) => {
          const p = `global.responses[${q(name)}]`;
          const t = all[name]!;
          const set = (k: string, v: Json) => setAll({ ...all, [name]: setField(t, k, v) });
          return (
            <Entry
              key={name}
              title={name}
              summary={[t.status, contentLabel(t.content_type)].filter(Boolean).join(', ')}
              usedBy={[
                ...kinds.filter((k) => defaults[k.name] === name).map((k) => `the default for ${k.name.replaceAll('_', ' ')}`),
                ...configRules(d.config)
                  .filter((r) => Object.values((r.settings.responses ?? {}) as Record<string, Json>).includes(name))
                  .map((r) => `rule ${r.id}`),
              ]}
              problems={d.at(p).length > 0}
              issues={only(d.at(p), p)}
              remove={`Remove template ${name}`}
              onRemove={() => setAll(Object.fromEntries(Object.entries(all).filter(([n]) => n !== name)))}
            >
              <Labeled label="Status" issues={d.at(`${p}.status`)}>
                <Choice value={typeof t.status === 'number' ? String(t.status) : undefined} options={statuses.map(String)} labels={statusLabels} onChange={(v) => set('status', v === undefined ? undefined : Number(v))} />
              </Labeled>
              <Labeled label="Content type" issues={d.at(`${p}.content_type`)}>
                <Choice value={t.content_type as string | undefined} options={content_types} onChange={(v) => set('content_type', v)} />
              </Labeled>
              <div className="flex flex-col gap-1 text-sm">
                <span className="font-medium text-heading">Body</span>
                <CodeEditor key={d.discards} label={`Body of ${name}`} value={typeof t.body === 'string' ? t.body : ''} onChange={(b) => set('body', b)} />
                <span className="text-body">
                  Sent as written. <code>{'{{status}}'}</code>, <code>{'{{retry_after}}'}</code> and <code>{'{{request_id}}'}</code> are filled in per request. A JSON body must still be JSON once they are, such as{' '}
                  <code>{'{"title":"Slow down","retry_after":{{retry_after}}}'}</code>.
                </span>
                <Errors issues={d.at(`${p}.body`)} />
              </div>
            </Entry>
          );
        })}
        <AddNamed label="New template name" button="Add template" example="slow-down" taken={names} onAdd={(n) => setAll({ ...all, [n]: { body: '' } })} />
      </Section>
      <Section
        title="Default response per kind"
        label="Default responses"
        get={(c) => c.global.defaults.responses}
        set={(c, v) => ({ ...c, global: { ...c.global, defaults: { ...c.global.defaults, responses: v } } })}
        intro="Which template each kind of edge response uses unless a config rule picks another. Every kind needs one; only templates with the kind's status are offered."
      >
        <div className="grid gap-3 text-sm sm:grid-cols-[minmax(0,28rem)_minmax(0,1fr)] sm:items-center">
          {kinds.map(({ name: k, status }) => (
            <label key={k} className="contents">
              <span className="flex flex-col">
                <span className="font-medium text-heading">
                  {k.replaceAll('_', ' ')} ({status})
                </span>
                <span className="text-body">{kindWhen[k]}</span>
              </span>
              <Choice
                value={defaults[k]}
                options={names.filter((n) => all[n]!.status === status)}
                labels={{}}
                onChange={(v) => d.setConfig((c) => ({ ...c, global: { ...c.global, defaults: { ...c.global.defaults, responses: setField(defaults, k, v) } } }))}
              />
            </label>
          ))}
        </div>
        <Errors issues={d.at('global.defaults.responses')} />
      </Section>
    </Page>
  );
}

type Policies = Record<string, JsonObject>;

export function CORS() {
  const d = useDraft();
  const schema = useSchema();
  if (!schema.data) return <Pending error={schema.error} />;
  const all = (d.config.global.cors_policies ?? {}) as Policies;
  const names = Object.keys(all).sort();
  const setAll = (p: Policies) => d.setConfig((c) => ({ ...c, global: { ...c.global, cors_policies: p } }));
  return (
    <Page
      title="CORS policies"
      info="CORS tells a browser which other sites may call this API from their pages. A config rule picks a policy for its routes; a policy no rule picks has no effect. The edge answers preflight requests itself."
    >
      <ReadOnlyNote />
      <Section
        title="Policies"
        label="CORS policies"
        get={(c) => c.global.cors_policies}
        set={(c, v) => ({ ...c, global: { ...c.global, cors_policies: v } })}
        intro="Which other sites may call the API from a browser. A policy does nothing until a config rule picks it under CORS policy."
      >
        {names.length === 0 && <p className="text-body">No policies yet.</p>}
        {names.map((name) => {
          const p = `global.cors_policies[${q(name)}]`;
          const cp = all[name]!;
          const set = (k: string, v: Json) => setAll({ ...all, [name]: setField(cp, k, v) });
          const methods = (cp.methods ?? []) as string[];
          return (
            <Entry
              key={name}
              title={name}
              summary={((cp.origins ?? []) as string[]).map((o) => (o === '*' ? 'any site' : o)).join(', ') || 'no sites'}
              usedBy={configRules(d.config)
                .filter((r) => r.settings.cors_policy === name)
                .map((r) => `rule ${r.id}`)}
              problems={d.at(p).length > 0}
              issues={only(d.at(p), p)}
              remove={`Remove policy ${name}`}
              onRemove={() => setAll(Object.fromEntries(Object.entries(all).filter(([n]) => n !== name)))}
            >
              <Lines
                label="Allowed sites"
                item="Allowed site"
                noun="site"
                values={cp.origins}
                onChange={(v) => set('origins', v)}
                at={d.at}
                path={`${p}.origins`}
                placeholder="such as https://app.example.com"
                hint="Scheme and host as the browser shows them, lowercase and with no path, such as https://app.example.com or http://localhost:3000. * allows any site, but not with cookies."
              />
              <fieldset className="flex flex-col gap-1 text-sm">
                <legend className="font-medium text-heading">Methods</legend>
                <span className="text-body">Methods the browser may use beyond GET, HEAD and simple POST, such as PUT and DELETE.</span>
                <div className="flex flex-wrap gap-x-4 gap-y-1">
                  {[...new Set([...schema.data.rules.methods, ...methods])].map((m) => (
                    <Check key={m} label={m} checked={methods.includes(m)} onChange={(e) => set('methods', e.target.checked ? [...methods, m] : methods.filter((x) => x !== m))} />
                  ))}
                </div>
                <Errors issues={d.at(`${p}.methods`)} />
              </fieldset>
              <Lines
                label="Headers the page may send"
                item="Request header"
                noun="request header"
                values={cp.request_headers}
                onChange={(v) => set('request_headers', v)}
                at={d.at}
                path={`${p}.request_headers`}
                placeholder="such as content-type"
                hint="Such as content-type and authorization. * allows any, but not with cookies."
              />
              <Lines
                label="Headers the page may read"
                item="Exposed header"
                noun="exposed header"
                values={cp.exposed_headers}
                onChange={(v) => set('exposed_headers', v)}
                at={d.at}
                path={`${p}.exposed_headers`}
                placeholder="such as x-request-id"
                hint="Response headers page scripts may read, such as x-request-id."
              />
              <div className="flex flex-col gap-1">
                <Check label="Let browsers send cookies and Authorization" checked={cp.credentials === true} onChange={(e) => set('credentials', e.target.checked || undefined)} />
                <Errors issues={d.at(`${p}.credentials`)} />
              </div>
              <Labeled label="Browsers may reuse the answer for" hint="Optional, up to 24 hours, such as 10 minutes. Leave empty to let each browser decide." issues={d.at(`${p}.max_age`)}>
                <Amount value={cp.max_age === '0s' ? undefined : cp.max_age} units={timeUnits.slice(0, 3)} fallback="m" duration onChange={(v) => set('max_age', v)} />
              </Labeled>
            </Entry>
          );
        })}
        <AddNamed label="New policy name" button="Add policy" example="web" taken={names} onAdd={(n) => setAll({ ...all, [n]: { origins: [''] } })} />
      </Section>
    </Page>
  );
}

export function Issuers() {
  const d = useDraft();
  const schema = useSchema();
  if (!schema.data) return <Pending error={schema.error} />;
  const issuers = (d.config.auth.issuers ?? []) as JsonObject[];
  const accepted = d.config.auth.default_accepted ?? [];
  const ids = issuers.map((i) => i.id).filter((id): id is string => typeof id === 'string' && id !== '');
  const setAuth = (a: Partial<Config['auth']>) => d.setConfig((c) => ({ ...c, auth: { ...c.auth, ...a } }));
  const setIssuer = (i: number, k: string, v: Json) => setAuth({ issuers: issuers.map((x, j) => (j === i ? setField(x, k, v) : x)) });
  return (
    <Page
      title="Issuers"
      info="An issuer is an identity provider whose tokens the edge accepts. Its signing keys are fetched from the keys URL, which must be https and may not point at a private or internal address. HMAC signing is not allowed."
    >
      <ReadOnlyNote />
      <Section
        title="JWT issuers"
        label="Auth"
        get={(c) => c.auth}
        set={(c, v) => ({ ...c, auth: v })}
        intro="Identity providers whose tokens the edge accepts. Saving the draft fetches the keys of any issuer that has none yet. Private addresses are refused unless the deployment allows the host."
      >
        {issuers.length === 0 && <p className="text-body">No issuers yet.</p>}
        {issuers.map((is, i) => {
          const p = `auth.issuers[${i}]`;
          const id = typeof is.id === 'string' && is.id ? is.id : undefined;
          return (
            <Entry
              key={i}
              title={id ?? `Issuer ${i + 1}`}
              summary={typeof is.issuer === 'string' ? is.issuer : ''}
              usedBy={[
                ...((d.config.auth.default_accepted ?? []) as Json[]).filter((x) => x === is.id).map(() => 'rules that accept the default issuers'),
                ...configRules(d.config)
                  .filter((r) => ((r.settings.auth as { accepted?: Json[] } | undefined)?.accepted ?? []).includes(is.id))
                  .map((r) => `rule ${r.id}`),
              ]}
              problems={d.at(p).length > 0}
              issues={only(d.at(p), p)}
              remove={`Remove issuer ${id ?? i + 1}`}
              onRemove={() => setAuth({ issuers: issuers.filter((_, j) => j !== i) })}
            >
              <Text label="ID" hint="The name rules use for this issuer, such as auth0." issues={d.at(`${p}.id`)} value={is.id} onChange={(v) => setIssuer(i, 'id', v)} />
              <Text
                label="Issuer"
                hint="Exactly as the iss claim in its tokens, often with a trailing slash, such as https://example.us.auth0.com/."
                issues={d.at(`${p}.issuer`)}
                value={is.issuer}
                onChange={(v) => setIssuer(i, 'issuer', v)}
              />
              <Lines
                label="Audiences"
                item="Audience"
                noun="audience"
                values={is.audiences}
                onChange={(v) => setIssuer(i, 'audiences', v)}
                at={d.at}
                path={`${p}.audiences`}
                placeholder="such as https://api.example.com"
                hint="Values of the token's aud claim to accept, such as https://api.example.com."
              />
              <Text
                label="Keys URL"
                hint="The https address of the issuer's public keys (JWKS), usually ending in /.well-known/jwks.json."
                issues={d.at(`${p}.jwks_url`)}
                value={is.jwks_url}
                onChange={(v) => setIssuer(i, 'jwks_url', v)}
              />
              <Labeled label="Signing algorithm" hint="The identity provider's documentation names it; RS256 is the most common." issues={d.at(`${p}.algorithm`)}>
                <Choice value={is.algorithm as string | undefined} options={schema.data.rules.jwt_algorithms} labels={{}} onChange={(v) => setIssuer(i, 'algorithm', v)} />
              </Labeled>
            </Entry>
          );
        })}
        <div>
          <Button onClick={() => setAuth({ issuers: [...issuers, { id: '', issuer: '', audiences: [''], jwks_url: '' }] })}>+ Add an issuer</Button>
        </div>
        <fieldset className="flex flex-col gap-1 border-t border-line pt-4 text-sm">
          <legend className="font-medium text-heading">Accepted by default</legend>
          <span className="text-body">Issuers a config rule accepts when it ticks none of its own.</span>
          {[...new Set([...ids, ...accepted])].map((id) => (
            <Check
              key={id}
              label={ids.includes(id) ? id : `${id} (does not exist)`}
              checked={accepted.includes(id)}
              onChange={(e) => setAuth({ default_accepted: e.target.checked ? [...accepted, id] : accepted.filter((x) => x !== id) })}
            />
          ))}
          {ids.length === 0 && <span className="text-body">Add an issuer with an ID first.</span>}
          <Errors issues={d.at('auth.default_accepted')} />
        </fieldset>
      </Section>
    </Page>
  );
}

export function Settings({ canManage }: { canManage: boolean }) {
  const d = useDraft();
  const ks = d.config.kill_switch;
  const toggle = (k: 'rate_limit' | 'auth') => d.setConfig((c) => ({ ...c, kill_switch: { ...c.kill_switch, [k]: !c.kill_switch[k] } }));
  const schema = useSchema();
  if (!schema.data) return <Pending error={schema.error} />;
  const g = d.config.global;
  const part = (k: string) => (g[k] ?? {}) as JsonObject;
  const setPart = (k: string, v: JsonObject) => d.setConfig((c) => ({ ...c, global: { ...c.global, [k]: v } }));
  const backstop = part('backstop');
  const setBackstop = (k: string, v: Json) => setPart('backstop', setField(backstop, k, v));
  const defaults = g.defaults;
  const setDefault = (k: string, v: Json) => d.setConfig((c) => ({ ...c, global: { ...c.global, defaults: setField(c.global.defaults, k, v) } }));
  const locale = part('locale');
  const setLocale = (k: string, v: Json) => setPart('locale', setField(locale, k, v));
  const supported = ((locale.supported ?? []) as string[]).filter((x) => x !== '');
  const forward = (part('request_headers').forward ?? {}) as JsonObject;
  const setForward = (f: JsonObject) => setPart('request_headers', { ...part('request_headers'), forward: f });
  return (
    <Page title="Settings">
      <ReadOnlyNote />
      <Card
        title="Kill switch"
        intro="Turns enforcement off for every edge once published. Use it in an incident, not as configuration."
        info="Like any change, it takes effect when you save and publish."
      >
        <Editable>
          <div className="flex flex-col gap-3">
            <Check
              label="Disable rate limiting"
              hint="Every rule only counts: Stats still shows requests over a limit, but none is blocked and no penalty starts."
              checked={ks.rate_limit}
              onChange={() => toggle('rate_limit')}
            />
            <Check
              label="Disable JWT checks"
              hint="No token is checked on any route, so routes that require one let every request through, and none reaches the upstream with X-Edge-Auth-Sub."
              checked={ks.auth}
              onChange={() => toggle('auth')}
            />
          </div>
        </Editable>
      </Card>
      {/* Two columns on wide screens: these blocks are short and narrow. */}
      <div className="grid gap-5 xl:grid-cols-2 [&>*]:min-w-0">
        <Section
          title="Backstop"
          label="Backstop"
          get={(c) => c.global.backstop}
          set={(c, v) => ({ ...c, global: { ...c.global, backstop: v } })}
          intro="The per-IP limit that applies before any rule, in each edge's memory. It stops floods even when Valkey is down."
          info="Each edge counts on its own, so with 10 edges a client can reach 10 times this limit across the fleet. Set it well above real traffic: it is a floor for floods, not a policy."
        >
          <div className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-heading">Allow each IP</span>
            <span className="flex flex-wrap items-center gap-2">
              <label className="contents">
                <span className="sr-only">Backstop limit</span>
                <Count value={backstop.limit} min={1} placeholder="such as 5000" onChange={(v) => setBackstop('limit', v)} />
              </label>
              <span>requests every</span>
              <label className="contents">
                <span className="sr-only">Backstop period</span>
                <Amount value={backstop.period} units={timeUnits.slice(1, 3)} fallback="s" duration onChange={(v) => setBackstop('period', v)} />
              </label>
            </span>
            <span className="text-body">On each edge, such as 5000 requests every 1 second. Periods run from 1 second to 1 hour.</span>
            <Errors issues={d.at('global.backstop.limit')} name="Limit" />
            <Errors issues={d.at('global.backstop.period')} name="Period" />
          </div>
          <Labeled label="Burst" hint="Requests an IP may send at once after a quiet spell, such as 10000." issues={d.at('global.backstop.burst')}>
            <Count value={backstop.burst} min={1} onChange={(v) => setBackstop('burst', v)} />
          </Labeled>
          <Labeled
            label="IPs tracked per edge"
            hint="Such as 1000000. When the table is full, new IPs pass unchecked until tracked ones expire."
            issues={d.at('global.backstop.max_entries')}
          >
            <Count value={backstop.max_entries} min={1} onChange={(v) => setBackstop('max_entries', v)} />
          </Labeled>
        </Section>
        <Section
          title="Defaults"
          label="Defaults"
          get={(c) => without(c.global.defaults, 'responses')}
          // Responses are edited under Templates.
          set={(c, v) => ({ ...c, global: { ...c.global, defaults: { ...v, responses: c.global.defaults.responses } } })}
          intro="What applies when no config rule says otherwise."
        >
          <Labeled label="Largest request body" hint="Such as 1 MiB. Larger bodies get the payload too large response." issues={d.at('global.defaults.body_limit')}>
            <Amount value={defaults.body_limit} units={sizeUnits} fallback="MiB" duration={false} onChange={(v) => setDefault('body_limit', v)} />
          </Labeled>
          <Labeled label="Time to send the body" hint="How long a client may take to send its request body, 1 second to 1 hour, such as 30 seconds." issues={d.at('global.defaults.body_read_timeout')}>
            <Amount value={defaults.body_read_timeout} units={timeUnits.slice(0, 3)} fallback="s" duration onChange={(v) => setDefault('body_read_timeout', v)} />
          </Labeled>
          <Labeled label="Upstream timeout" hint="How long to wait for the upstream, 1 second to 1 hour, such as 30 seconds." issues={d.at('global.defaults.upstream_timeout')}>
            <Amount value={defaults.upstream_timeout} units={timeUnits.slice(0, 3)} fallback="s" duration onChange={(v) => setDefault('upstream_timeout', v)} />
          </Labeled>
          <div className="flex flex-col gap-1">
            <Check label="Detect the locale on every request" checked={defaults.locale === true} onChange={(e) => setDefault('locale', e.target.checked)} />
            <span className="text-sm text-body">Needs supported locales under Locale.</span>
            <Errors issues={d.at('global.defaults.locale')} />
          </div>
        </Section>
        <Section
          title="Locale"
          label="Locale"
          get={(c) => c.global.locale}
          set={(c, v) => ({ ...c, global: { ...c.global, locale: v } })}
          intro="The languages the edge picks from Accept-Language, and the header that tells the upstream which one it picked."
        >
          <Lines
            label="Supported locales"
            item="Supported locale"
            noun="locale"
            values={locale.supported}
            onChange={(v) => setLocale('supported', v.length ? v : undefined)}
            at={d.at}
            path="global.locale.supported"
            placeholder="such as en-AU"
            hint="Language tags as written in Accept-Language, such as en-AU, fr-FR or zh-Hant-TW."
          />
          <Labeled label="Default locale" hint="Used when the request asks for none of the supported ones." issues={d.at('global.locale.default')}>
            <Choice value={(locale.default as string) || undefined} options={supported} labels={{}} empty="None" onChange={(v) => setLocale('default', v)} />
          </Labeled>
          <Text
            label="Header for the upstream"
            hint="Starts with X-Edge-, such as X-Edge-Locale. Leave empty to send none."
            issues={d.at('global.locale.output_header')}
            value={locale.output_header}
            onChange={(v) => setLocale('output_header', v || undefined)}
          />
        </Section>
        <Section
          title="Request headers"
          label="Request headers"
          get={(c) => c.global.request_headers}
          set={(c, v) => ({ ...c, global: { ...c.global, request_headers: v } })}
          intro="Which client headers reach the upstream. Header rules can change this per route."
        >
          <Labeled label="Forward" issues={d.at('global.request_headers.forward.mode')}>
            <Choice
              value={forward.mode as string | undefined}
              options={schema.data.rules.forward_modes}
              // Names are refused with all and required otherwise.
              onChange={(m) => setForward(m === 'all' ? { mode: m } : { ...forward, mode: m, names: forward.names ?? [''] })}
            />
          </Labeled>
          {forward.mode !== 'all' && (
            <Lines
              label="Headers"
              item="Header"
              noun="header"
              values={forward.names}
              onChange={(v) => setForward({ ...forward, names: v })}
              at={d.at}
              path="global.request_headers.forward.names"
              placeholder="such as x-debug"
              hint="Such as x-debug. Keep authorization, cookie and content-type in an allowlist, or the upstream loses them."
            />
          )}
        </Section>
      </div>
      <Guard canManage={canManage} />
    </Page>
  );
}

export const guardFields: Field[] = [
  ['enabled', 'false stops automatic rollbacks and alerts.'],
  ['window', 'How much recent traffic each check looks at, at least "1m".'],
  ['min_requests', 'No decision is made on fewer requests than this in the window.'],
  ['evaluate_every', 'How often the guard checks, at least "1s".'],
  ['max_auto_rollbacks_per_publish', 'Automatic rollbacks allowed per publish.'],
  ['step_min_time', 'Least time each canary step runs before the next.'],
  ['signals', 'fleet_adoption, edge_5xx_ratio, upstream_5xx_ratio, changed_rule_limited_ratio, unchanged_rule_limited_ratio, p99_latency and auth_failure_ratio.'],
  ['signals.<name>.mode', 'rollback, alert or off.'],
  [
    'signals.<name> thresholds',
    'factor: times the baseline. floor or floor_ms: never trips below it. min_ratio and max_ratio: absolute limits. max_vs_shadow: against the shadow count. after: grace time.',
  ],
];

// Guard settings apply at once, outside the draft, and are audited.
function Guard({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['guard'], queryFn: () => api<Json>('GET', '/api/settings/guard') });
  const [edit, setEdit] = useState<Json>();
  const [ok, setOK] = useState(true);
  // Text that never parsed leaves the value unchanged, so discarding it
  // remounts the editor.
  const [resets, setResets] = useState(0);
  const [asJson, setAsJson] = useState(false);
  useLeaveGuard(edit !== undefined || !ok ? 'The rollback guard has changes that are not saved. Leave and lose them?' : undefined);
  const save = useMutation({
    mutationFn: () => api('PUT', '/api/settings/guard', edit),
    onSuccess: () => (setEdit(undefined), qc.invalidateQueries({ queryKey: ['guard'] })),
  });
  if (!q.data) return <Pending error={q.error} />;
  return (
    <Card
      title="Rollback guard"
      intro="Watches a canary, or a version just published, and rolls back or alerts when a signal trips. Saved on its own, not with the draft."
      info="For the first minutes after a publish (10 by default), or during a canary, it compares the new version with the old one. Signals only a config change can cause, such as more 5xx, roll back. Signals an attack can also cause, such as more auth failures, only alert."
    >
      {asJson ? (
        <>
          <JsonEditor key={resets} label="Guard settings" value={edit ?? q.data} onChange={setEdit} onValidity={setOK} />
          <Reference fields={guardFields} example={{ edge_5xx_ratio: { mode: 'rollback', factor: 2, floor: 0.01 } }} />
        </>
      ) : (
        <GuardForm value={(edit ?? q.data) as JsonObject} onChange={setEdit} disabled={!canManage} />
      )}
      {/* Back to the form only from JSON that parses, which the form can show. */}
      {canManage && (
        <div className="mt-3">
          <Button disabled={asJson && !ok} onClick={() => setAsJson(!asJson)}>
            {asJson ? 'Use the form' : 'Edit as JSON'}
          </Button>
        </div>
      )}
      <div className="mt-3 flex flex-col items-start gap-2">
        <ErrorBox error={save.error} where={guardWhere} />
        {save.isSuccess && !edit && <Notice>Guard settings saved.</Notice>}
        <ConfirmButton
          variant="primary"
          title="Save guard settings?"
          action="Save guard settings"
          confirm="They apply at once to every canary and new publish, without a publish of their own."
          disabled={!canManage || !edit || !ok || save.isPending}
          onConfirm={() => save.mutate()}
        >
          Save guard settings
        </ConfirmButton>
        {(edit !== undefined || !ok) && (
          <Button
            onClick={() => {
              setEdit(undefined);
              setOK(true);
              setResets((n) => n + 1);
              save.reset();
            }}
          >
            Discard changes
          </Button>
        )}
        <Hint>{!canManage ? 'Your role cannot change guard settings.' : !ok ? 'Fix the JSON to save.' : undefined}</Hint>
      </div>
    </Card>
  );
}
