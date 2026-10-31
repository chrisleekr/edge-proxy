import { useMutation, useQuery } from '@tanstack/react-query';
import { type ReactNode, useState } from 'react';
import { api, type Issue, type Json, type JsonObject, Problem, type Schema, type TestResult } from '../api';
import { useDraft } from '../draft';
import { Choice, Count, Errors, Labeled, say, setField } from '../RuleForms';
import { Badge, Button, Card, Check, ErrorBox, type Field, Hint, JsonEditor, Page, Reference } from '../ui';
import { useVersions } from './Publish';

const testFields: Field[] = [
  ['name', 'What the test checks, shown in results.'],
  ['request', 'The request to send. Same fields as Simulate below: method, host, path, ip, headers, country, asn, ssl, http_version, ja4, ja3, verified_bot, jwt_claims.'],
  ['expect.rejected', 'The check that stops the request, such as auth or rate_limit_key.'],
  ['expect.preflight', 'true when the edge answers it as a CORS preflight.'],
  ['expect.config_rules, rate_limit_rules', 'Exactly the IDs of the rules that match, in order. [] means none.'],
  ['expect.settings', 'Resulting settings, such as {"auth_mode": "required", "upstream_timeout": "10s"}.'],
  ['expect.upstream_headers', 'First value of each named header the upstream gets. "" means the header must be absent.'],
];

// Sim is the result of /api/simulate; settings and headers are shown as given.
interface Sim {
  rejected?: string;
  config_rules: string[];
  rate_limit_rules: string[];
  rate_limit_capped: boolean;
  preflight: boolean;
  settings: { auth_mode: string; accepted: string[] | null; cors_policy: string; upstream_timeout: string; responses?: Record<string, string> };
  upstream_headers: Record<string, string[]> | null;
}

const ids = (l: string[] | null) => (l?.length ? l.join(', ') : 'none');

// asTest turns a simulation into a test that pins what it showed: the
// outcome and exactly which rules matched.
function asTest(request: Json, r: Sim, taken: Json[]): Json {
  const q = request as { method?: string; path?: string };
  const base = `${q.method ?? 'GET'} ${q.path ?? '/'}`;
  const names = new Set(taken.map((t) => (t as { name?: string }).name));
  let name = base;
  for (let n = 2; names.has(name); n++) name = `${base} (${n})`;
  return {
    name,
    request,
    expect: { ...(r.rejected && { rejected: r.rejected }), ...(r.preflight && { preflight: true }), config_rules: r.config_rules, rate_limit_rules: r.rate_limit_rules },
  };
}

// Pairs edits name and value pairs, such as headers, one row each. Rows
// are kept here so a half-typed or repeated name does not drop a row.
function Pairs({ label, noun, value, onChange, hint, example }: { label: string; noun: string; value: Json; onChange: (v: Record<string, string> | undefined) => void; hint: ReactNode; example: [string, string] }) {
  const [rows, setRows] = useState<[string, string][]>(() => Object.entries((value ?? {}) as Record<string, string>));
  const emit = (r: [string, string][]) => {
    setRows(r);
    const o = Object.fromEntries(r.filter(([k]) => k !== ''));
    onChange(Object.keys(o).length ? o : undefined);
  };
  return (
    <fieldset className="flex flex-col gap-2 text-sm">
      <legend className="font-medium text-heading">{label}</legend>
      <span className="text-body">{hint}</span>
      {rows.map(([k, v], i) => (
        <span key={i} className="flex flex-wrap items-center gap-2">
          <input aria-label={`${noun} name ${i + 1}`} placeholder={`such as ${example[0]}`} value={k} onChange={(e) => emit(rows.map((r, j) => (j === i ? [e.target.value, r[1]] : r)))} />
          <input aria-label={`${noun} value ${i + 1}`} placeholder={`such as ${example[1]}`} value={v} onChange={(e) => emit(rows.map((r, j) => (j === i ? [r[0], e.target.value] : r)))} />
          <Button aria-label={`Remove ${noun.toLowerCase()} ${i + 1}`} onClick={() => emit(rows.filter((_, j) => j !== i))}>
            Remove
          </Button>
        </span>
      ))}
      <div>
        <Button onClick={() => setRows([...rows, ['', '']])}>+ Add a {noun.toLowerCase()}</Button>
      </div>
    </fieldset>
  );
}

// RequestForm builds a simulated request. The simulator is the only check:
// its problems come back by field and show under them.
function RequestForm({ value, onChange, methods, issues }: { value: JsonObject; onChange: (v: JsonObject) => void; methods: string[]; issues: Issue[] }) {
  const set = (k: string, v: Json) => onChange(setField(value, k, v));
  const at = (f: string) => issues.filter((i) => i.path === `request.${f}`);
  const text = (k: string, label: string, hint: string, placeholder?: string) => (
    <Labeled label={label} hint={hint} issues={at(k)}>
      <input className="max-w-md" placeholder={placeholder} value={typeof value[k] === 'string' ? value[k] : ''} onChange={(e) => set(k, e.target.value || undefined)} />
    </Labeled>
  );
  const token = value.jwt_claims !== undefined;
  return (
    <div className="flex flex-col gap-4">
      <Labeled label="Method" issues={at('method')}>
        <Choice value={(value.method as string | undefined) ?? 'GET'} options={methods} labels={{}} onChange={(m) => set('method', m)} />
      </Labeled>
      {text('host', 'Host', 'The site the request is for, such as api.example.com.')}
      {text('path', 'Path', 'As the client sends it, query included, such as /login?next=/home.', '/')}
      {text('ip', 'Client IP', 'Such as 203.0.113.7. Leave empty for 192.0.2.1.', '192.0.2.1')}
      {text('country', 'Country', 'The two-letter code the CDN reports, such as AU. Leave empty for unknown.')}
      <Labeled label="AS number" hint="The network the CDN reports, such as 13335. Leave empty for unknown." issues={at('asn')}>
        <Count value={value.asn} min={1} onChange={(n) => set('asn', n)} />
      </Labeled>
      <Check label="Sent over HTTPS" checked={value.ssl === true} onChange={(e) => set('ssl', e.target.checked || undefined)} />
      {text('http_version', 'HTTP version', 'The version the CDN reports, such as 2.0 or HTTP/2. Leave empty for unknown.')}
      {text('ja4', 'JA4 fingerprint', 'The TLS fingerprint the CDN reports. With an HTTPS source configured, applies only with Sent over HTTPS checked. Leave empty for unknown.', 't13d1516h2_8daaf6152771_02713d6af862')}
      {text('ja3', 'JA3 fingerprint', 'The older TLS fingerprint, 32 hex characters. With an HTTPS source configured, applies only with Sent over HTTPS checked. Leave empty for unknown.')}
      <Check label="From a verified crawler" checked={value.verified_bot === true} onChange={(e) => set('verified_bot', e.target.checked || undefined)} />
      <Pairs label="Headers" noun="Header" value={value.headers} onChange={(h) => set('headers', h)} hint="Headers the client sends." example={['user-agent', 'curl/8.7.1']} />
      <div className="flex flex-col gap-2">
        <Check label="Has a token that verified" checked={token} onChange={(e) => set('jwt_claims', e.target.checked ? { sub: 'user-123' } : undefined)} />
        {token && (
          <Pairs
            label="Token claims"
            noun="Claim"
            value={value.jwt_claims}
            // A verified token always has claims, so the last one cannot go.
            onChange={(c) => set('jwt_claims', c ?? {})}
            hint="Claims of the token, such as sub. The simulator does not check signatures."
            example={['sub', 'user-123']}
          />
        )}
      </div>
      <Errors issues={issues.filter((i) => i.path === 'request')} />
    </div>
  );
}

// SimResult reads a simulation the way the edge would act on it.
function SimResult({ r }: { r: Sim }) {
  const s = r.settings;
  const headers = r.upstream_headers && Object.entries(r.upstream_headers);
  return (
    <div className="mt-3 flex flex-col gap-3 text-sm">
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
        <dt className="text-body">Outcome</dt>
        <dd className="font-medium">
          {r.rejected ? (
            <Badge tone="red">{rejections[r.rejected] ?? `rejected: ${r.rejected}`}</Badge>
          ) : r.preflight ? (
            <Badge tone="amber">answered as a CORS preflight</Badge>
          ) : (
            <Badge tone="green">sent to the upstream</Badge>
          )}
        </dd>
        <dt className="text-body">Config rules</dt>
        <dd className="font-mono">{ids(r.config_rules)}</dd>
        <dt className="text-body">Rate limit rules</dt>
        <dd className="font-mono">
          {ids(r.rate_limit_rules)}
          {r.rate_limit_capped && <span className="font-sans text-warning"> (more rules matched than the edge counts per request; the rest were skipped)</span>}
        </dd>
        <dt className="text-body">Auth</dt>
        <dd>
          {say[s.auth_mode] ?? s.auth_mode}
          {s.auth_mode !== 'none' && `, from ${ids(s.accepted)}`}
        </dd>
        <dt className="text-body">Upstream timeout</dt>
        <dd>{s.upstream_timeout}</dd>
        <dt className="text-body">CORS policy</dt>
        <dd>{s.cors_policy || 'none'}</dd>
        <dt className="text-body">Over a limit</dt>
        <dd>answered with template {s.responses?.rate_limited ?? 'rate_limited'}</dd>
      </dl>
      {headers?.length === 0 && <p className="text-body">The upstream receives no headers besides the forwarding ones the edge always sets.</p>}
      {!!headers?.length && (
        <div>
          <h3 className="mb-1 font-medium text-heading">Headers the upstream receives</h3>
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 font-mono">
            {headers.map(([k, v]) => (
              <div key={k} className="contents">
                <dt>{k}</dt>
                <dd className="break-all text-body">{v.join(', ')}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
      <details>
        <summary className="cursor-pointer font-medium text-heading">Full result</summary>
        <pre data-testid="simulate-result" className="mt-2">
          {JSON.stringify(r, null, 2)}
        </pre>
      </details>
    </div>
  );
}

// rejections says why the edge would refuse a simulated request, by the
// reason the simulator reports.
const rejections: Record<string, string> = {
  method: 'rejected with 400: the method is not in upper case',
  path: 'rejected with 400: the path is malformed or has an ambiguous encoding such as %2F',
  auth: 'rejected with 401: the route requires a valid token',
  rate_limit_key: 'rejected with 400: a rate limit rule needs a key part the request lacks',
};

export function Tests({ canTest, canWrite }: { canTest: boolean; canWrite: boolean }) {
  const d = useDraft();
  const run = useMutation({ mutationFn: () => api<TestResult[]>('POST', '/api/tests/run') });
  const [request, setRequest] = useState<JsonObject>({ method: 'GET', host: 'api.example.com', path: '/' });
  const [requestOK, setRequestOK] = useState(true);
  // JSON such as null parses but is no request, and the form cannot show it.
  const isRequest = typeof request === 'object' && request !== null && !Array.isArray(request);
  const [asJSON, setAsJSON] = useState(false);
  // Remounts the form when JSON replaced the request, so its rows reload.
  const [formKey, setFormKey] = useState(0);
  const schema = useQuery({ queryKey: ['schema'], queryFn: () => api<Schema>('GET', '/api/expr/schema'), staleTime: Infinity });
  const [version, setVersion] = useState('');
  const versions = useVersions();
  const sim = useMutation({
    mutationFn: (v: { version: string; request: JsonObject }) => api<Sim>('POST', '/api/simulate', { version: v.version ? Number(v.version) : null, request: v.request }),
  });
  const [added, setAdded] = useState('');
  // Simulate reads the saved draft, so rule edits not saved yet are not in
  // its result. Test-only edits leave the config object as loaded.
  const unsavedConfig = d.config !== d.draft.config;
  return (
    <Page title="Tests and simulate">
      <Card
        title="Config tests"
        info="Tests run through the edge's own code, so they check what will really happen. They run on the saved draft, so save first to test new edits."
        intro="Each test is a request and what the draft must do with it; expect checks only what it lists. Publishing is blocked while any test fails.">
        <JsonEditor key={d.discards} label="Tests" value={d.tests} onChange={d.setTests} onValidity={(ok) => d.markInvalid('Tests', !ok)} />
        <Reference
          fields={testFields}
          open={d.tests.length === 0}
          example={[
            {
              name: 'private pages need a token',
              request: { method: 'GET', host: 'api.example.com', path: '/private/x' },
              expect: { rejected: 'auth', config_rules: ['private-needs-auth'], settings: { auth_mode: 'required' } },
            },
            {
              name: 'login is limited per IP',
              request: { method: 'POST', host: 'api.example.com', path: '/login', ip: '203.0.113.7' },
              expect: { rate_limit_rules: ['login'], upstream_headers: { 'x-debug': '' } },
            },
          ]}
        />
        <div className="mt-3 flex flex-col items-start gap-2">
          <Button disabled={!canTest || d.dirty || run.isPending} onClick={() => run.mutate()}>
            {run.isPending ? 'Running…' : 'Run tests on the saved draft'}
          </Button>
          <Hint>{!canTest ? 'Your role cannot run tests.' : d.dirty ? 'Save the draft first: tests run on the saved draft.' : undefined}</Hint>
        </div>
        <ErrorBox error={run.error} />
        {run.data?.length === 0 && <p className="mt-2 text-body">The draft has no tests yet.</p>}
        {!!run.data?.length && (
          <ul className="mt-3 flex flex-col gap-1 text-sm" aria-label="Test results">
            {run.data.map((t) => (
              <li key={t.name}>
                <Badge tone={t.pass ? 'green' : 'red'}>{t.pass ? 'pass' : 'fail'}</Badge> {t.name}
                {t.failures && <span className="text-danger">: {t.failures.join('; ')}</span>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card
        title="Simulate a request"
        info="Pick the saved draft or any published version. Unsaved edits are not in the result. Simulating against the saved draft lets you add the request as a test that expects the same outcome."
        intro="Runs the edge's own request pipeline on a synthetic request. Rate limits are matched but not counted.">
        <label className="flex max-w-md flex-col gap-1 text-sm">
          <span className="font-medium text-heading">Run against</span>
          <select className="max-w-full" value={version} onChange={(e) => setVersion(e.target.value)}>
            <option value="">The saved draft</option>
            {versions.data?.map((v) => (
              <option key={v.version} value={v.version}>
                Version {v.version}
                {v.status === 'active' ? ' (live)' : ''}
                {v.message && `: ${v.message}`}
              </option>
            ))}
          </select>
        </label>
        <div className="mt-4">
          {asJSON ? (
            <JsonEditor label="Request" value={request} onChange={(r) => (setRequest(r), sim.reset())} onValidity={setRequestOK} />
          ) : schema.data ? (
            <RequestForm
              key={formKey}
              value={request}
              onChange={(r) => (setRequest(r), sim.reset())}
              methods={schema.data.rules.methods}
              issues={sim.error instanceof Problem ? sim.error.errors : []}
            />
          ) : (
            <ErrorBox error={schema.error} />
          )}
          <div className="mt-3">
            {/* The form cannot show text that does not parse, so JSON must be valid to leave it. */}
            <Button disabled={!requestOK || !isRequest} onClick={() => (setAsJSON(!asJSON), setFormKey((k) => k + 1))}>
              {asJSON ? 'Use the form' : 'Edit the request as JSON'}
            </Button>
          </div>
        </div>
        <div className="mt-3 flex flex-col items-start gap-2">
          <Button variant="primary" disabled={!canTest || !requestOK || !isRequest || sim.isPending} onClick={() => (setAdded(''), sim.mutate({ version, request }))}>
            {sim.isPending ? 'Simulating…' : 'Simulate'}
          </Button>
          <Hint>
            {!canTest
              ? 'Your role cannot simulate requests.'
              : !requestOK
                ? 'Fix the JSON in Request first.'
                : !isRequest
                  ? 'Request must be a JSON object.'
                  : version === '' && unsavedConfig
                    ? 'Runs the saved draft: your unsaved rule and setting changes are not included. Save the draft to simulate them.'
                    : undefined}
          </Hint>
        </div>
        <ErrorBox error={sim.error} />
        {sim.data && <SimResult r={sim.data} />}
        {/* Only a draft run: a test of an older version's behavior would fail on the draft. */}
        {sim.data && sim.variables.version === '' && canWrite && (
          <div className="mt-3 flex flex-col items-start gap-2">
            <Button
              disabled={d.invalid.includes('Tests') || !!added || unsavedConfig}
              onClick={() => {
                const t = asTest(sim.variables.request, sim.data, d.tests);
                d.setTests([...d.tests, t]);
                setAdded((t as { name: string }).name);
              }}
            >
              Add as a test
            </Button>
            <Hint>
              {added
                ? `Added “${added}” to Config tests above. Save the draft to keep it.`
                : d.invalid.includes('Tests')
                  ? 'Fix the JSON in Tests first.'
                  : unsavedConfig
                    ? 'Save the draft and simulate again first: this result is from the saved draft, so a test made from it might fail once your changes are saved.'
                    : 'Adds this request to Config tests, expecting this outcome and exactly these rules.'}
            </Hint>
          </div>
        )}
      </Card>
    </Page>
  );
}
