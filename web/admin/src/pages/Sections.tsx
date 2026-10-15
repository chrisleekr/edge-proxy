import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, type Config, type Json } from '../api';
import { useDraft } from '../draft';
import { Button, Card, ErrorBox, JsonEditor, Page } from '../ui';

// Section edits one part of the draft config as JSON. The server's
// validation on save is the only check.
function Section<T>({ title, label, get, set, help }: { title: string; label: string; get: (c: Config) => T; set: (c: Config, v: T) => Config; help: string }) {
  const d = useDraft();
  return (
    <Card title={title}>
      <p className="mb-2 text-sm text-slate-600">{help}</p>
      <JsonEditor key={d.discards} label={label} value={get(d.config)} onChange={(v) => d.setConfig((c) => set(c, v))} onValidity={(ok) => d.markInvalid(label, !ok)} />
    </Card>
  );
}

const global = (k: string) => ({
  get: (c: Config) => c.global[k],
  set: (c: Config, v: Json) => ({ ...c, global: { ...c.global, [k]: v } }),
});

export function Templates() {
  return (
    <Page title="Templates">
      <Section
        title="Response templates"
        label="Response templates"
        {...global('responses')}
        help="Named responses the edge sends itself. Placeholders such as {{request_id}} and {{retry_after}} are filled in per request."
      />
      <Section
        title="Default response per kind"
        label="Default responses"
        get={(c) => c.global.defaults.responses}
        set={(c, v) => ({ ...c, global: { ...c.global, defaults: { ...c.global.defaults, responses: v } } })}
        help="Which template each kind of edge response uses unless a config rule overrides it."
      />
    </Page>
  );
}

export function CORS() {
  return (
    <Page title="CORS policies">
      <Section title="Policies" label="CORS policies" {...global('cors_policies')} help="Named policies that config rules select with the cors_policy setting." />
    </Page>
  );
}

export function Issuers() {
  return (
    <Page title="Issuers">
      <Section
        title="JWT issuers"
        label="Auth"
        get={(c) => c.auth}
        set={(c, v) => ({ ...c, auth: v })}
        help="Each issuer's JWKS URL is fetched by admin through the SSRF guard, which refuses private addresses unless the host is in JWKS_ALLOWED_HOSTS."
      />
    </Page>
  );
}

export function Settings({ canManage }: { canManage: boolean }) {
  const d = useDraft();
  const ks = d.config.kill_switch;
  const toggle = (k: 'rate_limit' | 'auth') => d.setConfig((c) => ({ ...c, kill_switch: { ...c.kill_switch, [k]: !c.kill_switch[k] } }));
  return (
    <Page title="Settings">
      <Card title="Kill switch">
        <p className="mb-2 text-sm text-slate-600">Turns enforcement off for every edge once published. Use it in an incident, not as configuration.</p>
        <label className="mr-6 text-sm">
          <input type="checkbox" checked={ks.rate_limit} onChange={() => toggle('rate_limit')} className="mr-1" />
          Disable rate limiting
        </label>
        <label className="text-sm">
          <input type="checkbox" checked={ks.auth} onChange={() => toggle('auth')} className="mr-1" />
          Disable JWT checks
        </label>
      </Card>
      <Section title="Backstop" label="Backstop" {...global('backstop')} help="The per-IP limit that applies before any rule, in each edge's memory." />
      <Section
        title="Defaults"
        label="Defaults"
        get={(c) => {
          // Responses are edited under Templates.
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          const { responses, ...rest } = c.global.defaults;
          return rest;
        }}
        set={(c, v) => ({ ...c, global: { ...c.global, defaults: { ...v, responses: c.global.defaults.responses } } })}
        help="Body limit, timeouts and locale detection when no config rule says otherwise."
      />
      <Section title="Locale" label="Locale" {...global('locale')} help="Supported locales, the default, and the header the edge sets." />
      <Section title="Request headers" label="Request headers" {...global('request_headers')} help="Which client headers are forwarded to upstreams." />
      <Guard canManage={canManage} />
    </Page>
  );
}

// Guard settings apply at once, outside the draft, and are audited.
function Guard({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['guard'], queryFn: () => api<Json>('GET', '/api/settings/guard') });
  const [edit, setEdit] = useState<Json>();
  const [ok, setOK] = useState(true);
  const save = useMutation({
    mutationFn: () => api('PUT', '/api/settings/guard', edit),
    onSuccess: () => (setEdit(undefined), qc.invalidateQueries({ queryKey: ['guard'] })),
  });
  if (!q.data) return <ErrorBox error={q.error} />;
  return (
    <Card title="Rollback guard">
      <p className="mb-2 text-sm text-slate-600">Watches a canary, or a version just published, and rolls back or alerts when a signal trips. Saved on its own, not with the draft.</p>
      <JsonEditor label="Guard settings" value={edit ?? q.data} onChange={setEdit} onValidity={setOK} />
      <ErrorBox error={save.error} />
      <Button className="mt-2" variant="primary" disabled={!canManage || !edit || !ok || save.isPending} onClick={() => save.mutate()}>
        Save guard settings
      </Button>
    </Card>
  );
}
