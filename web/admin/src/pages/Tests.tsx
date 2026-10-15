import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { api, type Json, type TestResult } from '../api';
import { useDraft } from '../draft';
import { Badge, Button, Card, ErrorBox, Input, JsonEditor, Page } from '../ui';

export function Tests({ canTest }: { canTest: boolean }) {
  const d = useDraft();
  const run = useMutation({ mutationFn: () => api<TestResult[]>('POST', '/api/tests/run') });
  const [request, setRequest] = useState<Json>({ method: 'GET', host: 'api.example.com', path: '/' });
  const [requestOK, setRequestOK] = useState(true);
  const [version, setVersion] = useState('');
  const sim = useMutation({ mutationFn: () => api<Json>('POST', '/api/simulate', { version: version ? Number(version) : null, request }) });
  return (
    <Page title="Tests and simulate">
      <Card title="Config tests">
        <p className="mb-2 text-sm text-slate-600">Each test is a request and what the draft must do with it. Publishing is blocked while any test fails.</p>
        <JsonEditor label="Tests" value={d.tests} onChange={d.setTests} onValidity={(ok) => d.markInvalid('Tests', !ok)} />
        <Button className="mt-2" disabled={!canTest || d.dirty || run.isPending} onClick={() => run.mutate()}>
          Run tests on the saved draft
        </Button>
        {d.dirty && <p className="mt-1 text-xs text-slate-500">Save the draft first.</p>}
        <ErrorBox error={run.error} />
        {run.data && (
          <ul className="mt-2 flex flex-col gap-1 text-sm" aria-label="Test results">
            {run.data.map((t) => (
              <li key={t.name}>
                <Badge tone={t.pass ? 'green' : 'red'}>{t.pass ? 'pass' : 'fail'}</Badge> {t.name}
                {t.failures && <span className="text-red-800">: {t.failures.join('; ')}</span>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Simulate a request">
        <p className="mb-2 text-sm text-slate-600">Runs the edge's own request pipeline on a synthetic request. Rate limits are matched but not counted.</p>
        <Input label="Version (empty for the saved draft)" className="max-w-xs" inputMode="numeric" value={version} onChange={(e) => setVersion(e.target.value)} />
        <div className="mt-2">
          <JsonEditor label="Request" value={request} onChange={setRequest} onValidity={setRequestOK} />
        </div>
        <Button className="mt-2" disabled={!canTest || !requestOK || sim.isPending} onClick={() => sim.mutate()}>
          Simulate
        </Button>
        <ErrorBox error={sim.error} />
        {sim.isSuccess && (
          <pre data-testid="simulate-result" className="mt-2 overflow-x-auto rounded bg-slate-100 p-2 text-sm">
            {JSON.stringify(sim.data, null, 2)}
          </pre>
        )}
      </Card>
    </Page>
  );
}
