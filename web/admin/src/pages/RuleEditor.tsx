import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import type { RuleGroupType, RuleType } from 'react-querybuilder';
import { api, type Json, type JsonObject, type Rendered, type Rule, type Schema } from '../api';
import { useDraft } from '../draft';
import { phaseOf, rulesOf } from '../phases';
import { navigate } from '../router';
import { RuleBuilder, toAST, usePreview } from '../RuleBuilder';
import { Button, Card, CodeEditor, ErrorBox, Input, Issues, JsonEditor, Page } from '../ui';
import { RuleHistory } from './Versions';

// asGroup wraps a single-condition expression so the builder shows a row.
// The server's AST uses the builder's group and rule shapes.
const asGroup = (e: Json): RuleGroupType => {
  const g = e as Partial<RuleGroupType>;
  return g.rules || g.combinator ? { combinator: 'and', ...g, rules: g.rules ?? [] } : { combinator: 'and', rules: [e as RuleType] };
};

export function RuleEditor({ phase, id }: { phase: string; id: string }) {
  const p = phaseOf(phase);
  const d = useDraft();
  const schema = useQuery({ queryKey: ['schema'], queryFn: () => api<Schema>('GET', '/api/expr/schema'), staleTime: Infinity });
  const existing = p && rulesOf(d.config, p.key).find((r) => r.id === id);
  const [ruleID, setRuleID] = useState(existing?.id ?? '');
  const [query, setQuery] = useState<RuleGroupType>(() => asGroup(existing?.expression ?? { combinator: 'and', rules: [] }));
  const [rest, setRest] = useState<JsonObject>(() => {
    if (!existing) return p?.blank ?? {};
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { id: _, expression: __, ...r } = existing;
    return r;
  });
  const [restOK, setRestOK] = useState(true);
  const [text, setText] = useState<string>();
  const [exprError, setExprError] = useState<unknown>();
  const preview = usePreview(query, p?.phase ?? 'config');
  if (!p) return <p>Unknown phase.</p>;
  if (id && !existing) return <p>No rule {id} in the draft.</p>;
  if (!schema.data) return <ErrorBox error={schema.error} />;

  // Rendered now, not taken from the debounced preview, which can lag the
  // last edit.
  const toText = async () => {
    try {
      const r = await api<Rendered>('POST', '/api/expr/render', { ast: toAST(query), phase: p.phase });
      setText(r.text);
      setExprError(undefined);
    } catch (e) {
      setExprError(e);
    }
  };
  const toBuilder = async () => {
    try {
      const { ast } = await api<{ ast: Json }>('POST', '/api/expr/parse', { text });
      setQuery(asGroup(ast));
      setText(undefined);
      setExprError(undefined);
    } catch (e) {
      setExprError(e);
    }
  };
  const apply = () => {
    const rule: Rule = { id: ruleID, expression: toAST(query), ...rest };
    d.setConfig((c) => {
      const list = rulesOf(c, p.key);
      return { ...c, [p.key]: existing ? list.map((r) => (r.id === existing.id ? rule : r)) : [...list, rule] };
    });
    navigate('/');
  };
  const remove = () => {
    d.setConfig((c) => ({ ...c, [p.key]: rulesOf(c, p.key).filter((r) => r.id !== existing?.id) }));
    navigate('/');
  };
  return (
    <Page
      title={existing ? `Edit ${existing.id}` : `New ${p.title.toLowerCase().replace(/s$/, '')}`}
      actions={
        <>
          {existing && (
            <Button variant="danger" onClick={remove}>
              Delete rule
            </Button>
          )}
          <Button onClick={() => navigate('/')}>Cancel</Button>
          <Button variant="primary" disabled={!ruleID || !restOK || text !== undefined} onClick={apply}>
            Apply to draft
          </Button>
        </>
      }
    >
      <Input label="Rule ID" className="max-w-sm" value={ruleID} onChange={(e) => setRuleID(e.target.value)} />
      <Card title="When incoming requests match">
        {text === undefined ? (
          <div className="flex flex-col gap-3">
            <RuleBuilder schema={schema.data} phase={p.phase} query={query} onChange={setQuery} />
            <div>
              <Button onClick={() => void toText()}>Edit expression</Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            <CodeEditor label="Expression" value={text} onChange={setText} />
            <div>
              <Button onClick={() => void toBuilder()}>Use builder</Button>
            </div>
          </div>
        )}
        <ErrorBox error={exprError} />
        <section aria-label="Preview" className="mt-4 flex flex-col gap-2">
          <h3 className="text-sm font-medium text-slate-700">Expression preview</h3>
          {preview && 'text' in preview && (
            <>
              <pre data-testid="preview-text" className="overflow-x-auto rounded bg-slate-100 p-2 text-sm whitespace-pre-wrap">
                {preview.text || '(all incoming requests)'}
              </pre>
              <p className="text-xs text-slate-500">{preview.length} characters</p>
              <Issues issues={preview.errors} />
              <Issues issues={preview.warnings} tone="amber" />
            </>
          )}
          {preview && 'failed' in preview && <p role="alert">{preview.failed}</p>}
        </section>
      </Card>
      <Card title="Then">
        <JsonEditor label="Rule settings" value={rest} onChange={setRest} onValidity={setRestOK} />
        <p className="mt-2 text-xs text-slate-500">Checked when the draft is saved.</p>
      </Card>
      {existing && <RuleHistory id={existing.id} />}
    </Page>
  );
}
