import { useQuery } from '@tanstack/react-query';
import { useContext, useEffect, useState } from 'react';
import type { RuleGroupType, RuleType } from 'react-querybuilder';
import { api, type Checked, type Config, type Issue, type Json, type JsonObject, type Rendered, type Rule, type Schema } from '../api';
import { useDraft } from '../draft';
import { phaseOf, phases, rulesOf } from '../phases';
import { navigate, useLeaveGuard } from '../router';
import { RuleBuilder, toAST, usePreview } from '../RuleBuilder';
import { Errors, RuleForm } from '../RuleForms';
import { Button, CanWrite, Card, CodeEditor, ConfirmButton, Editable, ErrorBox, Hint, Input, Issues, JsonEditor, NotFound, Notice, Page, Pending, ReadOnlyNote, Reference } from '../ui';
import { RuleHistory } from './Versions';

// asGroup wraps a single-condition expression so the builder shows a row.
// The server's AST uses the builder's group and rule shapes.
const asGroup = (e: Json): RuleGroupType => {
  const g = e as Partial<RuleGroupType>;
  return g.rules || g.combinator ? { combinator: 'and', ...g, rules: g.rules ?? [] } : { combinator: 'and', rules: [e as RuleType] };
};

type PhaseKey = NonNullable<ReturnType<typeof phaseOf>>['key'];

// useRuleCheck asks the server to validate the draft with this rule in it,
// exactly as a save would. A result counts only for the input it checked,
// so Apply waits until what is on screen has been checked.
function useRuleCheck(config: Config, key: PhaseKey | undefined, index: number, rule: JsonObject, text: string | undefined, stamp: string) {
  const [res, setRes] = useState<{ stamp: string; config: Config; checked?: Checked; failed?: string }>();
  useEffect(() => {
    if (!key) return;
    const ctl = { cancelled: false };
    const base = `config.${key}[${index}]`;
    const t = setTimeout(() => {
      // Text is parsed first; a syntax error is the rule's problem, not a failed check.
      const expression = text === undefined ? Promise.resolve(rule.expression) : api<{ ast: Json }>('POST', '/api/expr/parse', { text }).then((r) => r.ast);
      expression
        .then(
          (ast) => {
            const list = config[key] ?? [];
            const r = { ...rule, expression: ast } as Rule;
            const next = { ...config, [key]: index < list.length ? list.map((x, i) => (i === index ? r : x)) : [...list, r] };
            return api<Checked>('POST', '/api/draft/check', { config: next });
          },
          (e: Error): Checked => ({ errors: [{ path: `${base}.expression`, message: e.message }], warnings: [] }),
        )
        .then((checked) => !ctl.cancelled && setRes({ stamp, config, checked }))
        .catch((e: Error) => !ctl.cancelled && setRes({ stamp, config, failed: e.message }));
    }, 300);
    return () => {
      ctl.cancelled = true;
      clearTimeout(t);
    };
    // stamp stands for rule and text, which are new objects every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stamp, config, key, index]);
  return res?.stamp === stamp && res.config === config ? res : undefined;
}

// mine keeps the issues for the rule at base, with paths relative to it,
// such as "limit" or "key[1]"; "" is the rule as a whole.
const mine = (issues: Issue[] | undefined, base: string) => (issues ?? []).filter((i) => i.path === base || i.path.startsWith(`${base}.`)).map((i) => ({ ...i, path: i.path.slice(base.length + 1) }));

// RuleEditor edits a rule. A new rule opened from a route (?route=<id>)
// starts with a condition that matches that route.
export function RuleEditor({ phase, id }: { phase: string; id: string }) {
  const route = id ? null : new URLSearchParams(window.location.search).get('route');
  const cond = useQuery({
    queryKey: ['route-condition', route],
    queryFn: () => api<{ expression: Json; text: string }>('GET', `/api/observed-routes/${route}/condition`),
    enabled: !!route,
  });
  if (!route) return <Editor phase={phase} id={id} />;
  if (!cond.data) return <Pending error={cond.error} />;
  return <Editor phase={phase} id={id} start={cond.data.expression} from={cond.data.text} />;
}

function Editor({ phase, id, start, from }: { phase: string; id: string; start?: Json; from?: string }) {
  const p = phaseOf(phase);
  const d = useDraft();
  const canWrite = useContext(CanWrite);
  const schema = useQuery({ queryKey: ['schema'], queryFn: () => api<Schema>('GET', '/api/expr/schema'), staleTime: Infinity });
  const existing = p && rulesOf(d.config, p.key).find((r) => r.id === id);
  const [ruleID, setRuleID] = useState(existing?.id ?? '');
  const [query, setQuery] = useState<RuleGroupType>(() => asGroup(existing?.expression ?? start ?? { combinator: 'and', rules: [] }));
  const [rest, setRest] = useState<JsonObject>(() => {
    if (!existing) return p?.blank ?? {};
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { id: _, expression: __, ...r } = existing;
    return r;
  });
  const [restOK, setRestOK] = useState(true);
  // Remounts the settings editor when the example replaces its text.
  const [restKey, setRestKey] = useState(0);
  const [text, setText] = useState<string>();
  // textBase is the text as rendered on switching, to tell edits from a look.
  const [textBase, setTextBase] = useState<string>();
  const [exprError, setExprError] = useState<unknown>();
  const [asJSON, setAsJSON] = useState(false);
  const preview = usePreview(query, p?.phase ?? 'config', text);
  const snapshot = JSON.stringify({ ruleID, ast: toAST(query), rest });
  const [initial] = useState(snapshot);
  const changed = snapshot !== initial || text !== textBase;
  const list = p ? rulesOf(d.config, p.key) : [];
  const index = existing ? list.indexOf(existing) : list.length;
  const check = useRuleCheck(d.config, p?.key, index, { id: ruleID, expression: toAST(query), ...rest }, text, `${snapshot}\u0000${text ?? ''}`);
  const base = `config.${p?.key}[${index}]`;
  // A new rule shows problems from its first edit, not before anything is
  // typed; an empty ID is explained by its field's hint. Apply stays off.
  const quiet = (is: Issue[]) => (existing || changed ? is : []).filter((i) => ruleID || i.path !== 'id');
  const all = mine(check?.checked?.errors, base);
  const errors = quiet(all);
  const warnings = quiet(mine(check?.checked?.warnings, base));
  const at = (f: string) => errors.filter((i) => i.path === f || i.path.startsWith(`${f}.`) || i.path.startsWith(`${f}[`));
  useLeaveGuard(changed ? 'This rule has changes not applied to the draft. Leave and lose them?' : undefined);
  if (!p) return <NotFound>There is no phase called “{phase}”.</NotFound>;
  if (id && !existing)
    return (
      <NotFound title="Rule not found">
        The draft has no {p.title.toLowerCase().replace(/s$/, '')} called “{id}”. It may have been deleted or renamed.
      </NotFound>
    );
  if (!schema.data) return <Pending error={schema.error} />;

  // Rendered now, not taken from the debounced preview, which can lag the
  // last edit.
  const toText = async () => {
    try {
      const r = await api<Rendered>('POST', '/api/expr/render', { ast: toAST(query), phase: p.phase });
      setText(r.text);
      setTextBase(r.text);
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
      setTextBase(undefined);
      setExprError(undefined);
    } catch (e) {
      setExprError(e);
    }
  };
  // Text is parsed on apply, so a rule typed as text applies without a trip
  // back through the builder.
  const apply = async () => {
    let expression = toAST(query);
    if (text !== undefined) {
      try {
        expression = (await api<{ ast: Json }>('POST', '/api/expr/parse', { text })).ast;
      } catch (e) {
        setExprError(e);
        return;
      }
    }
    const rule: Rule = { id: ruleID, expression, ...rest };
    d.setConfig((c) => {
      const list = rulesOf(c, p.key);
      return { ...c, [p.key]: existing ? list.map((r) => (r.id === existing.id ? rule : r)) : [...list, rule] };
    });
    navigate('/rules', { force: true });
  };
  const remove = () => {
    d.setConfig((c) => ({ ...c, [p.key]: rulesOf(c, p.key).filter((r) => r.id !== existing?.id) }));
    navigate('/rules', { force: true });
  };
  // Screens, links and Delete find a rule by its ID, so a second rule with
  // the same ID could not be opened or removed on its own.
  const taken = ruleID !== existing?.id && phases.find((x) => rulesOf(d.config, x.key).some((r) => r.id === ruleID));
  const blocked = !ruleID
    ? 'Give the rule an ID to apply it.'
    : taken
      ? `${taken.title} already has a rule called “${ruleID}”. Pick another ID: each rule's ID must be unique across all phases.`
      : !restOK
        ? 'Fix the JSON under Then to apply.'
        : !check
          ? 'Checking the rule…'
          : check.failed
            ? `Could not check the rule: ${check.failed}. Apply is off until it can be checked.`
            : all.length
              ? `Fix ${all.length === 1 ? 'the problem' : `the ${all.length} problems`} below to apply.`
              : undefined;
  return (
    <Page
      title={existing ? (canWrite ? `Edit ${existing.id}` : existing.id) : `New ${p.title.toLowerCase().replace(/s$/, '')}`}
      actions={
        <>
          {existing && canWrite && (
            <ConfirmButton
              variant="danger"
              title={`Delete ${existing.id}?`}
              action="Delete rule"
              confirm="The rule leaves the draft. Nothing changes in production until the draft is saved and published."
              onConfirm={remove}
            >
              Delete rule
            </ConfirmButton>
          )}
          <Button onClick={() => navigate('/rules')}>{canWrite ? 'Cancel' : 'Back to rules'}</Button>
          {canWrite && (
            <Button variant="primary" disabled={!!blocked} onClick={() => void apply()}>
              Apply to draft
            </Button>
          )}
        </>
      }
    >
      <ReadOnlyNote />
      <Editable>
        {from && (
          <Notice tone="green">
            Started from a route: <code className="break-all">{from}</code>. A <code>*</code> in a path wildcard also matches deeper paths, so narrow the condition if it should match this route only.
          </Notice>
        )}
        <div className="flex flex-col gap-1">
          <Input
            label="Rule ID"
            info="Unique across all three phases. Stats, the audit log and the rollback guard name the rule by it."
            hint="Lowercase letters, digits, - and _, such as login-per-ip."
            className="max-w-sm"
            value={ruleID}
            onChange={(e) => setRuleID(e.target.value)}
          />
          {/* An empty ID is already explained by the field's own hint. */}
          <Hint>{ruleID && blocked}</Hint>
          {!taken && <Errors issues={at('id')} />}
        </div>
        {/* Every problem is listed here too, so none hides under a closed section. */}
        <Issues issues={errors.map((i) => ({ ...i, path: i.path || 'rule' }))} />
        <Issues issues={warnings.map((i) => ({ ...i, path: i.path || 'rule' }))} tone="amber" />
        <Card
          title="When incoming requests match"
          info={
            <>
              Build the condition from fields and operators, or type it with Edit expression. Admin checks it as you go. An empty condition is <code>true</code> and matches every request.
            </>
          }
        >
          {text === undefined ? (
            <div className="flex flex-col gap-3">
              <RuleBuilder schema={schema.data} phase={p.phase} query={query} onChange={setQuery} />
              <div>
                <Button onClick={() => void toText()}>Edit expression</Button>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <CodeEditor
                label="Expression"
                value={text}
                onChange={(t) => {
                  setText(t);
                  setExprError(undefined);
                }}
              />
              <Hint>
                Such as <code>starts_with(http.request.uri.path, "/api/") and http.request.method in {'{"POST" "PUT"}'}</code>. Use <code>true</code> to match every request.
              </Hint>
              <div>
                <Button onClick={() => void toBuilder()}>Use builder</Button>
              </div>
            </div>
          )}
          <ErrorBox error={exprError} />
          <section aria-label="Preview" className="mt-4 flex flex-col gap-2">
            <h3 className="text-sm font-medium text-heading">Expression preview</h3>
            {preview && 'text' in preview && (
              <>
                <pre data-testid="preview-text" className="whitespace-pre-wrap wrap-anywhere">
                  {preview.text}
                </pre>
                {preview.text === 'true' && <p className="text-sm text-body">Matches every request.</p>}
                <Issues issues={preview.errors} />
                <Issues issues={preview.warnings} tone="amber" />
              </>
            )}
            {preview && 'failed' in preview && <Issues issues={[{ path: '', message: preview.failed }]} />}
          </section>
        </Card>
        <Card title="Then" intro={asJSON ? 'What the rule does, as JSON.' : 'What the rule does. Every choice is checked as you make it.'}>
          {asJSON ? (
            <>
              <JsonEditor key={restKey} label="Rule settings" value={rest} onChange={setRest} onValidity={setRestOK} />
              <Reference
                fields={p.fields}
                example={p.example}
                onUse={() => {
                  setRest(p.example);
                  setRestOK(true);
                  setRestKey((k) => k + 1);
                }}
              />
            </>
          ) : (
            <RuleForm phase={p.phase} value={rest} onChange={setRest} choices={schema.data.rules} config={d.config} at={at} />
          )}
          <div className="mt-4">
            {/* The form cannot show text that does not parse, so JSON must be valid to leave it. */}
            <Button disabled={!restOK} onClick={() => (setAsJSON(!asJSON), setRestKey((k) => k + 1))}>
              {asJSON ? 'Use the form' : 'Edit as JSON'}
            </Button>
          </div>
        </Card>
      </Editable>
      {existing && <RuleHistory id={existing.id} />}
    </Page>
  );
}
