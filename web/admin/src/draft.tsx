import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createContext, type ReactNode, useCallback, useContext, useEffect, useState } from 'react';
import { api, type Checked, type Config, type Draft, etag, type Issue, type Json, Problem, type Saved } from './api';
import { useBeforeUnload, useLeaveGuard } from './router';
import { Pending } from './ui';

// The draft is one document saved whole with If-Match.
// Screens edit a local copy; Save sends it and the server validates it.

interface DraftState {
  draft: Draft;
  config: Config;
  tests: Json[];
  dirty: boolean;
  // stale: someone saved the draft after these edits started.
  stale: boolean;
  // invalid names the editors holding text that is not JSON.
  invalid: string[];
  // discards counts discards, so editors holding text that never parsed
  // can remount: their value did not change, so they would keep it.
  discards: number;
  // check is the server's check of exactly this config, or undefined while
  // one runs. A saved draft passed it when it was saved.
  check: { checked?: Checked; failed?: string } | undefined;
  // at lists the check's errors for a config path such as
  // global.backstop.limit, and anything inside it, with "config." removed.
  at: (field: string) => Issue[];
  setConfig: (f: (c: Config) => Config) => void;
  setTests: (t: Json[]) => void;
  markInvalid: (key: string, bad: boolean) => void;
  save: () => Promise<Saved>;
  discard: () => void;
}

const Ctx = createContext<DraftState | null>(null);

export const useDraft = () => useContext(Ctx)!;
export const useOptionalDraft = () => useContext(Ctx);

export const draftKey = ['draft'];

export function DraftProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [edit, setEdit] = useState<{ config: Config; tests: Json[]; revision: number }>();
  // While edits are unsaved, a save by someone else shows up within 30s, so
  // the stale warning comes before more work goes into them.
  const q = useQuery({ queryKey: draftKey, queryFn: () => api<Draft>('GET', '/api/draft'), refetchInterval: edit ? 30_000 : false });
  const [bad, setBad] = useState<Set<string>>(new Set());
  const [discards, setDiscards] = useState(0);
  const markInvalid = useCallback(
    (key: string, isBad: boolean) =>
      setBad((s) => {
        if (s.has(key) === isBad) return s;
        const n = new Set(s);
        if (isBad) n.add(key);
        else n.delete(key);
        return n;
      }),
    [],
  );
  // Every edit is checked as a save would check it, so a section form can
  // show each problem by its field and Save waits for a clean result.
  const [checked, setChecked] = useState<{ config: Config; checked?: Checked; failed?: string }>();
  const editing = edit?.config;
  useEffect(() => {
    if (!editing) return;
    const ctl = { cancelled: false };
    const t = setTimeout(() => {
      api<Checked>('POST', '/api/draft/check', { config: editing })
        .then((c) => !ctl.cancelled && setChecked({ config: editing, checked: c }))
        .catch((e: Error) => !ctl.cancelled && setChecked({ config: editing, failed: e.message }));
    }, 300);
    return () => {
      ctl.cancelled = true;
      clearTimeout(t);
    };
  }, [editing]);
  // The draft lives only in this tab until saved.
  useBeforeUnload(edit !== undefined);
  useLeaveGuard(bad.size > 0 ? `${[...bad].join(', ')} is not valid JSON. Leave and lose that text?` : undefined);
  if (!q.data) return <Pending error={q.error} />;
  const draft = q.data;
  // Edits keep the revision they started from, so saving over someone
  // else's newer save fails with 412 instead of overwriting it.
  const revision = edit?.revision ?? draft.revision;
  const config = edit?.config ?? draft.config;
  const tests = edit?.tests ?? draft.tests ?? [];
  const check = !edit ? { checked: { errors: [], warnings: [] } } : checked?.config === edit.config ? checked : undefined;
  // An edit typed back to the saved draft is no edit: the bar and the leave
  // guard go quiet. Same key order is enough, as forms keep it.
  const change = (c: Config, t: Json[]) =>
    setEdit(revision === draft.revision && JSON.stringify(c) === JSON.stringify(draft.config) && JSON.stringify(t) === JSON.stringify(draft.tests ?? []) ? undefined : { config: c, tests: t, revision });
  const errors = (check?.checked?.errors ?? []).map((i) => ({ ...i, path: i.path.replace(/^config\./, '') }));
  const state: DraftState = {
    draft,
    config,
    tests,
    dirty: edit !== undefined,
    stale: edit !== undefined && edit.revision !== draft.revision,
    invalid: [...bad],
    discards,
    check,
    at: (f) => errors.filter((i) => i.path === f || i.path.startsWith(`${f}.`) || i.path.startsWith(`${f}[`)),
    markInvalid,
    setConfig: (f) => change(f(config), tests),
    setTests: (t) => change(config, t),
    save: async () => {
      const saved = await api<Saved>('PUT', '/api/draft', { config, tests }, { 'If-Match': etag(revision) }).catch(async (e: unknown) => {
        // Someone saved first: fetch their revision so the bar says so.
        if (e instanceof Problem && e.status === 412) await qc.invalidateQueries({ queryKey: draftKey });
        throw e;
      });
      // The saved draft replaces the edit at once, so no screen shows the
      // previous revision while the refetch runs.
      qc.setQueryData<Draft>(draftKey, { ...draft, config, tests, revision: saved.revision });
      setEdit(undefined);
      await qc.invalidateQueries({ queryKey: draftKey });
      return saved;
    },
    discard: () => {
      setEdit(undefined);
      setBad(new Set());
      setDiscards((n) => n + 1);
    },
  };
  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}
