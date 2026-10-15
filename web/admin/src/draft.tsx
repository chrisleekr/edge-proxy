import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createContext, type ReactNode, useCallback, useContext, useState } from 'react';
import { api, type Config, type Draft, etag, type Json, type Saved } from './api';
import { ErrorBox } from './ui';

// The draft is one document saved whole with If-Match.
// Screens edit a local copy; Save sends it and the server validates it.

interface DraftState {
  draft: Draft;
  config: Config;
  tests: Json[];
  dirty: boolean;
  // stale: someone saved the draft after these edits started.
  stale: boolean;
  invalid: boolean;
  // discards counts discards, so editors holding text that never parsed
  // can remount: their value did not change, so they would keep it.
  discards: number;
  setConfig: (f: (c: Config) => Config) => void;
  setTests: (t: Json[]) => void;
  markInvalid: (key: string, bad: boolean) => void;
  save: () => Promise<Saved>;
  discard: () => void;
}

const Ctx = createContext<DraftState | null>(null);

export const useDraft = () => useContext(Ctx)!;

export const draftKey = ['draft'];

export function DraftProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: draftKey, queryFn: () => api<Draft>('GET', '/api/draft') });
  const [edit, setEdit] = useState<{ config: Config; tests: Json[]; revision: number }>();
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
  if (q.error) return <ErrorBox error={q.error} />;
  if (!q.data) return <p>Loading draft…</p>;
  const draft = q.data;
  // Edits keep the revision they started from, so saving over someone
  // else's newer save fails with 412 instead of overwriting it.
  const revision = edit?.revision ?? draft.revision;
  const config = edit?.config ?? draft.config;
  const tests = edit?.tests ?? draft.tests ?? [];
  const state: DraftState = {
    draft,
    config,
    tests,
    dirty: edit !== undefined,
    stale: edit !== undefined && edit.revision !== draft.revision,
    invalid: bad.size > 0,
    discards,
    markInvalid,
    setConfig: (f) => setEdit({ config: f(config), tests, revision }),
    setTests: (t) => setEdit({ config, tests: t, revision }),
    save: async () => {
      const saved = await api<Saved>('PUT', '/api/draft', { config, tests }, { 'If-Match': etag(revision) });
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
