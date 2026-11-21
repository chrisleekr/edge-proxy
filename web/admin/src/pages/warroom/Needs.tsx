import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useId, useState } from 'react';
import { api, useCan } from '../../api';
import type { AttentionItem, useAttention } from '../../attention';
import { Link } from '../../router';
import { autopilotQuery } from '../Autopilot';
import { color, Head, Widget } from './shared';

type Att = ReturnType<typeof useAttention>;
type Autopilot = NonNullable<ReturnType<typeof useAutopilot>['data']>;

const useAutopilot = (on: boolean) => useQuery({ ...autopilotQuery, enabled: on });

// The project docs site, from site_url in mkdocs.yml.
const runbooks = 'https://chrisleekr.github.io/edge-proxy/operate/runbooks/';

const tones = {
  danger: { word: 'Critical', fg: color.red, bg: '#2a0e0f', ring: 'rgba(255,97,102,.45)' },
  warning: { word: 'Warning', fg: color.amber, bg: '#2a1e05', ring: 'rgba(245,181,68,.4)' },
  neutral: { word: 'Info', fg: color.body, bg: '#141414', ring: 'rgba(255,255,255,.14)' },
};

// suggest says what the item's own action leads to, one fixed sentence per kind.
function suggest(it: AttentionItem) {
  const signal = it.anomaly?.signal;
  const kind = it.key.split(':')[0];
  if (signal === 'traffic_surge') return 'Notifications shows when the surge started. Check whether the extra traffic is wanted, and ask the autopilot to look at it if not.';
  if (signal === 'rule_fail_mode') return 'Check that the edges can reach Valkey. Each rule\'s "When Valkey cannot answer" setting decides its requests meanwhile.';
  if (it.anomaly?.phase === 'verified_bots') return 'Fleet shows when each crawler range list was last fetched.';
  if (kind === 'anomaly') return 'Notifications shows this signal, what tripped it and when.';
  const by: Record<string, string> = {
    kill: 'Settings shows the kill switches. Find out why it was switched off before switching it back.',
    rollback: 'The version page shows why it was rolled back. Fix the change in the draft before publishing again.',
    guard: 'The version page shows what the guard measured and why the version was kept.',
    canary: 'Publish is where you promote the canary or stop it.',
    fallback: 'Fleet shows which edges run on a saved copy or their bootstrap file. Check that they can reach admin.',
    behind: 'Fleet lists each edge and the versions it has loaded.',
    valkey: 'Stats shows rate limit checks by rule. Check that the edges can reach Valkey.',
    shadow: 'Review opens the rule. Set it to block if requests over its limit should get a 429.',
    audit: 'The audit log shows the event where the check failed.',
  };
  return by[kind!] ?? `Open ${it.action} for the detail.`;
}

function runbook(it: AttentionItem): [string, string] | undefined {
  const signal = it.anomaly?.signal;
  if (it.key === 'valkey' || signal === 'rule_fail_mode') return ['#valkey-down', 'Runbook: Valkey down'];
  if (signal === 'traffic_surge') return ['#a-flood', 'Runbook: A flood'];
  if (it.key.startsWith('audit:')) return ['#audit-chain-broken', 'Runbook: Audit chain broken'];
  if (it.key.startsWith('rollback:') || it.key.startsWith('guard:')) return ['#a-bad-publish', 'Runbook: A bad publish'];
}

// age reads as minutes, or whole hours from 120 minutes.
const age = (iso: string) => {
  const n = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60_000));
  return n < 120 ? `${n} min` : `${Math.floor(n / 60)} h`;
};

export function NeedsPerson({ att, wall, expanded, onExpand }: { att: Att; wall: boolean; expanded: string | null; onExpand: (name: string | null) => void }) {
  const can = useCan();
  const manage = can('autopilot.manage');
  const autopilot = useAutopilot(can('autopilot.read'));
  const [asking, setAsking] = useState(false);
  const [question, setQuestion] = useState('');
  const [selected, setSelected] = useState<string>();
  const qc = useQueryClient();
  const open = useMutation({
    mutationFn: () => api<{ id: number }>('POST', '/api/autopilot/cases', { question }),
    onSuccess: () => {
      setAsking(false);
      setQuestion('');
      void qc.invalidateQueries({ queryKey: autopilotQuery.queryKey });
    },
  });
  const field = useId();
  const items = att.shown;
  const current = items.find((it) => it.key === selected) ?? items[0];
  const budget = autopilot.data?.budgets.cases_hour;
  return (
    <Widget label="Needs a person" name="needs" expanded={expanded} onExpand={onExpand} wall={wall} style={{ flex: '1 1 auto', ...(wall && { overflow: 'hidden' }) }}>
      <Head
        title={
          <>
            Needs a person, now
            {items.length > 0 && <span style={{ fontSize: 15, fontWeight: 400, color: color.body, marginLeft: 6 }}>{items.length} open</span>}
          </>
        }
      >
        {manage && !wall && (
          <button type="button" className="wr-btn" aria-expanded={asking} onClick={() => setAsking(!asking)}>
            Ask autopilot
          </button>
        )}
      </Head>
      {asking && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: 12, borderRadius: 8, background: '#0f0f0f', boxShadow: '0 0 0 1px rgba(255,255,255,.14)' }}>
          <label htmlFor={field} style={{ color: color.heading, fontWeight: 500 }}>
            Question for the autopilot
          </label>
          <textarea
            id={field}
            rows={3}
            maxLength={2000}
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Why are refusals up for Brazil on /api/search?"
            style={{ font: 'inherit', fontSize: 15, color: color.heading, background: '#1a1a1a', border: 0, borderRadius: 6, padding: '8px 10px', boxShadow: '0 0 0 1px rgba(255,255,255,.2)', resize: 'vertical' }}
          />
          {budget && (
            <span style={{ fontSize: 14 }}>
              {budget.used} of {budget.max} cases used this hour
            </span>
          )}
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" className="wr-btn wr-btn-primary" disabled={question.trim() === '' || open.isPending} onClick={() => open.mutate()}>
              Open case
            </button>
            <button type="button" className="wr-btn" onClick={() => setAsking(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      <div role="status">
        {(att.send.error ?? att.acks.error) && <span style={{ color: color.red }}>{(att.send.error ?? att.acks.error)!.message}</span>}
        {open.isSuccess && (
          <span style={{ color: color.green }}>
            Case {open.data.id} opened: the autopilot is investigating your question. <Link to={`/autopilot/cases/${open.data.id}`}>Open case {open.data.id}</Link>
          </span>
        )}
      </div>
      {open.isError && <span style={{ color: color.red }}>{open.error.message}</span>}
      {items.length === 0 &&
        (att.waiting ? (
          <p>Checking…</p>
        ) : (
          <div style={{ padding: '28px 8px', textAlign: 'center' }}>
            <span style={{ color: color.green, fontSize: 20, fontWeight: 600 }}>Nothing needs a person</span>
            <p style={{ fontSize: 14, color: color.muted, margin: '8px 0 0' }}>Checked: {att.checked.join(', ')}</p>
          </div>
        ))}
      {items.map((it) => {
        const t = tones[it.tone];
        const on = it === current;
        const since = it.since && (it.anomaly ? `Firing ${age(it.since)}` : `Since ${age(it.since)}`);
        return (
          <div key={it.key} style={{ borderRadius: 8, padding: 12, background: on ? t.bg : '#0f0f0f', boxShadow: `0 0 0 1px ${t.ring}`, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <button type="button" className="wr-item" aria-expanded={!wall && on} onClick={() => setSelected(it.key)}>
              <span style={{ display: 'flex', gap: 10, alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: '.06em', textTransform: 'uppercase', color: t.fg }}>{t.word}</span>
                <span className="wr-eyebrow">{since}</span>
              </span>
              <span style={{ color: color.heading, fontWeight: 600, fontSize: 17 }}>{it.say}</span>
            </button>
            {!wall && on && <Detail key={it.key} it={it} att={att} autopilot={autopilot.data} manage={manage} />}
          </div>
        );
      })}
    </Widget>
  );
}

// Detail is the selected item's body and actions. It is keyed by the item,
// so a status line belongs to the item it was run on.
function Detail({ it, att, autopilot, manage }: { it: AttentionItem; att: Att; autopilot: Autopilot | undefined; manage: boolean }) {
  const a = it.anomaly;
  const rule = a?.case_id != null ? autopilot?.rules.find((r) => r.kind === 'enforce' && r.state === 'observing' && r.case_id === a.case_id) : undefined;
  const approve = useMutation({ mutationFn: () => api('POST', `/api/autopilot/rules/${encodeURIComponent(rule!.id)}/enforce`) });
  const ask = useMutation({ mutationFn: () => api<{ id: number }>('POST', '/api/autopilot/cases', { anomaly_id: a!.id }) });
  const book = runbook(it);
  const state = a?.case_state;
  const caseSays = !a ? undefined : a.case_id == null ? 'No case yet.' : state === 'queued' || state === 'running' ? `Case ${a.case_id}: investigating.` : `Case ${a.case_id}: ${a.case_verdict ?? state}.`;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <span>{it.text}</span>
      {caseSays && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, borderTop: '1px solid #2e2e2e', paddingTop: 10 }}>
          <span className="wr-eyebrow">Autopilot</span>
          <span style={{ color: color.heading }}>
            {caseSays}
            {rule && ` It proposes blocking with rule ${rule.id}.`}
          </span>
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <span className="wr-eyebrow">Suggested</span>
        <span>{suggest(it)}</span>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        <Link to={it.to} className="wr-btn">
          {it.action}
        </Link>
        {book && (
          <a className="wr-btn" href={runbooks + book[0]} target="_blank" rel="noreferrer">
            {book[1]}
          </a>
        )}
        {a?.case_id != null && (
          <Link to={`/autopilot/cases/${a.case_id}`} className="wr-btn">
            Open case {a.case_id}
          </Link>
        )}
        {rule && manage && (
          <button type="button" className="wr-btn wr-btn-primary" disabled={approve.isPending || approve.isSuccess} onClick={() => approve.mutate()}>
            Approve blocking
          </button>
        )}
        {a && a.case_id == null && manage && a.phase !== 'verified_bots' && a.phase !== 'autopilot' && (
          <button type="button" className="wr-btn" disabled={ask.isPending || ask.isSuccess} onClick={() => ask.mutate()}>
            Ask autopilot
          </button>
        )}
        {att.canAck && (
          <button type="button" className="wr-btn" disabled={att.send.isPending} onClick={() => att.send.mutate({ it })}>
            Acknowledge
          </button>
        )}
      </div>
      <div role="status">
        {approve.isSuccess && <span style={{ color: color.green }}>Approved: it blocks from the next autopilot run if its counts still hold.</span>}
        {ask.isSuccess && (
          <span style={{ color: color.green }}>
            Case {ask.data.id} opened for this anomaly: the autopilot is investigating. <Link to={`/autopilot/cases/${ask.data.id}`}>Open case {ask.data.id}</Link>
          </span>
        )}
        {approve.isError && <span style={{ color: color.red }}>{approve.error.message}</span>}
        {ask.isError && <span style={{ color: color.red }}>{ask.error.message}</span>}
      </div>
    </div>
  );
}
