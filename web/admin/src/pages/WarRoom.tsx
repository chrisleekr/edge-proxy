import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { type CSSProperties, useEffect, useMemo, useState } from 'react';
import { api, useCan } from '../api';
import { type AttentionItem, quiet, useAttention, useDashboardData } from '../attention';
import { who } from '../ui';
import { Link, useSearch } from '../router';
import { said } from './Audit';
import { type RangeKey, ranges, useMarks, useRangeKey } from './Fleet';
import { type Bucket, type StatRow, Codes, OutcomeChart, ResponseTime, RoutesHit, RulesRefusing, bandsOf, fold, hist, hm, inRange, minute, pctIdx, perMin, stampOf, sumB, total, upTo } from './warroom/Charts';
import { WarMap } from './warroom/Map';
import { NeedsPerson } from './warroom/Needs';
import { Widget, Head, type View, color, fmt, share, short } from './warroom/shared';
import './warroom/warroom.css';

const grey = { color: '#a1a1a1', wash: '#141414', ring: 'rgba(255,255,255,.14)' };
const tones = {
  danger: { color: color.red, wash: '#2a0e0f', ring: 'rgba(255,97,102,.45)' },
  warning: { color: color.amber, wash: '#2a1e05', ring: 'rgba(245,181,68,.4)' },
  neutral: grey,
};

// Clock is its own component so the board does not redraw every second.
function Clock({ live }: { live: boolean }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const d = new Date(now);
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}>
      <span aria-hidden="true" className={live ? 'wr-live-dot' : ''} style={{ width: 8, height: 8, borderRadius: '50%', background: live ? color.green : color.muted }} />
      <span className="wr-num wr-mono" style={{ color: color.heading, fontSize: 18 }}>
        {d.toISOString().slice(11, 19)} UTC
      </span>
      {live && <span>Live · last 5 minutes</span>}
    </span>
  );
}

// Which anomaly signals colour which tile; the Valkey tile also follows the Valkey item.
const tileSignals = {
  requests: ['traffic_surge', 'traffic_drop'],
  refused: ['rule_block_spike'],
  response: ['p99_latency'],
  fivexx: ['edge_5xx_ratio', 'upstream_5xx_ratio', 'rule_edge_5xx_ratio', 'rule_upstream_5xx_ratio'],
  token: ['auth_failure_ratio', 'rule_auth_failure_ratio'],
  valkey: ['rule_fail_mode'],
};

// tint is a tile's colour, from what needs a person and never a threshold of its own.
function tint(att: ReturnType<typeof useAttention>, signals: string[], valkey = false) {
  const match = (it: AttentionItem) => signals.includes(it.anomaly?.signal ?? '') || (valkey && it.key === 'valkey');
  const shown = att.shown.filter(match);
  if (shown.some((it) => it.tone === 'danger')) return color.red;
  if (shown.some((it) => it.tone === 'warning') || att.acked.some(match)) return color.amber;
  return null;
}

function sparkPoints(vals: number[]) {
  const lo = Math.min(...vals);
  const span = Math.max(...vals) - lo || 1;
  return vals.map((x, i) => `${((i * 120) / Math.max(1, vals.length - 1)).toFixed(1)},${(29 - ((x - lo) / span) * 26).toFixed(1)}`).join(' ');
}

export function WarRoom() {
  const can = useCan();
  const d = useDashboardData(can);
  const att = useAttention(d, can);
  const [params, setParams] = useSearch();
  const [key, setKey] = useRangeKey();
  const live = params.get('view') !== 'period';
  const [wall, setWall] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [zoomed, setZoomed] = useState<{ key: RangeKey; from: number; to: number; cur: number } | null>(null);
  // Set when a drag left Live, so the reset button goes back to it.
  const [fromLive, setFromLive] = useState(false);
  const zoom = !live && zoomed?.key === key ? zoomed : null;

  useEffect(() => {
    document.title = 'War room · Edge Policy Admin';
  }, []);
  useEffect(() => {
    if (!expanded) return;
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setExpanded(null);
    document.addEventListener('keydown', esc);
    return () => document.removeEventListener('keydown', esc);
  }, [expanded]);
  // The browser's own exit from fullscreen, such as Esc, leaves the wall too.
  useEffect(() => {
    const out = () => {
      if (!document.fullscreenElement) setWall(false);
    };
    document.addEventListener('fullscreenchange', out);
    return () => document.removeEventListener('fullscreenchange', out);
  }, []);

  const { minutes, step } = live ? { minutes: 66, step: 1 } : ranges[key];
  const q = useQuery({
    // Its own key: the dashboard data's range query polls ['stats', minutes, step]
    // and would refetch a zoomed span this query freezes.
    queryKey: ['stats', minutes, step, 'warroom'],
    queryFn: () => api<StatRow[]>('GET', `/api/stats?minutes=${minutes}&step=${step}`),
    // A zoomed span is frozen: a refetch would slide the fetched window off its buckets.
    refetchInterval: zoom ? false : live || minutes <= 1440 ? 10_000 : 60_000,
    placeholderData: keepPreviousData,
    enabled: can('stats.read'),
  });
  // Time comes from the data's fetch, so the newest minute fills as its figures arrive.
  const [seen, setSeen] = useState(Date.now);
  // A range change shows the old rows with no fetch time yet, so the last one stays.
  if (q.dataUpdatedAt && q.dataUpdatedAt !== seen) setSeen(q.dataUpdatedAt);
  const cur = zoom ? zoom.cur : Math.floor(seen / minute) * minute;
  const rows = q.data;

  const data = useMemo(() => {
    const stepMs = step * minute;
    if (live) {
      const all = fold(rows ?? [], Array.from({ length: 65 }, (_, i) => cur - (65 - i) * minute));
      return { full: all.slice(5), win: all.slice(60), prior: all.slice(0, 60) };
    }
    const end = cur + minute;
    const start = Math.floor((end - minutes * minute) / stepMs) * stepMs;
    const full = fold(rows ?? [], Array.from({ length: Math.ceil((end - start) / stepMs) }, (_, i) => start + i * stepMs));
    return { full, win: [] as Bucket[], prior: [] as Bucket[] };
  }, [rows, live, cur, minutes, step]);
  const stepMs = step * minute;
  const vb = zoom ? data.full.filter((b) => b.t >= zoom.from && b.t < zoom.to) : data.full;
  const win = live ? data.win : vb;
  const days = ranges[live ? '1h' : key].minutes >= 1440;
  const last = vb[vb.length - 1];
  const inView = live ? ranges['1h'].label : zoom && vb.length ? `${stampOf(vb[0]!.t, days, step)} to ${last!.t + stepMs > cur ? 'now' : stampOf(last!.t, days, step)}` : ranges[key].label;
  const from = live ? cur - 5 * minute : zoom ? zoom.from : (vb[0]?.t ?? cur);
  const to = live ? cur : zoom ? zoom.to : (last?.t ?? cur) + stepMs;
  const view: View = { live, from, to, inView };
  const winRows = rows ? inRange(rows, from, to) : [];
  const chartFrom = live ? cur - 60 * minute : from;
  const marks = useMarks(chartFrom).filter((m) => m.t >= chartFrom && m.t < (live ? cur : to));
  const bands = bandsOf(d.anomalies?.data?.anomalies ?? [], chartFrom, live ? cur : to);

  const goLive = () => {
    setParams({ view: '' });
    setZoomed(null);
    setFromLive(false);
  };
  const goPeriod = () => {
    setParams({ view: 'period' });
    setZoomed(null);
    setFromLive(false);
  };
  const onZoom = (zf: number, zt: number) => {
    if (live) {
      setFromLive(true);
      setParams({ view: 'period', range: '1h' });
    }
    // From Live the period window ends one minute earlier so it still holds Live's first minute.
    setZoomed({ key: live ? '1h' : key, from: zf, to: zt, cur: live ? cur - minute : cur });
  };
  const enterWall = () => {
    setWall(true);
    setExpanded(null);
    goLive();
    try {
      document.documentElement.requestFullscreen().catch(() => {});
    } catch {
      // Fullscreen can be refused; the wall still works in the window.
    }
  };
  const leaveWall = () => {
    setWall(false);
    try {
      if (document.fullscreenElement) void document.exitFullscreen().catch(() => {});
    } catch {
      // Already out.
    }
  };

  // Status pill
  const n = att.shown.length;
  const status =
    n === 0
      ? att.waiting
        ? { ...grey, label: 'CHECKING…' }
        : att.unreadable
          ? { ...tones.warning, label: 'SOME CHECKS FAILED' }
          : { color: color.green, wash: '#0b2a16', ring: 'rgba(79,217,122,.4)', label: 'ALL CLEAR' }
      : { ...(att.shown.some((i) => i.tone === 'danger') ? tones.danger : att.shown.some((i) => i.tone === 'warning') ? tones.warning : grey), label: `${n} ${n === 1 ? 'ITEM NEEDS' : 'ITEMS NEED'} A PERSON` };
  const kill = d.live?.data?.config.kill_switch;
  const killOn = kill ? [kill.rate_limit && 'rate limiting off', kill.block && 'blocking off', kill.auth && 'JWT checks off'].filter(Boolean) : [];
  const canary = d.canary?.data?.canary;
  const edges = d.fleet?.data;

  // Tiles
  const ready = !!rows;
  const span = live ? 5 : Math.max(1, win.length * step);
  const req = sumB(win, (b) => b.requests);
  const refusedOf = (b: Bucket) => b.s[2]! + b.s[3]! + b.s[4]!;
  const refused = sumB(win, refusedOf);
  const u5 = sumB(win, (b) => b.u5);
  const e5 = sumB(win, (b) => b.e5);
  const auth = sumB(win, (b) => b.auth);
  const failed = sumB(win, (b) => b.failed);
  const priorReq = sumB(data.prior, (b) => b.requests);
  const h = hist(win);
  const priorH = hist(data.prior);
  const byRule = new Map<string, number>();
  for (const r of winRows) for (const c of r.rate_limit_rules ?? []) if (c.failed) byRule.set(c.id, (byRule.get(c.id) ?? 0) + c.failed);
  const topRule = [...byRule.entries()].sort((a, b) => b[1] - a[1])[0];
  const p99At = (b: Bucket) => Math.max(0, pctIdx(b.lat, 0.99));
  const ratio = (f: (b: Bucket) => number) => (b: Bucket) => (b.requests ? f(b) / b.requests : 0);
  const tiles = [
    {
      label: live ? 'Requests a minute' : 'Requests in view',
      value: live ? fmt(req / span) : short(req),
      note: live ? (priorReq ? `${(req / span / (priorReq / 60)).toFixed(1)}× the hour before` : 'No requests the hour before') : `${fmt(req / span)} a minute on average`,
      spark: (b: Bucket) => b.requests,
      c: tint(att, tileSignals.requests),
    },
    {
      label: 'Refused by the edge',
      value: share(refused, req),
      note: live ? `${perMin(refused / span)} a minute; hour before ${share(sumB(data.prior, refusedOf), priorReq)}` : `${short(refused)} refused in view`,
      spark: ratio(refusedOf),
      c: tint(att, tileSignals.refused),
    },
    {
      label: 'Response time, p99',
      value: upTo(pctIdx(h, 0.99)),
      note: live ? `p50 ${upTo(pctIdx(h, 0.5))}; hour before p99 ${upTo(pctIdx(priorH, 0.99))}` : `p50 ${upTo(pctIdx(h, 0.5))}`,
      spark: p99At,
      c: tint(att, tileSignals.response),
    },
    {
      label: '5xx answers',
      value: share(u5 + e5, req, 2),
      note: live ? `Upstream ${perMin(u5 / span)}, edge ${perMin(e5 / span)} a minute` : `Upstream ${fmt(u5)}, edge ${fmt(e5)}`,
      spark: ratio((b) => b.u5 + b.e5),
      c: tint(att, tileSignals.fivexx),
    },
    {
      label: 'Failed token checks',
      value: share(auth, req),
      note: live ? `${perMin(auth / span)} a minute on average` : `${fmt(auth)} in view`,
      spark: ratio((b) => b.auth),
      c: tint(att, tileSignals.token),
    },
    {
      label: 'Valkey checks unanswered',
      value: live ? perMin(failed / span) : fmt(failed),
      note: !topRule ? 'None' : `${topRule[1] === failed ? 'All' : topRule[1] * 2 > failed ? 'Most' : 'The largest share'} by rule ${topRule[0]}${live ? ', a minute on average' : ''}`,
      spark: (b: Bucket) => b.failed,
      c: tint(att, tileSignals.valkey, true),
    },
  ];

  // Grow weights 15:11:9, not 1.5:1.1:0.9: a flex-grow below 1 takes only
  // that share of its line's free space, so the right column alone on a
  // line stopped short of the edge.
  const wide: CSSProperties = { flex: '15 1 560px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 14 };
  const w = { wall, expanded, onExpand: setExpanded };
  const events = (d.audit?.data ?? []).filter((e) => e.action in said && !quiet.has(e.action)).slice(0, 3);

  return (
    <main id="main" className={wall ? 'wr wr-wall' : 'wr'}>
      <header style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '12px 24px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <span className="wr-eyebrow">Edge Proxy</span>
          <h1 style={{ margin: 0, color: color.heading, fontSize: 22, fontWeight: 600 }}>War room</h1>
        </div>
        <div role="status" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, width: 330, maxWidth: '100%', boxSizing: 'border-box', padding: '10px 18px', borderRadius: 8, background: status.wash, boxShadow: `0 0 0 1px ${status.ring}` }}>
          <span aria-hidden="true" style={{ width: 14, height: 14, borderRadius: '50%', background: status.color }} />
          <span style={{ color: status.color, fontWeight: 700, fontSize: 20, letterSpacing: '.02em' }}>{status.label}</span>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 22px', alignItems: 'center', flex: '1 1 340px' }}>
          {d.liveVersion !== undefined && (
            <span>
              <span className="wr-eyebrow">Live</span> <span style={{ color: color.heading, fontWeight: 600 }}>v{d.liveVersion}</span>
            </span>
          )}
          {canary && (
            <span>
              <span className="wr-eyebrow">Canary</span>{' '}
              <span style={{ color: color.heading, fontWeight: 600 }}>
                v{canary.version} at {canary.percent}%
              </span>
            </span>
          )}
          {edges && (
            <span>
              <span className="wr-eyebrow">Edges</span>{' '}
              <span style={{ color: color.heading, fontWeight: 600 }}>
                {edges.filter((e) => e.live).length} of {edges.length}
              </span>{' '}
              reporting
            </span>
          )}
          {kill && (
            <span>
              <span className="wr-eyebrow">Kill switches</span> <span style={{ color: color.heading, fontWeight: 600 }}>{killOn.length ? killOn.join(', ') : 'all off'}</span>
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {!wall && (
            <>
              <div role="group" aria-label="Time" style={{ display: 'flex', gap: 4 }}>
                <button type="button" className={live ? 'wr-btn wr-btn-on' : 'wr-btn'} aria-pressed={live} onClick={goLive}>
                  Live
                </button>
                <button type="button" className={live ? 'wr-btn' : 'wr-btn wr-btn-on'} aria-pressed={!live} onClick={goPeriod}>
                  Period
                </button>
              </div>
              {!live && (
                <select
                  className="wr-sel"
                  aria-label="Time range"
                  value={zoom ? 'picked' : key}
                  onChange={(e) => {
                    if (e.target.value === 'picked') return;
                    setKey(e.target.value as RangeKey);
                    setZoomed(null);
                    setFromLive(false);
                  }}
                >
                  {zoom && <option value="picked">Picked: {inView}</option>}
                  {Object.entries(ranges).map(([k, { label }]) => (
                    <option key={k} value={k}>
                      {label[0]!.toUpperCase() + label.slice(1)}
                    </option>
                  ))}
                </select>
              )}
            </>
          )}
          <Clock live={live} />
          {!wall && (
            <>
              <button type="button" className="wr-btn" onClick={enterWall}>
                Wall view
              </button>
              <Link to="/" style={{ fontSize: 14 }}>
                Leave war room
              </Link>
            </>
          )}
          {wall && (
            <button type="button" className="wr-btn" onClick={leaveWall}>
              Exit wall view
            </button>
          )}
        </div>
      </header>

      {!live && (
        <div role="status" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', padding: '8px 14px', borderRadius: 8, background: color.heading, color: '#0a0a0a' }}>
          <span style={{ fontWeight: 700, fontSize: 17, letterSpacing: '.02em' }}>
            NOT LIVE <span style={{ fontWeight: 500, letterSpacing: 0, marginLeft: 8 }}>Showing {inView}</span>
          </span>
          <button type="button" className="wr-btn" onClick={goLive} style={{ background: '#0a0a0a', color: color.heading }}>
            Back to live
          </button>
        </div>
      )}

      <section aria-label={live ? 'Key figures, last 5 minutes' : `Key figures, ${inView}`} className="wr-tiles">
        {tiles.map((t) => (
          <div key={t.label} className="wr-card" style={{ gap: 4, padding: '14px 16px' }}>
            <span className="wr-eyebrow">{t.label}</span>
            <span className="wr-num" style={{ color: t.c ?? color.heading, fontSize: wall ? 52 : 36, fontWeight: 600, lineHeight: 1.05, whiteSpace: 'nowrap' }}>
              {ready ? t.value : '—'}
            </span>
            <svg aria-hidden="true" viewBox="0 0 120 32" preserveAspectRatio="none" style={{ display: 'block', width: '100%', height: 28 }}>
              <polyline points={sparkPoints(vb.slice(-30).map(t.spark))} fill="none" stroke={t.c ?? color.muted} strokeWidth="2" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
            </svg>
            <span style={{ color: t.c ?? color.body, fontSize: 14 }}>{ready ? t.note : ''}</span>
          </div>
        ))}
      </section>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, flex: '1 1 auto', alignItems: 'stretch', minHeight: 0, overflow: wall ? 'hidden' : undefined }}>
        <div style={wide}>
          <OutcomeChart
            {...w}
            view={vb}
            win={win}
            step={step}
            days={days}
            live={live}
            cur={cur}
            before={live && data.prior.length ? sumB(data.prior, total) / data.prior.length : null}
            marks={marks}
            bands={bands}
            inView={inView}
            zoomed={!!zoom}
            resetLabel={fromLive ? 'Back to live' : 'Reset zoom'}
            onReset={() => (fromLive ? goLive() : setZoomed(null))}
            onZoom={onZoom}
          />
          {!wall && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(270px, 1fr))', gap: 14 }}>
              <ResponseTime {...w} view={vb} inView={inView} />
              <Codes {...w} rows={winRows} live={live} inView={inView} />
              <RoutesHit {...w} live={live} from={from} to={to} inView={inView} />
              <RulesRefusing {...w} rows={winRows} live={live} inView={inView} cfg={d.live?.data?.config} />
            </div>
          )}
        </div>

        <div className="wr-fill" style={{ flex: '11 1 440px' }}>
          <WarMap view={view} {...w} />
        </div>

        <div style={{ flex: '9 1 360px', minWidth: 0, minHeight: 0, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="wr-fill" style={{ flex: '1 1 auto', minHeight: 0 }}>
            <NeedsPerson att={att} {...w} />
          </div>
          {!wall && d.audit && (
            <Widget label="Recent changes" name="changes" {...w}>
              <Head title="Recent changes" />
              {events.map((e) => (
                <div key={e.seq} style={{ display: 'flex', gap: 10, fontSize: 15 }}>
                  <span className="wr-num wr-mono" style={{ color: color.muted, flex: '0 0 48px' }}>
                    {hm(Date.parse(e.occurred_at))}
                  </span>
                  <span style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
                    <span style={{ color: color.heading }}>{who(e.actor)}</span> {said[e.action] ?? e.action} <span style={{ color: color.heading }}>{e.action.startsWith('token.') && e.details?.name ? e.details.name : e.target}</span>
                  </span>
                </div>
              ))}
            </Widget>
          )}
        </div>
      </div>

      {expanded && <div className="wr-backdrop" aria-hidden="true" onClick={() => setExpanded(null)} />}

      <footer style={{ fontSize: 14 }}>Country and route counts come from access logs; ≈ marks an estimate from sampled lines.</footer>
    </main>
  );
}
