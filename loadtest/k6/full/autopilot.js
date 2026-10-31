// Five attacks against the autopilot, with the scripted agent (tools agent)
// answering its cases from loadtest/tools/autopilot-plan.json. For each
// attack a sensor watches its route; the attack makes the sensor would-block,
// which opens a case; the agent enforces a block rule citing the sensor;
// the rule blocks the attack and not the background, and expires once the
// attack stops. load-full.sh starts the agent before this and stops it after.
import http from 'k6/http';
import { sleep } from 'k6';
import exec from 'k6/execution';
import { Counter, Rate, Trend } from 'k6/metrics';
import { call, session, publish, converged } from '../admin.js';
import { edges, path, pick, thresholdReport, viewer, waitReady } from '../lib.js';

const MAX_BLOCK_SHARE = Number(__ENV.MAX_BLOCK_SHARE ?? 0.05);
const BACKGROUND = Number(__ENV.BACKGROUND_RPS ?? 800);
const ATTACK = '8m';
const attackMs = 8 * 60_000;
// An enforcing rule renews while it limited within 10m; then its 5m ttl
// runs out. 5m, not shorter: admin refuses a ttl under 4 x (30s tick +
// min_publish_interval), which is 4m with the 30s interval set below.
const ttl = '5m';
const expiryMs = 10 * 60_000 + 5 * 60_000 + 120_000;

// Each attack's plan sensor, and the base of its own IP range.
const attacks = {
  idor: { sensor: 'idor-paths', ips: 1_000_000 },
  scraping: { sensor: 'catalog-per-user', ips: 2_000_000 },
  stuffing: { sensor: 'login-401', ips: 3_000_000 },
  scanner: { sensor: 'notfound-per-ip', ips: 4_000_000 },
  asn: { sensor: 'search-per-ip', ips: 5_000_000 },
};

const timeToCase = new Trend('time_to_case_seconds');
const timeToEnforce = new Trend('time_to_enforce_seconds');
const collateral = new Rate('collateral_429');
const blocked = new Rate('attack_blocked');
const expired = new Counter('expired');
const asnKeyRefused = new Counter('asn_key_refused');

const attackScenario = (exec, rate) => ({ executor: 'constant-arrival-rate', exec, rate, timeUnit: '1s', duration: ATTACK, preAllocatedVUs: 10, maxVUs: 100, tags: { attack: exec } });
const thresholds = { collateral_429: [`rate<${MAX_BLOCK_SHARE}`], asn_key_refused: ['count==1'] };
for (const a of Object.keys(attacks)) {
  thresholds[`time_to_case_seconds{attack:${a}}`] = ['max<180'];
  thresholds[`time_to_enforce_seconds{attack:${a}}`] = ['max<180'];
  thresholds[`attack_blocked{attack:${a}}`] = ['rate>0.5'];
  thresholds[`expired{attack:${a}}`] = ['count==1'];
}

export const options = {
  setupTimeout: '600s',
  summaryTrendStats: ['p(99)', 'max'],
  insecureSkipTLSVerify: true,
  scenarios: {
    background: { executor: 'constant-arrival-rate', exec: 'background', rate: BACKGROUND, timeUnit: '1s', duration: '10m', preAllocatedVUs: 100, maxVUs: 1000 },
    idor: attackScenario('idor', 20),
    scraping: attackScenario('scraping', 20),
    stuffing: attackScenario('stuffing', 20),
    scanner: attackScenario('scanner', 6),
    asn: attackScenario('asn', 11),
    watch: { executor: 'per-vu-iterations', exec: 'watch', vus: 1, iterations: 1, maxDuration: '27m' },
  },
  thresholds,
};

const rules = (cookie) => call(cookie, 'GET', '/api/autopilot').json('rules') ?? [];
const sensorID = (list, name) => list.find((r) => new RegExp(`^ap-${name}-\\d+$`).test(r.id) && r.state === 'observing')?.id;

export function setup() {
  waitReady();
  const cookie = session();
  // No base rate-limit rules, so only the autopilot's limit the attacks. The
  // catalog verifies a token when one is sent, so the scraper's sub is a key.
  const catalog = { id: 'catalog-auth', expression: path('starts_with', '/api/catalog/'), settings: { auth: { mode: 'optional' } } };
  converged(
    cookie,
    publish(cookie, (c) => ({ ...c, rate_limit_rules: [], config_rules: [...c.config_rules.filter((r) => r.id !== catalog.id), catalog] }), { message: 'autopilot attacks: no base rate limits', tests: [] }),
  );
  // A sensor's anomaly fires on the first check that sees it: checks run
  // every minute over whole minutes 30s old, and the autopilot ticks every
  // 30s, so a case opens within about 3 minutes of an attack starting.
  call(cookie, 'PUT', '/api/settings/notifications', { ...call(cookie, 'GET', '/api/settings/notifications').json(), fire_after: 1 });
  call(cookie, 'PUT', '/api/settings/autopilot', {
    ...call(cookie, 'GET', '/api/settings/autopilot').json(),
    mode: 'auto',
    observe_for: '1m',
    default_ttl: ttl,
    max_block_share: MAX_BLOCK_SHARE,
    min_publish_interval: '30s',
    cases_per_hour: 60,
    max_sensors: 10,
    max_enforcing: 10,
    reason: 'load test: five attacks',
  });
  // The agent's first sweep proposes the plan's sensors; they observe within a tick or two.
  const sensors = {};
  for (let i = 0; Object.keys(sensors).length < 5; i++) {
    if (i > 100) throw new Error(`plan sensors not observing after 500s: ${JSON.stringify(sensors)}`);
    const list = rules(cookie);
    for (const [a, { sensor }] of Object.entries(attacks)) {
      const id = sensorID(list, sensor);
      if (id) sensors[a] = id;
    }
    sleep(5);
  }
  const token = http.get('https://idp:8443/token?sub=scraper').body;
  return { cookie, sensors, token, started: Date.now() };
}

let n = 0;
// send makes one request: an attack's counts toward attack_blocked once its
// block rule enforces, anyone else's toward collateral_429.
const send = (d, method, url, headers, attack) => {
  const r = http.request(method, `${pick(edges)}${url}`, method === 'POST' ? '{}' : null, { headers, responseCallback: http.expectedStatuses(200, 401, 404, 429) });
  if (!attack) {
    collateral.add(r.status === 429);
  } else if (enforcingFor(d, attack)) {
    blocked.add(r.status === 429, { attack });
  }
};

// enforcingFor reports whether the attack's block rule has been enforcing
// for 15s, long enough to reach every edge. Each VU asks admin every 10s.
const seen = {};
function enforcingFor(d, attack) {
  const s = seen[attack] || (seen[attack] = { checked: 0, since: null });
  if (s.since === null && Date.now() - s.checked > 10_000) {
    s.checked = Date.now();
    const r = rules(d.cookie).find((x) => x.id.startsWith(`ap-${attacks[attack].sensor}-block-`) && x.enforcing_since);
    if (r) s.since = Date.parse(r.enforcing_since);
  }
  return s.since !== null && Date.now() - s.since > 15_000;
}

export function background(d) {
  send(d, 'GET', '/pages/home', viewer(n++ % 100_000));
  // Legitimate logins and searches, on the attacked routes, from ordinary clients.
  if (n % 400 === 0) send(d, 'POST', '/login?status=200', viewer(200_000 + (n % 100)));
  if (n % 160 === 0) send(d, 'POST', '/api/search', viewer(300_000 + (n % 300), 64500));
}

const ip = (a, i) => viewer(attacks[a].ips + i);

// 4 IPs each walking order ids in sequence.
// iterationInTest is unique across VUs, so each order id is walked once.
export function idor(d) {
  const i = exec.scenario.iterationInTest;
  send(d, 'GET', `/api/orders/${i}`, ip('idor', i % 4), 'idor');
}

// One user over 20 rotating IPs, each request a new catalog page. 20 rps,
// so the edges' 1-in-16 sample keeps the user in their reported top 20.
export function scraping(d) {
  const i = exec.scenario.iterationInTest;
  send(d, 'GET', `/api/catalog/${i}`, { ...ip('scraping', i % 20), Authorization: `Bearer ${d.token}` }, 'scraping');
}

// 10 IPs guessing passwords: every login fails. Each subject must be at
// least 5% of the rule's blocks for the guard to exclude it; 40 IPs at 2.5%
// each would count as collateral and roll the rule back, as designed.
export function stuffing(d) {
  send(d, 'POST', '/login?status=401', ip('stuffing', n++ % 10), 'stuffing');
}

const probes = ['/.env', '/wp-login.php', '/wp-admin/', '/wp-config.php.bak', '/wp-content/debug.log'];
const chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

// 3 IPs probing for files that are not there, as a browser would.
export function scanner(d) {
  const i = n++;
  send(d, 'GET', `${probes[i % probes.length]}?status=404`, { ...ip('scanner', i % 3), 'User-Agent': chrome }, 'scanner');
}

// 2 IPs searching hard from AS64500, which the 300 legitimate searchers share.
export function asn(d) {
  send(d, 'POST', '/api/search', viewer(attacks.asn.ips + (n++ % 2), 64500), 'asn');
}

// watch follows each attack's case and block rule until the rule expires.
export function watch(d) {
  const done = {};
  const caseOf = {};
  const end = d.started + attackMs + expiryMs;
  while (Object.keys(done).length < 5 && Date.now() < end) {
    sleep(5);
    const cases = call(d.cookie, 'GET', '/api/autopilot/cases').json();
    for (const [a, sensor] of Object.entries(d.sensors)) {
      if (done[a]) continue;
      if (!caseOf[a]) {
        const c = cases.find((x) => x.kind === 'anomaly' && x.rule === sensor);
        if (!c) continue;
        caseOf[a] = { id: c.id, opened: Date.parse(c.created_at) };
        timeToCase.add((caseOf[a].opened - d.started) / 1000, { attack: a });
        console.log(`${a}: case ${c.id} opened ${Math.round((caseOf[a].opened - d.started) / 1000)}s into the attack`);
      }
      const c = call(d.cookie, 'GET', `/api/autopilot/cases/${caseOf[a].id}`).json();
      if (a === 'asn' && !caseOf[a].refused && c.proposals.some((p) => !p.accepted && (p.checks ?? []).some((k) => k.name === 'key_needs_ip_or_jwt' && !k.ok))) {
        caseOf[a].refused = true;
        asnKeyRefused.add(1);
      }
      const rule = c.rules.find((r) => r.id.startsWith(`ap-${attacks[a].sensor}-block-`));
      if (rule?.enforcing_since && !caseOf[a].enforced) {
        caseOf[a].enforced = true;
        timeToEnforce.add((Date.parse(rule.enforcing_since) - caseOf[a].opened) / 1000, { attack: a });
        console.log(`${a}: ${rule.id} enforcing ${Math.round((Date.parse(rule.enforcing_since) - caseOf[a].opened) / 1000)}s after its case opened`);
      }
      if (rule?.outcome === 'expired' && Date.now() > d.started + attackMs) {
        done[a] = true;
        expired.add(1, { attack: a });
        console.log(`${a}: ${rule.id} expired ${Math.round((Date.now() - d.started - attackMs) / 1000)}s after the attack stopped`);
      } else if (rule?.outcome) {
        done[a] = true;
        const why = c.transitions.filter((t) => t.rule_id === rule.id).map((t) => `${t.to_state}: ${t.reason} ${JSON.stringify(t.numbers)}`);
        console.log(`${a}: ${rule.id} ended ${rule.outcome} before its attack stopped: ${why.join('; ')}`);
      }
    }
  }
  // An attack that never reached a step fails its threshold rather than having no data.
  for (const a of Object.keys(attacks)) {
    if (!caseOf[a]) timeToCase.add(1e6, { attack: a });
    if (!caseOf[a]?.enforced) {
      timeToEnforce.add(1e6, { attack: a });
      blocked.add(false, { attack: a });
    }
    if (!done[a]) expired.add(0, { attack: a });
  }
}

export function handleSummary(data) {
  return { stdout: '\nAutopilot: five attacks, enforced by the scripted agent\n' + thresholdReport(data) };
}
