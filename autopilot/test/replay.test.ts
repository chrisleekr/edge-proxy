import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { createServer, request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';
import { MCPServerStreamableHttp } from '@openai/agents';
import type { Usage } from '../src/admin.ts';
import { replayMain } from '../src/replay.ts';
import type { Adapter, RunInput } from '../src/runner.ts';

const sha = (s: string) => createHash('sha256').update(s).digest('hex');

const prompt = 'You are the autopilot.';
const tools = [
  { name: 'get_case', permission: 'autopilot.agent', evidence: false, description: 'The case this run answers.', input_schema: { type: 'object', properties: {}, additionalProperties: false } },
  {
    name: 'get_rule_stats',
    permission: 'stats.read',
    evidence: true,
    description: 'Counts per minute for one rate-limit rule and its most-limited subjects.',
    input_schema: { type: 'object', properties: { rule: { type: 'string' }, minutes: { type: 'integer' } }, required: ['rule'], additionalProperties: false },
  },
  {
    name: 'get_route',
    permission: 'stats.read',
    evidence: true,
    description: 'One observed route with its hourly series.',
    input_schema: { type: 'object', properties: { id: { type: 'integer' } }, required: ['id'], additionalProperties: false },
  },
  {
    name: 'prom_query',
    permission: 'autopilot.agent',
    evidence: true,
    description: 'Runs one PromQL instant query.',
    input_schema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'], additionalProperties: false },
  },
  {
    name: 'propose',
    permission: 'autopilot.agent',
    evidence: false,
    description: 'Proposes add_sensor, enforce or retire.',
    input_schema: { type: 'object', properties: { action: { type: 'string' }, name: { type: 'string' }, cites: { type: 'string' }, rationale: { type: 'string' } }, required: ['action', 'rationale'], additionalProperties: false },
  },
];
const contract = { prompt, prompt_sha256: sha(prompt), tools, tools_sha256: sha(JSON.stringify(tools)), output_schema: { type: 'object' } };

const brief = { kind: 'anomaly', signal: 'rule_would_block', rule: 'ap-login-401-17', summary: { untrusted: 'login-401 would block 3 addresses' } };
const caseAnswer = { case_id: 7, kind: 'anomaly', brief };
const stats = {
  rule: 'ap-login-401-17',
  minutes: 60,
  step_minutes: 1,
  series: [{ minute: '2026-10-29T01:00:00Z', evaluated: 900, would_limit: 41 }],
  top_subjects: { untrusted: [{ subject: '203.0.113.7', would_limit: 40 }] },
};
const enforce = { action: 'enforce', name: 'login-401-block', cites: 'ap-login-401-17', rationale: 'Forty failed logins a minute from one address' };
const accepted = { proposal_id: 31, accepted: true, rule_id: 'ap-login-401-block-31', reasons: [], checks: [] };
const noRoute = 'no observed route 999';
const at = '2026-10-29T01:02:00Z';
const promArgs = { query: 'sum(rate(http_requests_total{route="/login"}[5m]))' };
const promAnswer = { result_type: 'vector', result: [{ metric: {}, value: [1793235720, '41'] }] };

// caseRead is GET /api/autopilot/cases/7 as admin answers it: case 7, run
// 11, and the four MCP calls admin recorded for it, one refused.
function caseRead(runToolsSha: string) {
  return {
    case: { id: 7, kind: 'anomaly', rule: 'ap-login-401-17', route_id: null, anomaly_id: 5, question: '', brief, state: 'done', attempts: 1, lease_until: null, run_id: 11, verdict: 'attack', summary: 'One address guessing passwords', opened_by: 'system:autopilot', created_at: at, closed_at: at, ablation_of: null },
    runs: [
      {
        id: 11, attempt: 1, runner: 'runner-a', provider: 'claude', model: 'claude-opus-5-5', prompt_sha256: contract.prompt_sha256, tools_sha256: runToolsSha, started_at: at, finished_at: at,
        status: 'ok', error_category: '', turns: 5, tool_calls: 4, input_tokens: 12000, output_tokens: 900, cache_read_tokens: 30000, cache_write_tokens: 2000,
        configured_cost_usd_micros: 85000, provider_cost_usd_micros: 80000, telemetry_complete: true,
      },
    ],
    proposals: [],
    tool_calls: [
      { run_id: 11, seq: 1, at, payload: { tool: 'get_case', arguments: {}, allowed: true, duration_ms: 4, result: caseAnswer } },
      { run_id: 11, seq: 2, at, payload: { tool: 'get_rule_stats', arguments: { rule: 'ap-login-401-17', minutes: 60 }, allowed: true, duration_ms: 9, result: stats } },
      { run_id: 11, seq: 3, at, payload: { tool: 'get_route', arguments: { id: 999 }, allowed: false, duration_ms: 2, refusal: noRoute } },
      { run_id: 11, seq: 4, at, payload: { tool: 'propose', arguments: enforce, allowed: true, duration_ms: 30, result: accepted } },
    ],
    transitions: [],
    rules: [],
  };
}

const token = 'eap_reader_0123456789abcdef';

// startAdmin is admin's read API for case 7, recording every request. Any
// other request, such as one to /v1/mcp, gets 500 and fails the test.
async function startAdmin(t: TestContext, read: object = caseRead(contract.tools_sha256)): Promise<{ url: string; tokenFile: string; requests: string[] }> {
  const requests: string[] = [];
  const srv = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    const answer = (status: number, body: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    if (req.headers.authorization !== `Bearer ${token}`) {
      return answer(401, { detail: 'unauthenticated' });
    }
    if (req.method === 'GET' && req.url === '/api/autopilot/cases/7') {
      return answer(200, read);
    }
    if (req.method === 'GET' && req.url === '/api/autopilot/contract') {
      return answer(200, contract);
    }
    answer(500, { detail: 'a replay asked admin for more than the case and the contract' });
  });
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  t.after(() => srv.close());
  const dir = await mkdtemp(join(tmpdir(), 'replay-test-'));
  const tokenFile = join(dir, 'token');
  await writeFile(tokenFile, token + '\n');
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, tokenFile, requests };
}

type Answer = Awaited<ReturnType<MCPServerStreamableHttp['callToolResult']>>;

interface Seen {
  input?: RunInput;
  tools: Awaited<ReturnType<MCPServerStreamableHttp['listTools']>>;
  answers: Answer[];
}

const usage: Usage = { input_tokens: 8000, output_tokens: 700, cache_read_tokens: 0, cache_write_tokens: 0 };

// model stands in for a model: it lists the tools, makes each call over MCP
// to the server the replay gives it, and answers with verdict.
function model(calls: { tool: string; arguments: Record<string, unknown> }[], verdict: string, seen: Seen): Adapter {
  return async (input) => {
    seen.input = input;
    // The MCP client the OpenAI adapter uses.
    const server = new MCPServerStreamableHttp({ name: 'replay', url: input.mcpURL, requestInit: { headers: input.mcpHeaders } });
    await server.connect();
    try {
      seen.tools = await server.listTools();
      for (const c of calls) {
        seen.answers.push(await server.callToolResult(c.tool, c.arguments));
      }
    } finally {
      await server.close();
    }
    return { output: { verdict, summary: 'replayed', proposals: [] }, error: '', turns: calls.length + 1, toolCalls: calls.length, usage, costUSD: 0.02 };
  };
}

const newSeen = (): Seen => ({ tools: [], answers: [] });

function texts(a: Answer | undefined): string[] {
  return (a?.content ?? []).map((c) => (c.type === 'text' ? String(c['text']) : `<${c.type}>`));
}

test('a recorded call gets its recorded answer and evidence id', async (t) => {
  const admin = await startAdmin(t);
  const seen = newSeen();
  // Keys in another order than recorded: a call is the same call whatever its key order.
  const calls = [
    { tool: 'get_case', arguments: {} },
    { tool: 'get_rule_stats', arguments: { minutes: 60, rule: 'ap-login-401-17' } },
    { tool: 'propose', arguments: { rationale: enforce.rationale, cites: enforce.cites, name: enforce.name, action: enforce.action } },
  ];
  await replayMain({ claude: model(calls, 'attack', seen) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]);
  const [getCase, ruleStats, propose] = seen.answers;

  assert.equal(getCase?.isError ?? false, false);
  assert.deepEqual(getCase?.structuredContent, caseAnswer);
  assert.deepEqual(texts(getCase).map((s) => JSON.parse(s) as unknown), [caseAnswer]);

  // A stats read is evidence, by its seq, in both forms as admin sends it.
  assert.equal(ruleStats?.isError ?? false, false);
  assert.deepEqual(ruleStats?.structuredContent, { ...stats, evidence_id: 2 });
  assert.deepEqual(texts(ruleStats).map((s) => JSON.parse(s) as unknown), [stats, { evidence_id: 2 }]);

  // The recorded acceptance, with no proposal made.
  assert.deepEqual(propose?.structuredContent, accepted);
  assert.equal(texts(propose).length, 1);
});

test('an unrecorded call is an error the model sees', async (t) => {
  const admin = await startAdmin(t);
  const seen = newSeen();
  const sensor = { action: 'add_sensor', name: 'login-watch', rationale: 'Watch the login route' };
  await replayMain({ claude: model([{ tool: 'propose', arguments: sensor }], 'attack', seen) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]);
  assert.equal(seen.answers[0]?.isError, true);
  assert.deepEqual(texts(seen.answers[0]), ['not recorded in run 11; a replay answers only the calls the run made, and never proposes or records']);
  // The proposal never reached admin: the replay read the case and the contract, and nothing else.
  assert.deepEqual(admin.requests, ['GET /api/autopilot/cases/7', 'GET /api/autopilot/contract']);
});

test('a recorded refusal is refused again', async (t) => {
  const admin = await startAdmin(t);
  const seen = newSeen();
  await replayMain({ claude: model([{ tool: 'get_route', arguments: { id: 999 } }], 'attack', seen) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]);
  assert.equal(seen.answers[0]?.isError, true);
  assert.deepEqual(texts(seen.answers[0]), [noRoute]);
});

test('the report names a changed verdict and calls not recorded', async (t) => {
  const admin = await startAdmin(t);
  const seen = newSeen();
  const calls = [
    { tool: 'get_case', arguments: {} },
    { tool: 'get_rule_stats', arguments: { rule: 'ap-login-401-17', minutes: 30 } },
  ];
  const report = await replayMain({ claude: model(calls, 'benign', seen) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]);
  assert.ok(report);
  assert.ok(report.replay.seconds >= 0);
  assert.deepEqual(report, {
    case: 7,
    run: 11,
    recorded: {
      provider: 'claude',
      model: 'claude-opus-5-5',
      verdict: 'attack',
      tokens: { input_tokens: 12000, output_tokens: 900, cache_read_tokens: 30000, cache_write_tokens: 2000 },
      configured_usd_micros: 85000,
      provider_usd_micros: 80000,
    },
    replay: { provider: 'claude', model: 'claude-opus-5-5', verdict: 'benign', turns: 3, tool_calls: 2, tokens: usage, provider_cost_usd: 0.02, seconds: report.replay.seconds },
    differences: {
      verdict: true,
      prompt_changed: false,
      tools_changed: false,
      unrecorded_calls: [{ tool: 'get_rule_stats', arguments: { rule: 'ap-login-401-17', minutes: 30 } }],
      recorded_calls_not_made: ['get_rule_stats', 'get_route', 'propose'],
    },
  });
});

test('a saved bundle replays from a file', async (t) => {
  const admin = await startAdmin(t);
  const dir = await mkdtemp(join(tmpdir(), 'replay-bundle-'));
  const bundle = join(dir, 'case-7.json');
  // An earlier bundle anyone could read is replaced by one only its owner reads.
  // chmod, since a create mode is narrowed by the umask.
  await writeFile(bundle, '{}');
  await chmod(bundle, 0o644);
  const unused = newSeen();
  assert.equal(await replayMain({ claude: model([], 'attack', unused) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile, '--save', bundle]), null);
  assert.equal(unused.input, undefined, 'saving runs no model');
  const saved = await readFile(bundle, 'utf8');
  assert.equal((await stat(bundle)).mode & 0o777, 0o600, 'the bundle holds client IPs and stats, so only its owner reads it');
  assert.ok(!saved.includes(token), 'the bundle holds the token');
  assert.ok(!saved.includes(prompt), 'the bundle holds the prompt text');

  const revised = join(dir, 'prompt.md');
  await writeFile(revised, 'You are the autopilot, revised.');
  const before = admin.requests.length;
  const seen = newSeen();
  const calls = [
    { tool: 'get_case', arguments: {} },
    { tool: 'get_rule_stats', arguments: { rule: 'ap-login-401-17', minutes: 60 } },
    { tool: 'get_route', arguments: { id: 999 } },
    { tool: 'propose', arguments: enforce },
  ];
  const report = await replayMain({ claude: model(calls, 'attack', seen) }, ['7', '--file', bundle, '--prompt', revised]);
  assert.equal(admin.requests.length, before, 'a file replay asks admin nothing');
  assert.equal(seen.input?.claim.prompt, 'You are the autopilot, revised.');
  assert.deepEqual(seen.answers[1]?.structuredContent, { ...stats, evidence_id: 2 });
  assert.deepEqual(report?.differences, { verdict: false, prompt_changed: true, tools_changed: false, unrecorded_calls: [], recorded_calls_not_made: [] });
});

test("the model gets the run's case and model, admin's prompt and tools, from a server on 127.0.0.1", async (t) => {
  const admin = await startAdmin(t);
  const seen = newSeen();
  await replayMain({ claude: model([], 'attack', seen) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]);
  const claim = seen.input?.claim;
  assert.deepEqual(
    { case_id: claim?.case_id, kind: claim?.kind, brief: claim?.brief, provider: claim?.provider, model: claim?.model, prompt: claim?.prompt, output_schema: claim?.output_schema },
    { case_id: 7, kind: 'anomaly', brief, provider: 'claude', model: 'claude-opus-5-5', prompt, output_schema: contract.output_schema },
  );
  assert.equal(new URL(seen.input?.mcpURL ?? '').hostname, '127.0.0.1');
  assert.deepEqual(
    seen.tools.map((x) => ({ name: x.name, description: x.description, input_schema: x.inputSchema })),
    tools.map((x) => ({ name: x.name, description: x.description, input_schema: x.input_schema })),
  );
});

test("the report says the tools changed when admin's differ from the run's", async (t) => {
  const admin = await startAdmin(t, caseRead(sha('the tools of an older admin')));
  const report = await replayMain({ claude: model([], 'attack', newSeen()) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]);
  assert.equal(report?.differences.tools_changed, true);
  assert.equal(report?.differences.prompt_changed, false);
});

test('a connector read is evidence by its seq, as a stats read is', async (t) => {
  const read = caseRead(contract.tools_sha256);
  const admin = await startAdmin(t, { ...read, tool_calls: [...read.tool_calls, { run_id: 11, seq: 5, at, payload: { tool: 'prom_query', arguments: promArgs, allowed: true, duration_ms: 12, result: promAnswer } }] });
  const seen = newSeen();
  await replayMain({ claude: model([{ tool: 'prom_query', arguments: promArgs }], 'attack', seen) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]);
  assert.deepEqual(seen.answers[0]?.structuredContent, { ...promAnswer, evidence_id: 5 });
  assert.deepEqual(texts(seen.answers[0]).map((s) => JSON.parse(s) as unknown), [promAnswer, { evidence_id: 5 }]);
});

test('a token admin hides a connector answer from stops the replay, naming what it needs', async (t) => {
  const read = caseRead(contract.tools_sha256);
  // Admin drops a hidden connector call's arguments and answer, and says why.
  const hidden = { tool: 'prom_query', allowed: true, duration_ms: 12, hidden: true, hidden_reason: 'needs stats.read, config.read and autopilot.manage' };
  const admin = await startAdmin(t, { ...read, tool_calls: [...read.tool_calls, { run_id: 11, seq: 5, at, payload: hidden }] });
  const seen = newSeen();
  await assert.rejects(replayMain({ claude: model([], 'attack', seen) }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]), {
    message: 'admin hid the recorded answer of prom_query: the token needs stats.read, config.read and autopilot.manage',
  });
  assert.equal(seen.input, undefined, 'no model ran');
});

// post sends one MCP initialize to url with headers, as any local process can.
function post(url: string, headers: Record<string, string>): Promise<number> {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'other', version: '1' } } });
  return new Promise((resolve, reject) => {
    const req = request(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers } }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', reject);
    req.end(body);
  });
}

test("the replay's MCP server answers only the model it started, at its own address", async (t) => {
  const admin = await startAdmin(t);
  const got: Record<string, number> = {};
  const probe: Adapter = async (input) => {
    const port = new URL(input.mcpURL).port;
    got['no token'] = await post(input.mcpURL, {});
    got['wrong token'] = await post(input.mcpURL, { authorization: 'Bearer not-the-replay-token' });
    // A DNS-rebound page reaches 127.0.0.1 under its own host name.
    got['rebound host'] = await post(input.mcpURL, { ...input.mcpHeaders, host: `attacker.example:${port}` });
    got['the model'] = await post(input.mcpURL, input.mcpHeaders);
    return { output: { verdict: 'attack', summary: 'probed', proposals: [] }, error: '', turns: 1, toolCalls: 0, usage, costUSD: 0 };
  };
  await replayMain({ claude: probe }, ['7', '--admin', admin.url, '--token-file', admin.tokenFile]);
  assert.deepEqual(got, { 'no token': 401, 'wrong token': 401, 'rebound host': 401, 'the model': 200 });
});
