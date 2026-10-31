// Replays one recorded autopilot run against a model: the model gets the
// run's case and tools from a local MCP server that answers only the calls
// the run made, as admin answered them. Nothing reaches admin's MCP, so a
// replay never opens a run, proposes or records.
//
//   npm run replay -- <case> [--run N] --admin URL --token-file F [--provider P --model M] [--prompt FILE] [--save FILE] [--max-turns N]
//   npm run replay -- <case> --file FILE [--provider P --model M] [--prompt FILE] [--max-turns N]
//
// The token needs autopilot.read, stats.read and config.read, and
// autopilot.manage for a run with connector calls: without them admin hides
// the recorded answers.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdtemp, open, readFile, rm } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import type { Usage } from './admin.ts';
import type { Provider } from './config.ts';
import { verdictSchema, type Adapter } from './runner.ts';

const toolSchema = z.object({ name: z.string(), permission: z.string(), evidence: z.boolean(), description: z.string(), input_schema: z.record(z.string(), z.unknown()) });

// contractSchema is GET /api/autopilot/contract, which is what a claim
// gives the runner, minus the case. A bundle keeps it without the prompt.
const contractSchema = z.object({
  prompt: z.string(),
  prompt_sha256: z.string(),
  tools: z.array(toolSchema),
  tools_sha256: z.string(),
  output_schema: z.record(z.string(), z.unknown()),
});

const runSchema = z.looseObject({
  id: z.number(),
  provider: z.enum(['claude', 'openai']),
  model: z.string(),
  prompt_sha256: z.string(),
  tools_sha256: z.string(),
  input_tokens: z.number().nullable(),
  output_tokens: z.number().nullable(),
  cache_read_tokens: z.number().nullable(),
  cache_write_tokens: z.number().nullable(),
  configured_cost_usd_micros: z.number().nullable(),
  provider_cost_usd_micros: z.number().nullable(),
});

const callSchema = z.object({
  seq: z.number(),
  tool: z.string(),
  arguments: z.unknown(),
  result: z.unknown().optional(),
  refusal: z.string().optional(),
});

const bundleSchema = z.object({
  case: z.looseObject({ id: z.number(), kind: z.string(), brief: z.unknown(), run_id: z.number().nullable(), verdict: z.string().nullable() }),
  run: runSchema,
  calls: z.array(callSchema),
  contract: contractSchema.omit({ prompt: true }),
  expect: z.object({ verdict: z.enum(['attack', 'benign', 'unsure']) }).optional(),
});

export type Bundle = z.infer<typeof bundleSchema>;
type Call = z.infer<typeof callSchema>;

export interface Report {
  case: number;
  run: number;
  recorded: { provider: string; model: string; verdict: string; tokens: Usage; configured_usd_micros: number | null; provider_usd_micros: number | null };
  replay: { provider: string; model: string; verdict: string; turns: number; tool_calls: number; tokens: Usage; provider_cost_usd: number | null; seconds: number };
  differences: { verdict: boolean; prompt_changed: boolean; tools_changed: boolean; unrecorded_calls: { tool: string; arguments: unknown }[]; recorded_calls_not_made: string[] };
}

export async function loadBundle(file: string): Promise<Bundle> {
  return bundleSchema.parse(JSON.parse(await readFile(file, 'utf8')));
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

// canonical is JSON with object keys sorted, so a call matches its record
// whatever order the model wrote the arguments in.
function canonical(v: unknown): string {
  if (Array.isArray(v)) {
    return `[${v.map(canonical).join(',')}]`;
  }
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v);
}

const callKey = (tool: string, args: unknown) => `${tool} ${canonical(args ?? {})}`;

async function adminGet(url: string, token: string, path: string): Promise<unknown> {
  const resp = await fetch(url + path, { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(30_000) });
  if (!resp.ok) {
    throw new Error(`admin answered ${path} with ${resp.status}: ${await resp.text()}`);
  }
  return resp.json();
}

const caseReadSchema = z.object({
  case: bundleSchema.shape.case,
  runs: z.array(runSchema),
  tool_calls: z.array(z.object({ run_id: z.number(), seq: z.number(), payload: z.record(z.string(), z.unknown()) })),
});

// fromAdmin builds the bundle of one run of a case from admin's case read and contract.
async function fromAdmin(url: string, token: string, caseID: number, runID: number | undefined): Promise<{ bundle: Bundle; prompt: string }> {
  const read = caseReadSchema.parse(await adminGet(url, token, `/api/autopilot/cases/${caseID}`));
  const contract = contractSchema.parse(await adminGet(url, token, '/api/autopilot/contract'));
  const id = runID ?? read.case.run_id;
  const run = read.runs.find((r) => r.id === id);
  if (!run) {
    throw new Error(`case ${caseID} has no run ${id ?? ''}`);
  }
  const calls: Call[] = [];
  for (const e of read.tool_calls.filter((e) => e.run_id === run.id)) {
    const p = e.payload;
    if (p['hidden'] === true) {
      throw new Error(`admin hid the recorded answer of ${String(p['tool'])}: the token ${String(p['hidden_reason'])}`);
    }
    // ponytail: a call whose record admin cut over its size limit has no tool or arguments left, so it can't be replayed and is skipped.
    if (typeof p['tool'] !== 'string') {
      continue;
    }
    const call = { seq: e.seq, tool: p['tool'], arguments: p['arguments'] };
    calls.push(p['allowed'] === true ? { ...call, result: p['result'] } : { ...call, refusal: typeof p['refusal'] === 'string' ? p['refusal'] : '' });
  }
  const { prompt, ...rest } = contract;
  return { bundle: { case: read.case, run, calls, contract: rest }, prompt };
}

const unrecorded = (run: number) => `not recorded in run ${run}; a replay answers only the calls the run made, and never proposes or records`;

// Recorded answers the calls of one run and notes what it was asked.
class Recorded {
  readonly #byKey = new Map<string, Call[]>();
  readonly #made = new Set<Call>();
  readonly #evidence: Set<string>;
  readonly #run: number;
  readonly unrecorded: { tool: string; arguments: unknown }[] = [];

  constructor(b: Bundle) {
    this.#run = b.run.id;
    this.#evidence = new Set(b.contract.tools.filter((t) => t.evidence).map((t) => t.name));
    for (const c of b.calls) {
      const k = callKey(c.tool, c.arguments);
      this.#byKey.set(k, [...(this.#byKey.get(k) ?? []), c]);
    }
  }

  // answer gives a call its recorded answer as admin sent it. A call the
  // run made twice gets its answers in order, then the last again.
  answer(tool: string, args: unknown): CallToolResult {
    const list = this.#byKey.get(callKey(tool, args)) ?? [];
    const c = list.find((x) => !this.#made.has(x)) ?? list.at(-1);
    if (!c) {
      this.unrecorded.push({ tool, arguments: args ?? {} });
      return { isError: true, content: [{ type: 'text', text: unrecorded(this.#run) }] };
    }
    this.#made.add(c);
    if (c.refusal !== undefined) {
      return { isError: true, content: [{ type: 'text', text: c.refusal }] };
    }
    const out: CallToolResult = { content: [{ type: 'text', text: JSON.stringify(c.result) }] };
    const isObject = c.result !== null && typeof c.result === 'object' && !Array.isArray(c.result);
    if (isObject) {
      out.structuredContent = c.result as Record<string, unknown>;
    }
    // An evidence read carries its seq, in both forms, as admin sends it.
    if (this.#evidence.has(tool)) {
      if (isObject) {
        out.structuredContent = { ...(c.result as Record<string, unknown>), evidence_id: c.seq };
      }
      out.content.push({ type: 'text', text: JSON.stringify({ evidence_id: c.seq }) });
    }
    return out;
  }

  notMade(calls: Call[]): string[] {
    return calls.filter((c) => !this.#made.has(c)).map((c) => c.tool);
  }
}

// serve answers MCP on 127.0.0.1 from rec, statelessly: a new server and
// transport per request, as the SDK requires of a stateless transport. The
// answers hold stats and client IPs, so it answers only a request with its
// token, which keeps out other local users, and its own Host, which keeps
// out a DNS-rebound page.
async function serve(b: Bundle, rec: Recorded): Promise<{ url: string; headers: Record<string, string>; close: () => Promise<void> }> {
  const tools = b.contract.tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.input_schema as { type: 'object' } }));
  const want = Buffer.from(`Bearer ${randomBytes(32).toString('hex')}`);
  let host = '';
  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const got = Buffer.from(req.headers.authorization ?? '');
    if (req.headers.host !== host || got.length !== want.length || !timingSafeEqual(got, want)) {
      res.writeHead(401).end();
      return;
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST' }).end();
      return;
    }
    const server = new Server({ name: 'edge-proxy-replay', version: '1' }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, () => ({ tools }));
    server.setRequestHandler(CallToolRequestSchema, (r) => rec.answer(r.params.name, r.params.arguments));
    // No sessionIdGenerator: stateless.
    const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    // The SDK's own types differ only in sessionId's optionality under exactOptionalPropertyTypes.
    await server.connect(transport as Transport);
    await transport.handleRequest(req, res);
  };
  const srv = createServer((req, res) => {
    handle(req, res).catch((e: unknown) => {
      if (!res.headersSent) {
        res.writeHead(500).end(String(e));
      }
    });
  });
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  host = `127.0.0.1:${(srv.address() as AddressInfo).port}`;
  return {
    url: `http://${host}/mcp`,
    headers: { authorization: want.toString() },
    close: () =>
      new Promise((resolve) => {
        srv.closeAllConnections();
        srv.close(() => resolve());
      }),
  };
}

const defaultPrompt = join(import.meta.dirname, '../../internal/admin/autopilot_prompt.md');

// replayMain runs one replay from argv and prints its report as JSON on
// stdout. With --save it writes the bundle instead, runs no model and
// returns null.
export async function replayMain(adapters: Partial<Record<Provider, Adapter>>, argv = process.argv.slice(2)): Promise<Report | null> {
  const { values: o, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      run: { type: 'string' },
      admin: { type: 'string' },
      'token-file': { type: 'string' },
      provider: { type: 'string' },
      model: { type: 'string' },
      prompt: { type: 'string' },
      save: { type: 'string' },
      file: { type: 'string' },
      'max-turns': { type: 'string' },
    },
  });
  const caseID = Number(positionals[0]);
  if (positionals.length !== 1 || !Number.isSafeInteger(caseID) || caseID < 1) {
    throw new Error('usage: replay <case> [--run N] (--admin URL --token-file F [--save FILE] | --file FILE) [--provider P --model M] [--prompt FILE] [--max-turns N]');
  }
  const maxTurns = Number(o['max-turns'] ?? 30);
  if (!Number.isSafeInteger(maxTurns) || maxTurns < 1 || maxTurns > 100) {
    throw new Error('--max-turns is a whole number from 1 to 100');
  }

  let bundle: Bundle;
  let prompt: string | undefined;
  if (o.file !== undefined) {
    if (o.admin !== undefined || o.save !== undefined || o.run !== undefined) {
      throw new Error('--file replays a saved bundle: it takes no --admin, --save or --run');
    }
    bundle = await loadBundle(o.file);
    if (bundle.case.id !== caseID) {
      throw new Error(`${o.file} is a bundle of case ${bundle.case.id}, not ${caseID}`);
    }
  } else {
    if (o.admin === undefined || o['token-file'] === undefined) {
      throw new Error('give --admin and --token-file to read the case from admin, or --file to replay a saved bundle');
    }
    const token = (await readFile(o['token-file'], 'utf8')).trim();
    const runID = o.run === undefined ? undefined : Number(o.run);
    ({ bundle, prompt } = await fromAdmin(o.admin.replace(/\/+$/, ''), token, caseID, runID));
    if (o.save !== undefined) {
      // It holds client IPs and stats. mode applies only to a new file, so
      // an existing one is narrowed once truncated and before it is written.
      const f = await open(o.save, 'w', 0o600);
      try {
        await f.chmod(0o600);
        await f.writeFile(JSON.stringify(bundle, null, 2) + '\n');
      } finally {
        await f.close();
      }
      return null;
    }
  }
  // The prompt text is not recorded, so a replay uses the current one and says when it changed.
  if (o.prompt !== undefined || prompt === undefined) {
    prompt = await readFile(o.prompt ?? defaultPrompt, 'utf8');
  }

  const { run } = bundle;
  const provider = (o.provider ?? run.provider) as Provider;
  const model = o.model ?? run.model;
  const adapter = adapters[provider];
  if (!adapter) {
    throw new Error(`no adapter for provider ${provider}: give claude or openai`);
  }
  const rec = new Recorded(bundle);
  const mcp = await serve(bundle, rec);
  const workDir = await mkdtemp(join(tmpdir(), 'autopilot-replay-'));
  const start = performance.now();
  let out;
  try {
    out = await adapter({
      claim: {
        case_id: bundle.case.id,
        kind: bundle.case.kind,
        brief: bundle.case.brief,
        run_id: run.id,
        attempt: 1,
        lease_until: '',
        provider,
        model,
        prompt,
        prompt_sha256: sha256(prompt),
        tools_sha256: bundle.contract.tools_sha256,
        output_schema: bundle.contract.output_schema,
      },
      mcpURL: mcp.url,
      mcpHeaders: mcp.headers,
      maxTurns,
      workDir,
      signal: new AbortController().signal,
      emit: () => undefined,
    });
  } finally {
    await mcp.close();
    await rm(workDir, { recursive: true, force: true });
  }
  const seconds = Math.round(performance.now() - start) / 1000;
  const v = verdictSchema.safeParse(out.output);
  if (out.error || !v.success) {
    process.stderr.write(`the replay gave no verdict: ${out.error || 'invalid_output'}\n`);
  }
  const recordedVerdict = run.id === bundle.case.run_id ? (bundle.case.verdict ?? '') : '';
  const replayVerdict = v.success ? v.data.verdict : '';
  const report: Report = {
    case: bundle.case.id,
    run: run.id,
    recorded: {
      provider: run.provider,
      model: run.model,
      verdict: recordedVerdict,
      tokens: { input_tokens: run.input_tokens ?? 0, output_tokens: run.output_tokens ?? 0, cache_read_tokens: run.cache_read_tokens ?? 0, cache_write_tokens: run.cache_write_tokens ?? 0 },
      configured_usd_micros: run.configured_cost_usd_micros,
      provider_usd_micros: run.provider_cost_usd_micros,
    },
    replay: { provider, model, verdict: replayVerdict, turns: out.turns, tool_calls: out.toolCalls, tokens: out.usage, provider_cost_usd: out.costUSD, seconds },
    differences: {
      verdict: replayVerdict !== recordedVerdict,
      prompt_changed: sha256(prompt) !== run.prompt_sha256,
      tools_changed: bundle.contract.tools_sha256 !== run.tools_sha256,
      unrecorded_calls: rec.unrecorded,
      recorded_calls_not_made: rec.notMade(bundle.calls),
    },
  };
  process.stdout.write(JSON.stringify(report) + '\n');
  return report;
}

if (import.meta.main) {
  const { runClaude } = await import('./claude.ts');
  const { runOpenAI } = await import('./openai.ts');
  await replayMain({ claude: runClaude, openai: runOpenAI });
}
