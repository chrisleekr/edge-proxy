import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { Admin, AdminError, type Claim, type Result, type RunEvent, type Usage } from './admin.ts';
import { loadConfig, type Config, type Provider } from './config.ts';

// RunInput is what an adapter gets for one case.
export interface RunInput {
  claim: Claim;
  mcpURL: string;
  mcpHeaders: Record<string, string>;
  maxTurns: number;
  workDir: string;
  signal: AbortSignal;
  emit: (kind: string, payload: Record<string, unknown>) => void;
}

// Outcome is how a run ended: output is the model's structured answer,
// checked by the runner; error names why there is none.
export interface Outcome {
  output: unknown;
  error: string;
  turns: number;
  toolCalls: number;
  usage: Usage;
  costUSD: number | null;
}

export type Adapter = (input: RunInput) => Promise<Outcome>;

export const noUsage: Usage = { input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0 };

// The verdict admin's output schema describes, checked again here so a
// provider that does not enforce the schema can't send admin a bad result.
export const verdictSchema = z.strictObject({
  verdict: z.enum(['attack', 'benign', 'unsure']),
  summary: z.string().max(4000),
  proposals: z.array(z.int()).max(50),
});

// casePrompt is the user turn: the case and its brief, whose client-written
// fields admin marks untrusted.
export function casePrompt(c: Claim): string {
  return `Case ${c.case_id}, a ${c.kind} case. Its brief:\n${JSON.stringify(c.brief)}`;
}

function log(level: 'info' | 'warn' | 'error', msg: string, fields: Record<string, unknown> = {}): void {
  process.stdout.write(JSON.stringify({ time: new Date().toISOString(), level, msg, ...fields }) + '\n');
}

function message(e: unknown): string {
  if (e instanceof Error) {
    // fetch failures say only "fetch failed"; the cause names the network error.
    return e.cause instanceof Error ? `${e.message}: ${e.cause.message}` : e.message;
  }
  return String(e);
}

// Admin keeps at most 1000 events of a run and cuts a payload over 64 KiB;
// a batch must stay under 1 MiB. The runner sends at most 500: admin's own
// record of each MCP call counts against the same 1000.
const maxEvents = 500;
const maxPayload = 64 << 10;
const maxBatch = 900 << 10;

// Recorder numbers a run's events, hashes the full transcript as JSONL and
// holds what admin has not been sent yet. A payload over 64 KiB is sent as
// its size and hash; the transcript hash still covers all of it.
export class Recorder {
  seq = 0;
  bytes = 0;
  #hash = createHash('sha256');
  #pending: RunEvent[] = [];

  emit(kind: string, payload: Record<string, unknown>): void {
    const e: RunEvent = { seq: ++this.seq, kind, at: new Date().toISOString(), payload };
    const line = JSON.stringify(e) + '\n';
    this.#hash.update(line);
    this.bytes += Buffer.byteLength(line);
    const body = JSON.stringify(payload);
    const bodyBytes = Buffer.byteLength(body);
    if (bodyBytes > maxPayload) {
      e.payload = { cut: true, bytes: bodyBytes, sha256: createHash('sha256').update(body).digest('hex') };
    }
    if (e.seq <= maxEvents) {
      this.#pending.push(e);
    }
  }

  // batches takes the pending events in batches under the size admin accepts.
  batches(): RunEvent[][] {
    const out: RunEvent[][] = [];
    let batch: RunEvent[] = [];
    let size = 0;
    for (const e of this.#pending.splice(0)) {
      const n = Buffer.byteLength(JSON.stringify(e));
      if (batch.length > 0 && size + n > maxBatch) {
        out.push(batch);
        batch = [];
        size = 0;
      }
      batch.push(e);
      size += n;
    }
    if (batch.length > 0) {
      out.push(batch);
    }
    return out;
  }

  digest(): string {
    return this.#hash.copy().digest('hex');
  }
}

interface Ctx {
  cfg: Config;
  admin: Admin;
  adapters: Partial<Record<Provider, Adapter>>;
  heartbeatMs: number;
  stop: AbortSignal;
}

// aborted rejects when signal aborts, or at once if it already has: an
// abort event never fires twice.
export function aborted(signal: AbortSignal): Promise<never> {
  return new Promise((_, reject) => {
    const fail = () => reject(new Error(String(signal.reason)));
    if (signal.aborted) {
      fail();
    } else {
      signal.addEventListener('abort', fail, { once: true });
    }
  });
}

// runCase runs one claimed case to a result. A run whose lease lapsed is
// dropped without one: admin has already requeued its case.
async function runCase(ctx: Ctx, claim: Claim): Promise<void> {
  const { cfg, admin } = ctx;
  const ids = { case_id: claim.case_id, run_id: claim.run_id, attempt: claim.attempt, model: claim.model };
  log('info', 'run started', ids);
  const workDir = await mkdtemp(join(tmpdir(), 'autopilot-run-'));
  // A second abort is a no-op, so the first reason is the one reported.
  const ac = new AbortController();
  const abort = (why: string) => ac.abort(why);
  const onStop = () => abort('shutdown');
  ctx.stop.addEventListener('abort', onStop, { once: true });
  if (ctx.stop.aborted) {
    onStop();
  }
  const timer = setTimeout(() => abort('timeout'), cfg.caseTimeoutMs);

  const rec = new Recorder();
  let refused = false; // admin refused events: the run's cap, or the run ended
  let flushing = Promise.resolve();
  const flush = () =>
    (flushing = flushing.then(async () => {
      for (const batch of rec.batches()) {
        if (refused) {
          return;
        }
        try {
          await admin.events(claim.run_id, batch, AbortSignal.timeout(5000));
        } catch (e) {
          refused = e instanceof AdminError && e.status < 500;
          log('warn', 'events not recorded', { ...ids, error: message(e) });
        }
      }
    }));
  const beat = setInterval(() => {
    admin.heartbeat(claim.case_id, claim.run_id, cfg.providers, AbortSignal.timeout(10_000)).catch((e: unknown) => {
      if (e instanceof AdminError && e.status === 409) {
        abort('lease_lost');
        return;
      }
      log('warn', 'heartbeat failed', { ...ids, error: message(e) });
    });
    void flush();
  }, ctx.heartbeatMs);

  let out: Outcome;
  try {
    ac.signal.throwIfAborted();
    const adapter = ctx.adapters[claim.provider];
    if (!adapter) {
      throw new Error(`no adapter for ${claim.provider}`);
    }
    const input: RunInput = {
      claim,
      mcpURL: `${cfg.adminURL}/v1/mcp`,
      mcpHeaders: admin.mcpHeaders(claim.run_id),
      maxTurns: cfg.maxTurns,
      workDir,
      signal: ac.signal,
      emit: (kind, payload) => rec.emit(kind, payload),
    };
    // The race ends the run on abort even if the adapter ignores its signal.
    out = await Promise.race([adapter(input), aborted(ac.signal)]);
  } catch (e) {
    if (!ac.signal.aborted) {
      log('error', 'run failed', { ...ids, error: message(e) });
    }
    out = { output: null, error: 'exception', turns: 0, toolCalls: 0, usage: noUsage, costUSD: null };
  } finally {
    clearInterval(beat);
    clearTimeout(timer);
    ctx.stop.removeEventListener('abort', onStop);
    // A leftover directory only takes /tmp space, so the result still goes.
    await rm(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch((e: unknown) => {
      log('warn', 'run directory not removed', { ...ids, error: message(e) });
    });
  }

  const why = ac.signal.aborted ? String(ac.signal.reason) : '';
  if (why === 'lease_lost') {
    log('warn', 'lease lapsed; dropped the run', ids);
    return;
  }
  const result: Result = {
    run_id: claim.run_id,
    status: 'ok',
    error_category: out.error,
    summary: '',
    proposals: [],
    turns: out.turns,
    tool_calls: out.toolCalls,
    usage: out.usage,
    provider_cost_usd: out.costUSD,
    transcript_bytes: 0,
    transcript_sha256: '',
    last_seq: 0,
  };
  if (why === 'timeout') {
    result.status = 'timeout';
    result.error_category = '';
  } else if (why === 'shutdown') {
    result.status = 'error';
    result.error_category = 'shutdown';
  } else if (out.error) {
    result.status = 'error';
  } else {
    const v = verdictSchema.safeParse(out.output);
    if (v.success) {
      rec.emit('verdict', v.data);
      Object.assign(result, v.data);
    } else {
      result.status = 'error';
      result.error_category = 'invalid_output';
    }
  }
  await flush();
  result.transcript_bytes = rec.bytes;
  result.transcript_sha256 = rec.digest();
  result.last_seq = rec.seq;
  try {
    await admin.result(claim.case_id, result, AbortSignal.timeout(5000));
    log('info', 'run finished', { ...ids, status: result.status, error_category: result.error_category, verdict: result.verdict });
  } catch (e) {
    log('error', 'result not recorded', { ...ids, status: result.status, error: message(e) });
  }
}

// backoff is how long to wait after the nth failed claim in a row.
export function backoff(n: number): number {
  return Math.min(60_000, 1000 * 2 ** Math.min(n - 1, 6)) + Math.random() * 1000;
}

async function loop(ctx: Ctx): Promise<void> {
  const body = { runner: ctx.cfg.runner, version: ctx.cfg.version, sdk_version: ctx.cfg.sdkVersion, providers: ctx.cfg.providers, wait: '30s' };
  let failures = 0;
  while (!ctx.stop.aborted) {
    let claim: Claim | null;
    try {
      // Admin holds a claim up to 30s; past 45s the connection is gone.
      claim = await ctx.admin.claim(body, AbortSignal.any([ctx.stop, AbortSignal.timeout(45_000)]));
      failures = 0;
    } catch (e) {
      if (ctx.stop.aborted) {
        return;
      }
      failures++;
      log('warn', 'claim failed', { status: e instanceof AdminError ? e.status : undefined, error: message(e) });
      await sleep(backoff(failures), undefined, { signal: ctx.stop }).catch(() => undefined);
      continue;
    }
    if (claim) {
      // An escaped error would reject main's Promise.all and drop every concurrent run.
      const ids = { case_id: claim.case_id, run_id: claim.run_id };
      await runCase(ctx, claim).catch((e: unknown) => {
        log('error', 'run failed', { ...ids, error: message(e) });
      });
    }
  }
}

// exit exits once stdout has drained: on macOS a pipe is written
// asynchronously, and process.exit alone drops the last log lines.
function exit(code: number): Promise<never> {
  process.stdout.write('', () => process.exit(code));
  return new Promise(() => undefined);
}

// main runs the runner until SIGTERM or SIGINT. A run in progress is
// aborted and reported as a shutdown; past 10s the process exits anyway.
export async function main(adapters: Partial<Record<Provider, Adapter>>, heartbeatMs: number): Promise<never> {
  let cfg: Config;
  try {
    cfg = loadConfig(process.env);
  } catch (e) {
    log('error', message(e));
    return exit(1);
  }
  const stop = new AbortController();
  const onSignal = () => {
    if (stop.signal.aborted) {
      return;
    }
    log('info', 'stopping');
    stop.abort();
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  // on, not once: the OpenAI SDK's own handler exits the process as soon as
  // no other listener is left.
  process.on('SIGTERM', onSignal);
  process.on('SIGINT', onSignal);
  log('info', 'runner started', { runner: cfg.runner, version: cfg.version, sdk_version: cfg.sdkVersion, providers: cfg.providers, concurrency: cfg.concurrency });
  const ctx: Ctx = { cfg, admin: new Admin(cfg.adminURL, cfg.token), adapters, heartbeatMs, stop: stop.signal };
  await Promise.all(Array.from({ length: cfg.concurrency }, () => loop(ctx)));
  log('info', 'stopped');
  return exit(0);
}
