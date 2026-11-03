import type { Provider } from './config.ts';

// A claimed case, as admin's POST /v1/autopilot/claim answers it.
export interface Claim {
  case_id: number;
  kind: string;
  brief: unknown;
  run_id: number;
  attempt: number;
  lease_until: string;
  provider: Provider;
  model: string;
  prompt: string;
  prompt_sha256: string;
  tools_sha256: string;
  output_schema: Record<string, unknown>;
}

export interface RunEvent {
  seq: number;
  kind: string;
  at: string;
  payload: Record<string, unknown>;
}

export interface Usage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface Result {
  run_id: number;
  status: 'ok' | 'error' | 'timeout';
  error_category: string;
  verdict?: string;
  summary: string;
  proposals: number[];
  turns: number;
  tool_calls: number;
  usage: Usage;
  provider_cost_usd: number | null;
  transcript_bytes: number;
  transcript_sha256: string;
  last_seq: number;
}

// AdminError is an answer other than 2xx; message is admin's problem detail.
export class AdminError extends Error {
  readonly status: number;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
  }
}

async function detail(resp: Response): Promise<string> {
  try {
    const p = (await resp.json()) as { detail?: string; title?: string };
    return p.detail || p.title || `status ${resp.status}`;
  } catch {
    return `status ${resp.status}`;
  }
}

// Admin is admin's runner API, with the runner token.
export class Admin {
  readonly url: string;
  readonly #token: string;

  constructor(url: string, token: string) {
    this.url = url;
    this.#token = token;
  }

  async #post(path: string, body: unknown, signal: AbortSignal): Promise<Response> {
    const resp = await fetch(this.url + path, {
      method: 'POST',
      headers: { authorization: `Bearer ${this.#token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    });
    if (!resp.ok) {
      throw new AdminError(resp.status, await detail(resp));
    }
    return resp;
  }

  // #send posts and discards the answer, cancelling its body so fetch frees the connection.
  async #send(path: string, body: unknown, signal: AbortSignal): Promise<void> {
    await (await this.#post(path, body, signal)).body?.cancel();
  }

  // claim long-polls for a case; null when none came.
  async claim(body: { runner: string; version: string; sdk_version: string; providers: Provider[]; wait: string }, signal: AbortSignal): Promise<Claim | null> {
    const resp = await this.#post('/v1/autopilot/claim', body, signal);
    if (resp.status === 204) {
      return null;
    }
    return (await resp.json()) as Claim;
  }

  async heartbeat(caseID: number, runID: number, providers: Provider[], signal: AbortSignal): Promise<void> {
    await this.#send(`/v1/autopilot/cases/${caseID}/heartbeat`, { run_id: runID, providers }, signal);
  }

  async events(runID: number, events: RunEvent[], signal: AbortSignal): Promise<void> {
    await this.#send(`/v1/autopilot/runs/${runID}/events`, { events }, signal);
  }

  async result(caseID: number, result: Result, signal: AbortSignal): Promise<void> {
    await this.#send(`/v1/autopilot/cases/${caseID}/result`, result, signal);
  }

  // mcpHeaders are what the model's MCP client sends: the token and the run its calls belong to.
  mcpHeaders(runID: number): Record<string, string> {
    return { Authorization: `Bearer ${this.#token}`, 'X-Autopilot-Run': String(runID) };
  }
}
