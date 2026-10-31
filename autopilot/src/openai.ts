import {
  Agent,
  MaxTurnsExceededError,
  MCPServerStreamableHttp,
  ModelBehaviorError,
  ModelRefusalError,
  run,
  setTracingDisabled,
  type JsonSchemaDefinition,
  type RunItem,
  type Usage,
} from '@openai/agents';
import { casePrompt, type Adapter, type Outcome } from './runner.ts';

// Tracing is on by default and would send prompts and tool results to
// OpenAI's trace store.
setTracingDisabled(true);

// openaiEvents is what a run's items add to its events.
export function openaiEvents(items: RunItem[]): [string, Record<string, unknown>][] {
  const out: [string, Record<string, unknown>][] = [];
  for (const item of items) {
    if (item.type === 'tool_call_item') {
      const raw = item.rawItem;
      // Admin already records each call's arguments, redacted where needed, so only the size is kept here.
      out.push(['tool_use', raw.type === 'function_call' ? { name: raw.name, bytes: Buffer.byteLength(raw.arguments) } : { type: raw.type }]);
    } else if (item.type === 'tool_call_output_item') {
      // Admin already stores each tool's full answer, and both count against the run's event cap.
      out.push(['tool_result', { bytes: Buffer.byteLength(JSON.stringify(item.output ?? null)) }]);
    } else if (item.type === 'message_output_item') {
      out.push(['assistant_text', { content: item.rawItem.content }]);
    }
  }
  return out;
}

// fromOpenAI is a run's outcome. OpenAI counts cached input inside
// inputTokens, so cached tokens are moved out of input; it reports no cost.
export function fromOpenAI(usage: Usage, toolCalls: number, output: unknown, error: string): Outcome {
  let cached = 0;
  for (const d of usage.inputTokensDetails) {
    const n = d['cached_tokens'];
    cached += typeof n === 'number' ? n : 0;
  }
  return {
    output,
    error,
    turns: usage.requests,
    toolCalls,
    usage: { input_tokens: usage.inputTokens - cached, output_tokens: usage.outputTokens, cache_read_tokens: cached, cache_write_tokens: 0 },
    costUSD: null,
  };
}

// Failure is what a run's error handler sees when max turns, a refusal or an
// unparseable final output ends the run. It names only the fields read here,
// since the SDK's own type is fixed to one agent's output type.
export interface Failure {
  error: MaxTurnsExceededError | ModelRefusalError | ModelBehaviorError;
  runData: { newItems: RunItem[]; state?: { usage: Usage } };
}

// failure is the usage, items and error category of a run the SDK ended with
// an error, or undefined for an error to rethrow. The record counts only for the
// error it saw: the SDK also calls the handler on turns it then continues past.
export function failure(seen: Failure | undefined, e: unknown): { usage: Usage; items: RunItem[]; error: string } | undefined {
  if (seen?.runData.state && seen.error === e) {
    const error = seen.error instanceof MaxTurnsExceededError ? 'error_max_turns' : seen.error instanceof ModelRefusalError ? 'refusal' : 'invalid_output';
    return { usage: seen.runData.state.usage, items: seen.runData.newItems, error };
  }
  if (e instanceof MaxTurnsExceededError && e.state) {
    // _generatedItems is what result.newItems returns on success.
    return { usage: e.state.usage, items: e.state._generatedItems, error: 'error_max_turns' };
  }
  return undefined;
}

export const runOpenAI: Adapter = async (input) => {
  const admin = new MCPServerStreamableHttp({ name: 'admin', url: input.mcpURL, requestInit: { headers: input.mcpHeaders } });
  await admin.connect();
  try {
    const agent = new Agent({
      name: 'autopilot',
      instructions: input.claim.prompt,
      model: input.claim.model,
      // The Responses API otherwise keeps each response at OpenAI for 30 days.
      modelSettings: { store: false },
      mcpServers: [admin],
      // Not strict: strict mode accepts only a subset of JSON Schema and the
      // schema is admin's. The runner checks the output against it instead.
      outputType: {
        type: 'json_schema',
        name: 'verdict',
        strict: false,
        schema: input.claim.output_schema as JsonSchemaDefinition['schema'],
      },
    });
    // emit records a run's items and counts its tool calls.
    const emit = (items: RunItem[]) => {
      const events = openaiEvents(items);
      for (const [kind, payload] of events) {
        input.emit(kind, payload);
      }
      return events.filter(([kind]) => kind === 'tool_use').length;
    };
    // An unparseable final output throws with no state, so the handler keeps
    // the run's items and usage. Returning nothing leaves the error thrown.
    const seen: { failure?: Failure } = {};
    let result;
    try {
      result = await run(agent, casePrompt(input.claim), {
        maxTurns: input.maxTurns,
        signal: input.signal,
        errorHandlers: { default: ({ error, runData }) => void (seen.failure = { error, runData }) },
      });
    } catch (e) {
      const f = failure(seen.failure, e);
      if (f) {
        return fromOpenAI(f.usage, emit(f.items), null, f.error);
      }
      throw e;
    }
    return fromOpenAI(result.state.usage, emit(result.newItems), result.finalOutput, '');
  } finally {
    await admin.close();
  }
};
