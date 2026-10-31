import { query, type Options, type SDKMessage, type SDKResultMessage } from '@anthropic-ai/claude-agent-sdk';
import { casePrompt, type Adapter, type Outcome, type RunInput } from './runner.ts';

// claudeOptions isolates a run: no built-in tools, no settings, memory or
// MCP servers from disk, only admin's MCP tools, and a config directory of
// its own. The CLI gets no OpenAI key.
export function claudeOptions(input: RunInput, abortController: AbortController): Options {
  const env = { ...process.env };
  delete env['OPENAI_API_KEY'];
  return {
    model: input.claim.model,
    systemPrompt: input.claim.prompt,
    // The brief holds client- and operator-written text: an @path in it must not pull a file into context.
    verbatimPrompts: true,
    tools: [],
    allowedTools: ['mcp__admin__*'],
    mcpServers: { admin: { type: 'http', url: input.mcpURL, headers: input.mcpHeaders, alwaysLoad: true } },
    strictMcpConfig: true,
    settingSources: [],
    permissionMode: 'dontAsk',
    persistSession: false,
    cwd: input.workDir,
    // HOME too: the root filesystem is read-only, and the run's directory is writable.
    env: {
      ...env,
      HOME: input.workDir,
      CLAUDE_CONFIG_DIR: input.workDir,
      CLAUDE_CODE_DISABLE_AUTO_MEMORY: '1',
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
    },
    outputFormat: { type: 'json_schema', schema: input.claim.output_schema },
    maxTurns: input.maxTurns,
    abortController,
  };
}

// claudeEvents is what one SDK message adds to the run's events.
export function claudeEvents(msg: SDKMessage): [string, Record<string, unknown>][] {
  const out: [string, Record<string, unknown>][] = [];
  switch (msg.type) {
    case 'system':
      if (msg.subtype === 'init') {
        out.push(['init', { claude_code_version: msg.claude_code_version, model: msg.model, tools: msg.tools, mcp_servers: msg.mcp_servers }]);
      }
      break;
    case 'assistant':
      for (const b of msg.message.content) {
        if (b.type === 'text') {
          out.push(['assistant_text', { text: b.text }]);
        } else if (b.type === 'tool_use') {
          // Admin already records each call's arguments, redacted where needed, so only the size is kept here.
          out.push(['tool_use', { id: b.id, name: b.name, bytes: Buffer.byteLength(JSON.stringify(b.input ?? null)) }]);
        }
      }
      break;
    case 'user':
      if (typeof msg.message.content !== 'string') {
        for (const b of msg.message.content) {
          if (b.type === 'tool_result') {
            // Admin already stores each tool's full answer, and both count against the run's event cap.
            out.push(['tool_result', { tool_use_id: b.tool_use_id, is_error: b.is_error ?? false, bytes: Buffer.byteLength(JSON.stringify(b.content ?? null)) }]);
          }
        }
      }
      break;
    case 'result':
      for (const d of msg.permission_denials) {
        out.push(['permission_denied', { tool_name: d.tool_name, tool_use_id: d.tool_use_id }]);
      }
      out.push(['result', { subtype: msg.subtype, is_error: msg.is_error, num_turns: msg.num_turns }]);
      break;
  }
  return out;
}

// fromClaude is the outcome of a run's result message.
export function fromClaude(r: SDKResultMessage, toolCalls: number): Outcome {
  const out: Outcome = {
    output: null,
    error: '',
    turns: r.num_turns,
    toolCalls,
    usage: {
      input_tokens: r.usage.input_tokens,
      output_tokens: r.usage.output_tokens,
      cache_read_tokens: r.usage.cache_read_input_tokens,
      cache_write_tokens: r.usage.cache_creation_input_tokens,
    },
    costUSD: r.total_cost_usd,
  };
  if (r.subtype !== 'success') {
    out.error = r.subtype;
  } else if (r.is_error) {
    out.error = 'api_error';
  } else {
    out.output = r.structured_output;
  }
  return out;
}

export const runClaude: Adapter = async (input) => {
  const ac = new AbortController();
  input.signal.addEventListener('abort', () => ac.abort(), { once: true });
  let result: SDKResultMessage | undefined;
  let toolCalls = 0;
  try {
    for await (const msg of query({ prompt: casePrompt(input.claim), options: claudeOptions(input, ac) })) {
      for (const [kind, payload] of claudeEvents(msg)) {
        if (kind === 'tool_use') {
          toolCalls++;
        }
        input.emit(kind, payload);
      }
      if (msg.type === 'result') {
        result = msg;
      }
    }
  } catch (e) {
    // The SDK throws after some error results, such as error_max_turns.
    if (!result) {
      throw e;
    }
  }
  if (!result) {
    throw new Error('the Claude run ended without a result');
  }
  return fromClaude(result, toolCalls);
};
