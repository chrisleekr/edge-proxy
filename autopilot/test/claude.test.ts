import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { SDKAssistantMessage, SDKResultError, SDKResultSuccess, SDKSystemMessage, SDKUserMessage } from '@anthropic-ai/claude-agent-sdk';
import { claudeEvents, claudeOptions, fromClaude } from '../src/claude.ts';
import type { RunInput } from '../src/runner.ts';

const input: RunInput = {
  claim: {
    case_id: 7,
    kind: 'investigate',
    brief: { kind: 'investigate', question: 'Guessing passwords?' },
    run_id: 9,
    attempt: 1,
    lease_until: '2026-10-28T00:10:00Z',
    provider: 'claude',
    model: 'claude-opus-5-5',
    prompt: 'You are the autopilot.',
    prompt_sha256: '',
    tools_sha256: '',
    output_schema: { type: 'object' },
  },
  mcpURL: 'http://admin:8081/v1/mcp',
  mcpHeaders: { Authorization: 'Bearer t', 'X-Autopilot-Run': '9' },
  maxTurns: 30,
  workDir: '/tmp/autopilot-run-x',
  signal: new AbortController().signal,
  emit: () => undefined,
};

test('a Claude run gets no built-in tools, no settings from disk and only admin over MCP', () => {
  const o = claudeOptions(input, new AbortController());
  assert.deepEqual(o.tools, []);
  assert.deepEqual(o.allowedTools, ['mcp__admin__*']);
  assert.deepEqual(o.settingSources, []);
  assert.deepEqual(o.mcpServers, { admin: { type: 'http', url: 'http://admin:8081/v1/mcp', headers: input.mcpHeaders, alwaysLoad: true } });
  assert.equal(o.strictMcpConfig, true);
  assert.equal(o.permissionMode, 'dontAsk');
  assert.equal(o.persistSession, false);
  assert.equal(o.systemPrompt, 'You are the autopilot.');
  assert.deepEqual(o.outputFormat, { type: 'json_schema', schema: { type: 'object' } });
  assert.equal(o.cwd, '/tmp/autopilot-run-x');
});

test('a Claude run sends the brief as written, with no @path expansion or slash commands', () => {
  assert.equal(claudeOptions(input, new AbortController()).verbatimPrompts, true);
});

test("the Claude CLI gets its own config directory and never the OpenAI key", () => {
  process.env['OPENAI_API_KEY'] = 'fake-openai-key';
  const env = claudeOptions(input, new AbortController()).env ?? {};
  assert.equal(env['OPENAI_API_KEY'], undefined);
  assert.equal(env['CLAUDE_CONFIG_DIR'], '/tmp/autopilot-run-x');
  assert.equal(env['HOME'], '/tmp/autopilot-run-x');
  assert.equal(env['CLAUDE_CODE_DISABLE_AUTO_MEMORY'], '1');
  assert.equal(env['CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'], '1');
});

const tokens = { input_tokens: 1200, output_tokens: 300, cache_read_input_tokens: 5000, cache_creation_input_tokens: 800 };

// usage as an assistant message carries it, and as a result totals it.
const messageUsage = {
  ...tokens,
  cache_creation: null,
  fallback_credit: null,
  inference_geo: null,
  iterations: null,
  output_tokens_details: null,
  server_tool_use: null,
  service_tier: null,
  speed: null,
};
const resultUsage = {
  ...tokens,
  cache_creation: { ephemeral_1h_input_tokens: 0, ephemeral_5m_input_tokens: 800 },
  fallback_credit: null,
  inference_geo: 'global',
  iterations: [],
  output_tokens_details: { thinking_tokens: 0 },
  server_tool_use: { web_fetch_requests: 0, web_search_requests: 0 },
  service_tier: 'standard' as const,
  speed: 'standard' as const,
};

test('an assistant message adds its text and each tool call', () => {
  const msg = {
    type: 'assistant',
    message: {
      id: 'msg_1',
      type: 'message',
      role: 'assistant',
      model: 'claude-opus-5-5',
      content: [
        { type: 'text', text: 'Reading the case', citations: null },
        { type: 'tool_use', id: 'tu_1', name: 'mcp__admin__get_case', input: {}, caller: { type: 'direct' } },
      ],
      container: null,
      context_management: null,
      stop_reason: 'tool_use',
      stop_sequence: null,
      stop_details: null,
      diagnostics: null,
      usage: messageUsage,
    },
    parent_tool_use_id: null,
    uuid: '00000000-0000-0000-0000-000000000001',
    session_id: 's',
  } satisfies SDKAssistantMessage;
  assert.deepEqual(claudeEvents(msg), [
    ['assistant_text', { text: 'Reading the case' }],
    ['tool_use', { id: 'tu_1', name: 'mcp__admin__get_case', bytes: 2 }],
  ]);
});

test('a tool_use event carries the tool name and input size, not the input', () => {
  const input = { note: 'the upstream accepts token sk-live-123' };
  const msg = {
    type: 'assistant',
    message: {
      id: 'msg_2',
      type: 'message',
      role: 'assistant',
      model: 'claude-opus-5-5',
      content: [{ type: 'tool_use', id: 'tu_3', name: 'mcp__admin__record_learning', input, caller: { type: 'direct' } }],
      container: null,
      context_management: null,
      stop_reason: 'tool_use',
      stop_sequence: null,
      stop_details: null,
      diagnostics: null,
      usage: messageUsage,
    },
    parent_tool_use_id: null,
    uuid: '00000000-0000-0000-0000-000000000003',
    session_id: 's',
  } satisfies SDKAssistantMessage;
  const events = claudeEvents(msg);
  assert.deepEqual(events, [['tool_use', { id: 'tu_3', name: 'mcp__admin__record_learning', bytes: Buffer.byteLength(JSON.stringify(input)) }]]);
  assert.ok(!JSON.stringify(events).includes('sk-live-123'));
});

test('the init message records the tools and MCP servers the run has', () => {
  const msg = {
    type: 'system',
    subtype: 'init',
    apiKeySource: 'ANTHROPIC_API_KEY',
    claude_code_version: '2.1.312',
    cwd: '/tmp/autopilot-run-x',
    tools: ['mcp__admin__get_case'],
    mcp_servers: [{ name: 'admin', status: 'connected' }],
    model: 'claude-opus-5-5',
    permissionMode: 'dontAsk',
    slash_commands: [],
    output_style: 'default',
    skills: [],
    plugins: [],
    uuid: '00000000-0000-0000-0000-000000000003',
    session_id: 's',
  } satisfies SDKSystemMessage;
  assert.deepEqual(claudeEvents(msg), [
    ['init', { claude_code_version: '2.1.312', model: 'claude-opus-5-5', tools: ['mcp__admin__get_case'], mcp_servers: [{ name: 'admin', status: 'connected' }] }],
  ]);
});

test("a tool result is recorded as its size, since admin keeps the tool's answer", () => {
  const content = [{ type: 'text' as const, text: '{"case_id":7}' }];
  const msg = {
    type: 'user',
    message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_1', content }] },
    parent_tool_use_id: null,
    session_id: 's',
  } satisfies SDKUserMessage;
  assert.deepEqual(claudeEvents(msg), [['tool_result', { tool_use_id: 'tu_1', is_error: false, bytes: Buffer.byteLength(JSON.stringify(content)) }]]);
});

const result = {
  type: 'result',
  subtype: 'success',
  duration_ms: 1000,
  duration_api_ms: 900,
  is_error: false,
  num_turns: 4,
  result: '',
  stop_reason: 'end_turn',
  total_cost_usd: 0.42,
  usage: resultUsage,
  modelUsage: {},
  permission_denials: [{ tool_name: 'Bash', tool_use_id: 'tu_2', tool_input: { command: 'ls' } }],
  structured_output: { verdict: 'attack', summary: 'One /24', proposals: [3] },
  uuid: '00000000-0000-0000-0000-000000000002',
  session_id: 's',
} satisfies SDKResultSuccess;

test('a refused tool call is recorded as permission_denied', () => {
  assert.deepEqual(claudeEvents(result), [
    ['permission_denied', { tool_name: 'Bash', tool_use_id: 'tu_2' }],
    ['result', { subtype: 'success', is_error: false, num_turns: 4 }],
  ]);
});

test('a successful result carries the structured output, turns, tokens and cost', () => {
  assert.deepEqual(fromClaude(result, 2), {
    output: { verdict: 'attack', summary: 'One /24', proposals: [3] },
    error: '',
    turns: 4,
    toolCalls: 2,
    usage: { input_tokens: 1200, output_tokens: 300, cache_read_tokens: 5000, cache_write_tokens: 800 },
    costUSD: 0.42,
  });
});

test('a run that hit its turn limit ends as error_max_turns with its usage', () => {
  const r = { ...result, subtype: 'error_max_turns', errors: [] } satisfies SDKResultError;
  const out = fromClaude(r, 30);
  assert.equal(out.error, 'error_max_turns');
  assert.equal(out.output, null);
  assert.equal(out.usage.input_tokens, 1200);
});

test('a result marked is_error ends as api_error with no output', () => {
  const out = fromClaude({ ...result, is_error: true }, 2);
  assert.equal(out.error, 'api_error');
  assert.equal(out.output, null);
});
