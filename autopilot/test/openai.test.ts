import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  Agent,
  MaxTurnsExceededError,
  ModelBehaviorError,
  ModelRefusalError,
  RunMessageOutputItem,
  RunToolCallItem,
  RunToolCallOutputItem,
  Usage,
} from '@openai/agents';
import { failure, fromOpenAI, openaiEvents } from '../src/openai.ts';

const agent = new Agent({ name: 'autopilot' });

test("a run's items add its tool calls, the size of their results and the model's text", () => {
  const items = [
    new RunToolCallItem({ type: 'function_call', callId: 'c1', name: 'get_case', arguments: '{}' }, agent),
    new RunToolCallOutputItem({ type: 'function_call_result', callId: 'c1', name: 'get_case', status: 'completed', output: { type: 'text', text: '{"case_id":7}' } }, agent, '{"case_id":7}'),
    new RunMessageOutputItem({ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'Benign' }] }, agent),
  ];
  assert.deepEqual(openaiEvents(items), [
    ['tool_use', { name: 'get_case', bytes: 2 }],
    ['tool_result', { bytes: Buffer.byteLength(JSON.stringify('{"case_id":7}')) }],
    ['assistant_text', { content: [{ type: 'output_text', text: 'Benign' }] }],
  ]);
});

test('a tool_use event carries the tool name and input size, not the input', () => {
  const args = '{"note":"the upstream accepts token sk-live-123"}';
  const events = openaiEvents([new RunToolCallItem({ type: 'function_call', callId: 'c2', name: 'record_learning', arguments: args }, agent)]);
  assert.deepEqual(events, [['tool_use', { name: 'record_learning', bytes: Buffer.byteLength(args) }]]);
  assert.ok(!JSON.stringify(events).includes('sk-live-123'));
});

test('cached input is reported apart from input, and an OpenAI run has no cost', () => {
  const usage = new Usage({ requests: 3, inputTokens: 10_000, outputTokens: 700, totalTokens: 10_700, inputTokensDetails: [{ cached_tokens: 4000 }, { cached_tokens: 2000 }] });
  assert.deepEqual(fromOpenAI(usage, 2, { verdict: 'benign' }, ''), {
    output: { verdict: 'benign' },
    error: '',
    turns: 3,
    toolCalls: 2,
    usage: { input_tokens: 4000, output_tokens: 700, cache_read_tokens: 6000, cache_write_tokens: 0 },
    costUSD: null,
  });
});

for (const [name, error, want] of [
  ['a run that reaches max turns keeps its usage and items', new MaxTurnsExceededError('Max turns (30) exceeded'), 'error_max_turns'],
  ['a refused run keeps its usage and items', new ModelRefusalError('I cannot help with that'), 'refusal'],
  ['a final output that is not JSON keeps its usage and items', new ModelBehaviorError('Invalid output type: Unexpected token'), 'invalid_output'],
] as const) {
  test(name, () => {
    const usage = new Usage({ requests: 2, inputTokens: 900, outputTokens: 80, totalTokens: 980 });
    const items = [new RunToolCallItem({ type: 'function_call', callId: 'c1', name: 'get_case', arguments: '{}' }, agent)];
    assert.deepEqual(failure({ error, runData: { newItems: items, state: { usage } } }, error), { usage, items, error: want });
  });
}

test('an error no handler saw is rethrown', () => {
  assert.equal(failure(undefined, new Error('fetch failed')), undefined);
});

test('a record from an earlier turn does not hide a later error', () => {
  const usage = new Usage({ requests: 1, inputTokens: 400, outputTokens: 40, totalTokens: 440 });
  const earlier = new ModelBehaviorError('Invalid output type: Unexpected token');
  assert.equal(failure({ error: earlier, runData: { newItems: [], state: { usage } } }, new Error('fetch failed')), undefined);
});
