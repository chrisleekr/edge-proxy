import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { backoff, Recorder, verdictSchema } from '../src/runner.ts';

test('events are numbered from 1 and the transcript hash covers each as a JSONL line', () => {
  const r = new Recorder();
  r.emit('tool_use', { name: 'get_case' });
  r.emit('verdict', { verdict: 'benign' });
  const [batch, ...rest] = r.batches();
  assert.equal(rest.length, 0);
  assert.deepEqual(
    batch?.map((e) => [e.seq, e.kind]),
    [
      [1, 'tool_use'],
      [2, 'verdict'],
    ],
  );
  const jsonl = batch?.map((e) => JSON.stringify(e) + '\n').join('') ?? '';
  assert.equal(r.digest(), createHash('sha256').update(jsonl).digest('hex'));
  assert.equal(r.bytes, Buffer.byteLength(jsonl));
});

test('a payload over 64 KiB is sent as its size and hash, and the transcript keeps all of it', () => {
  const r = new Recorder();
  const text = 'a'.repeat(70 << 10);
  r.emit('assistant_text', { text });
  const body = JSON.stringify({ text });
  const sent = r.batches()[0]?.[0];
  assert.deepEqual(sent?.payload, { cut: true, bytes: body.length, sha256: createHash('sha256').update(body).digest('hex') });
  assert.ok(r.bytes > 70 << 10);
});

test('events past 500 are counted but not sent, so admin sees the telemetry as incomplete', () => {
  const r = new Recorder();
  for (let i = 0; i < 501; i++) {
    r.emit('tool_use', { i });
  }
  assert.equal(r.seq, 501);
  assert.equal(r.batches().flat().length, 500);
});

test('batches stay under 1 MiB', () => {
  const r = new Recorder();
  for (let i = 0; i < 40; i++) {
    r.emit('assistant_text', { text: 'b'.repeat(60 << 10) });
  }
  const batches = r.batches();
  assert.ok(batches.length > 1);
  for (const b of batches) {
    assert.ok(Buffer.byteLength(JSON.stringify({ events: b })) < 1 << 20);
  }
  assert.equal(batches.flat().length, 40);
  assert.equal(r.batches().length, 0);
});

test('a verdict with a field the schema does not list is refused', () => {
  assert.equal(verdictSchema.safeParse({ verdict: 'attack', summary: 's', needs_you: [], details: '', proposals: [], extra: 1 }).success, false);
});

test('a verdict outside attack, benign and unsure is refused', () => {
  assert.equal(verdictSchema.safeParse({ verdict: 'maybe', summary: 's', needs_you: [], details: '', proposals: [] }).success, false);
});

test('a well-formed verdict is accepted', () => {
  assert.equal(verdictSchema.safeParse({ verdict: 'attack', summary: 's', needs_you: [], details: '', proposals: [1] }).success, true);
});

test('claim backoff doubles from 1s and stops growing at 60s', () => {
  assert.ok(backoff(1) >= 1000 && backoff(1) < 2000);
  assert.ok(backoff(3) >= 4000 && backoff(3) < 5000);
  assert.ok(backoff(20) >= 60_000 && backoff(20) < 61_000);
});

const okVerdict = { verdict: 'attack', summary: 's', needs_you: [], details: '', proposals: [] };
const item = { rule: '', ask: 'Decide.' };

test('a verdict with six needs_you items is refused', () => {
  assert.equal(verdictSchema.safeParse({ ...okVerdict, needs_you: Array(6).fill(item) }).success, false);
});

test('a verdict with five needs_you items is accepted', () => {
  assert.equal(verdictSchema.safeParse({ ...okVerdict, needs_you: Array(5).fill(item) }).success, true);
});

test('a needs_you item with an unknown field is refused', () => {
  assert.equal(verdictSchema.safeParse({ ...okVerdict, needs_you: [{ rule: 'ap-x', ask: 'a', extra: 1 }] }).success, false);
});

test('a verdict with a 301-character summary is refused', () => {
  assert.equal(verdictSchema.safeParse({ ...okVerdict, summary: 'a'.repeat(301) }).success, false);
});

test('a needs_you item with an empty ask is refused', () => {
  assert.equal(verdictSchema.safeParse({ ...okVerdict, needs_you: [{ rule: '', ask: '' }] }).success, false);
});

test('a needs_you rule of 65 characters is refused and 64 accepted', () => {
  assert.equal(verdictSchema.safeParse({ ...okVerdict, needs_you: [{ rule: 'a'.repeat(65), ask: 'Decide.' }] }).success, false);
  assert.equal(verdictSchema.safeParse({ ...okVerdict, needs_you: [{ rule: 'a'.repeat(64), ask: 'Decide.' }] }).success, true);
});

test('NUL in the summary, details, an ask or a rule is refused', () => {
  assert.equal(verdictSchema.safeParse({ ...okVerdict, summary: 'a\0b' }).success, false);
  assert.equal(verdictSchema.safeParse({ ...okVerdict, details: 'a\0b' }).success, false);
  assert.equal(verdictSchema.safeParse({ ...okVerdict, needs_you: [{ rule: '', ask: 'a\0b' }] }).success, false);
  assert.equal(verdictSchema.safeParse({ ...okVerdict, needs_you: [{ rule: 'a\0b', ask: 'Decide.' }] }).success, false);
});
