import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadConfig } from '../src/config.ts';

const dir = mkdtempSync(join(tmpdir(), 'autopilot-config-'));
const tokenFile = join(dir, 'token');
writeFileSync(tokenFile, 'autopilot-token-0123456789abcdefghijklmnop\n');
const shortFile = join(dir, 'short');
writeFileSync(shortFile, 'too-short\n');
const splitFile = join(dir, 'split');
writeFileSync(splitFile, 'autopilot-token-0123456789\nabcdefghijklmnop\n');

const base = { AUTOPILOT_ADMIN_URL: 'http://admin:8081/', AUTOPILOT_TOKEN_FILE: tokenFile, CLAUDE_CODE_OAUTH_TOKEN: 'fake' };

test('the required variables alone give the documented defaults', () => {
  const c = loadConfig(base);
  assert.equal(c.adminURL, 'http://admin:8081');
  assert.equal(c.token, 'autopilot-token-0123456789abcdefghijklmnop');
  assert.deepEqual(
    { concurrency: c.concurrency, caseTimeoutMs: c.caseTimeoutMs, maxTurns: c.maxTurns, providers: c.providers },
    { concurrency: 1, caseTimeoutMs: 600_000, maxTurns: 30, providers: ['claude'] },
  );
  assert.match(c.sdkVersion, /^claude-agent-sdk \d+\.\d+\.\d+, openai-agents \d+\.\d+\.\d+$/);
});

test('each credential adds its provider', () => {
  const c = loadConfig({ AUTOPILOT_ADMIN_URL: 'https://admin.internal', AUTOPILOT_TOKEN_FILE: tokenFile, ANTHROPIC_API_KEY: 'fake', OPENAI_API_KEY: 'fake' });
  assert.deepEqual(c.providers, ['claude', 'openai']);
});

test('settings in range are read', () => {
  const c = loadConfig({ ...base, AUTOPILOT_CONCURRENCY: '4', AUTOPILOT_CASE_TIMEOUT: '90s', AUTOPILOT_MAX_TURNS: '100' });
  assert.deepEqual([c.concurrency, c.caseTimeoutMs, c.maxTurns], [4, 90_000, 100]);
});

for (const [name, env, want] of [
  ['no admin URL is refused', { ...base, AUTOPILOT_ADMIN_URL: '' }, /AUTOPILOT_ADMIN_URL is required/],
  ['an admin URL with a user is refused', { ...base, AUTOPILOT_ADMIN_URL: 'http://u:p@admin:8081' }, /no user, query or fragment/],
  ['an admin URL with a query is refused', { ...base, AUTOPILOT_ADMIN_URL: 'http://admin:8081/?x=1' }, /no user, query or fragment/],
  ['a file URL is refused', { ...base, AUTOPILOT_ADMIN_URL: 'file:///etc/passwd' }, /http or https/],
  ['no token file is refused', { ...base, AUTOPILOT_TOKEN_FILE: '' }, /AUTOPILOT_TOKEN_FILE is required/],
  ['a missing token file is refused', { ...base, AUTOPILOT_TOKEN_FILE: join(dir, 'missing') }, /AUTOPILOT_TOKEN_FILE .*missing can't be read/],
  ['a token under 32 characters is refused', { ...base, AUTOPILOT_TOKEN_FILE: shortFile }, /at least 32 characters/],
  ['a token file with a line break inside the token is refused', { ...base, AUTOPILOT_TOKEN_FILE: splitFile }, /no spaces or line breaks/],
  ['no credential is refused', { AUTOPILOT_ADMIN_URL: 'http://admin:8081', AUTOPILOT_TOKEN_FILE: tokenFile }, /CLAUDE_CODE_OAUTH_TOKEN/],
  ['five concurrent runs are refused', { ...base, AUTOPILOT_CONCURRENCY: '5' }, /AUTOPILOT_CONCURRENCY must be a whole number from 1 to 4/],
  ['a case timeout under 1s is refused', { ...base, AUTOPILOT_CASE_TIMEOUT: '999ms' }, /AUTOPILOT_CASE_TIMEOUT/],
  ['a case timeout over an hour is refused', { ...base, AUTOPILOT_CASE_TIMEOUT: '2h' }, /AUTOPILOT_CASE_TIMEOUT/],
  ['a case timeout without a unit is refused', { ...base, AUTOPILOT_CASE_TIMEOUT: '600' }, /AUTOPILOT_CASE_TIMEOUT/],
  ['zero turns are refused', { ...base, AUTOPILOT_MAX_TURNS: '0' }, /AUTOPILOT_MAX_TURNS/],
  ['101 turns are refused', { ...base, AUTOPILOT_MAX_TURNS: '101' }, /AUTOPILOT_MAX_TURNS/],
] as const) {
  test(name, () => {
    assert.throws(() => loadConfig(env), want);
  });
}
