// Golden cases: bundles recorded from the load-full attacks, each with the
// verdict a model should reach. CI only loads them; AUTOPILOT_LIVE=1
// replays each against the real provider, which costs tokens.
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { runClaude } from '../src/claude.ts';
import { runOpenAI } from '../src/openai.ts';
import { loadBundle, replayMain } from '../src/replay.ts';

const dir = join(import.meta.dirname, 'golden');
const live = process.env['AUTOPILOT_LIVE'] === '1';

test('every golden bundle loads and names its verdict', async () => {
  const names = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  assert.deepEqual(names, ['asn.json', 'idor.json', 'scanner.json', 'scraping.json', 'stuffing.json']);
  for (const name of names) {
    const b = await loadBundle(join(dir, name));
    assert.ok(['attack', 'benign', 'unsure'].includes(b.expect?.verdict ?? ''), `${name} names no verdict`);
  }
});

test('golden bundles replay against the real provider', { skip: !live && 'set AUTOPILOT_LIVE=1 to replay against the real provider' }, async (t) => {
  for (const name of readdirSync(dir).filter((f) => f.endsWith('.json'))) {
    await t.test(name, async (t) => {
      const file = join(dir, name);
      const b = await loadBundle(file);
      const report = await replayMain({ claude: runClaude, openai: runOpenAI }, [String(b.case.id), '--file', file]);
      assert.ok(report);
      t.diagnostic(JSON.stringify({ verdict: report.replay.verdict, tokens: report.replay.tokens, seconds: report.replay.seconds }));
      assert.equal(report.replay.verdict, b.expect?.verdict);
    });
  }
});
