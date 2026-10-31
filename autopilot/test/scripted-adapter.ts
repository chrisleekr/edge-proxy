// The scripted adapter scripted.ts and replay-scripted.ts run in place of
// a model. Test only: the image never holds it.
//
// AUTOPILOT_SCRIPT names a JSON plan:
//   {"steps": [{"tool": "get_case", "arguments": {}}, ...], "verdict": "attack", "summary": "...", "hang": false}
// Each step is one MCP call to the server the run is given, reported as
// tool_use and tool_result events. The answer is the verdict and summary,
// with the proposal_id of every propose call that was accepted. With hang
// set the run calls nothing and waits until it is aborted.
import { readFileSync } from 'node:fs';
import { MCPServerStreamableHttp } from '@openai/agents';
import { aborted, noUsage, type Adapter } from '../src/runner.ts';

interface Plan {
  steps?: { tool: string; arguments: Record<string, unknown> }[];
  verdict?: string;
  summary?: string;
  hang?: boolean;
}

const plan = JSON.parse(readFileSync(process.env['AUTOPILOT_SCRIPT'] ?? '', 'utf8')) as Plan;

export const scripted: Adapter = async (input) => {
  if (plan.hang) {
    await aborted(input.signal);
  }
  const steps = plan.steps ?? [];
  const proposals: number[] = [];
  // The MCP client the OpenAI adapter uses, so this path is the one it takes to admin.
  const admin = new MCPServerStreamableHttp({ name: 'admin', url: input.mcpURL, requestInit: { headers: input.mcpHeaders } });
  await admin.connect();
  try {
    for (const step of steps) {
      input.emit('tool_use', { name: step.tool, input: step.arguments });
      const res = await admin.callToolResult(step.tool, step.arguments, null, { signal: input.signal });
      input.emit('tool_result', { name: step.tool, is_error: res.isError === true });
      const out = res.structuredContent as { accepted?: boolean; proposal_id?: number } | undefined;
      if (step.tool === 'propose' && out?.accepted && out.proposal_id !== undefined) {
        proposals.push(out.proposal_id);
      }
    }
  } finally {
    await admin.close();
  }
  return { output: { verdict: plan.verdict, summary: plan.summary ?? '', proposals }, error: '', turns: steps.length + 1, toolCalls: steps.length, usage: noUsage, costUSD: null };
};
