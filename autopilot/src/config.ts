import { readFileSync } from 'node:fs';
import { hostname } from 'node:os';

export type Provider = 'claude' | 'openai';

export interface Config {
  adminURL: string;
  token: string;
  concurrency: number;
  caseTimeoutMs: number;
  maxTurns: number;
  providers: Provider[];
  runner: string;
  version: string;
  sdkVersion: string;
}

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
  version: string;
  dependencies: Record<string, string>;
};

// Admin records both on every run, so a verdict traces back to the code that produced it.
export const version = pkg.version;
export const sdkVersion = `claude-agent-sdk ${pkg.dependencies['@anthropic-ai/claude-agent-sdk']}, openai-agents ${pkg.dependencies['@openai/agents']}`;

const units: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 };

// parseDuration reads one number and unit, as 90s or 10m.
export function parseDuration(s: string): number {
  const m = /^(\d+)(ms|s|m|h)$/.exec(s);
  if (!m?.[1] || !m[2]) {
    return NaN;
  }
  return Number(m[1]) * (units[m[2]] ?? NaN);
}

function int(name: string, v: string | undefined, def: number, min: number, max: number): number {
  if (v === undefined || v === '') {
    return def;
  }
  const n = /^\d+$/.test(v) ? Number(v) : NaN;
  if (!(n >= min && n <= max)) {
    throw new Error(`${name} must be a whole number from ${min} to ${max}`);
  }
  return n;
}

function duration(name: string, v: string | undefined, def: number, min: number, max: number): number {
  if (v === undefined || v === '') {
    return def;
  }
  const ms = parseDuration(v);
  if (!(ms >= min && ms <= max)) {
    throw new Error(`${name} must be a duration such as 90s or 10m, from ${min / 1000}s to ${max / 3_600_000}h`);
  }
  return ms;
}

// adminURL accepts admin's base URL only: credentials go in the token file,
// and a query or fragment would be dropped from every request path.
function adminURL(v: string | undefined): string {
  if (!v) {
    throw new Error("AUTOPILOT_ADMIN_URL is required: admin's base URL, as http://admin:8081");
  }
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new Error('AUTOPILOT_ADMIN_URL must be an http or https URL');
  }
  if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.username || u.password || u.search || u.hash) {
    throw new Error('AUTOPILOT_ADMIN_URL must be an http or https URL with no user, query or fragment');
  }
  return u.origin + u.pathname.replace(/\/+$/, '');
}

export function loadConfig(env: Record<string, string | undefined>): Config {
  const url = adminURL(env['AUTOPILOT_ADMIN_URL']);
  const file = env['AUTOPILOT_TOKEN_FILE'];
  if (!file) {
    throw new Error("AUTOPILOT_TOKEN_FILE is required: the file holding admin's runner token");
  }
  let token: string;
  try {
    token = readFileSync(file, 'utf8').trim();
  } catch (e) {
    // The log line adds the cause's message, so it is not repeated here.
    throw new Error(`AUTOPILOT_TOKEN_FILE ${file} can't be read`, { cause: e });
  }
  if (token.length < 32) {
    throw new Error('AUTOPILOT_TOKEN_FILE must hold a token of at least 32 characters');
  }
  // fetch refuses such a header value with an error that quotes it, and the claim loop logs that error.
  if (!/^[\x21-\x7e]+$/.test(token)) {
    throw new Error('AUTOPILOT_TOKEN_FILE must hold one token of printable ASCII, with no spaces or line breaks');
  }
  const providers: Provider[] = [];
  if (env['CLAUDE_CODE_OAUTH_TOKEN'] || env['ANTHROPIC_API_KEY']) {
    providers.push('claude');
  }
  if (env['OPENAI_API_KEY']) {
    providers.push('openai');
  }
  if (providers.length === 0) {
    throw new Error('set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY for Claude models, or OPENAI_API_KEY for OpenAI models');
  }
  return {
    adminURL: url,
    token,
    concurrency: int('AUTOPILOT_CONCURRENCY', env['AUTOPILOT_CONCURRENCY'], 1, 1, 4),
    caseTimeoutMs: duration('AUTOPILOT_CASE_TIMEOUT', env['AUTOPILOT_CASE_TIMEOUT'], 600_000, 1000, 3_600_000),
    maxTurns: int('AUTOPILOT_MAX_TURNS', env['AUTOPILOT_MAX_TURNS'], 30, 1, 100),
    providers,
    runner: hostname(),
    version,
    sdkVersion,
  };
}
