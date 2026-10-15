// Types mirror the admin API (internal/admin). Configs are passed through
// as JSON; the server validates every save.

export type Phase = 'config' | 'rate_limit' | 'request_headers';

export interface FieldDef {
  name: string;
  label: string;
  type: string;
  keyed: boolean;
  phases: Phase[];
  available: boolean;
}

export interface OpDef {
  name: string;
  label: string;
  list: boolean;
  no_value: boolean;
  types: string[];
}

export interface Schema {
  fields: FieldDef[];
  operators: OpDef[];
}

export interface Issue {
  path: string;
  message: string;
}

export interface Rendered {
  text: string;
  length: number;
  errors: Issue[];
  warnings: Issue[];
}

export interface Me {
  username: string;
  permissions: string[];
}

// Json is a value the server defines and validates; the UI passes it
// through and narrows it only where it reads a field.
export type Json = unknown;

export type JsonObject = Record<string, Json>;

// Rule names the fields the rule list summarizes; the rest pass through.
export interface Rule {
  id: string;
  expression: Json;
  action?: string;
  limit?: number;
  period?: string;
  key?: string[];
  ops?: Json[];
  settings?: JsonObject;
  [k: string]: Json;
}

export interface Config {
  schema: number;
  version: number;
  kill_switch: { rate_limit: boolean; auth: boolean };
  global: JsonObject & { defaults: JsonObject };
  auth: { issuers: Json[]; default_accepted: string[] | null };
  config_rules: Rule[] | null;
  rate_limit_rules: Rule[] | null;
  request_header_rules: Rule[] | null;
}

export interface TestResult {
  name: string;
  pass: boolean;
  failures?: string[];
}

export interface Draft {
  config: Config;
  tests: Json[] | null;
  base_version: number | null;
  revision: number;
  updated_by: string;
  updated_at: string;
}

export interface Saved {
  revision: number;
  warnings: Issue[];
  test_results: TestResult[] | null;
}

export interface Version {
  version: number;
  author: string;
  published_at: string;
  message: string;
  source: string;
  based_on: number | null;
  status: string;
  change_summary: string;
  override_reason: string | null;
  guard_outcome: { at: string; decision: string; signals?: Record<string, Json> } | null;
  guard_override_reason?: string | null;
}

export interface VersionDetail extends Version {
  config: Config;
  tests: Json[] | null;
  test_results: TestResult[] | null;
}

export interface FieldChange {
  path: string;
  before: Json;
  after: Json;
}

export interface Diff {
  sections: FieldChange[] | null;
  phases: Record<string, { added: string[] | null; removed: string[] | null; changed: { id: string; fields: FieldChange[] }[] | null; reordered: boolean }>;
}

// Problem is an RFC 9457 error from the API.
export class Problem extends Error {
  constructor(
    public status: number,
    public title: string,
    public detail?: string,
    public errors: Issue[] = [],
    public testResults: TestResult[] = [],
  ) {
    super(detail || title);
  }
}

export async function api<T = unknown>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? headers : { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? null : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = (await res.json().catch(() => ({}))) as Partial<{ title: string; detail: string; errors: Issue[]; test_results: TestResult[] }>;
  if (!res.ok) throw new Problem(res.status, data.title ?? res.statusText, data.detail, data.errors ?? [], data.test_results ?? []);
  return data as T;
}

export const etag = (revision: number) => `"${revision}"`;
