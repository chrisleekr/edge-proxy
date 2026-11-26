import AxeBuilder from '@axe-core/playwright';
import { expect, type Page, type Request, test } from '@playwright/test';
import type { VersionDetail } from '../src/api';

// One admin through the critical flows, in order: sign in, publish the
// starter draft unchanged, build a rule with And/Or, switch to text and
// back, save, publish through a canary, compare versions, revert, and read
// the audit log.
test.describe.configure({ mode: 'serial' });

const user = process.env.SMOKE_USER!;
const password = process.env.SMOKE_PASSWORD!;
const oncall = process.env.SMOKE_ONCALL_USER!;
const viewer = process.env.SMOKE_VIEWER_USER!;

let page: Page;
test.beforeAll(async ({ browser }) => {
  // An explicit context: axe refuses a page that owns its own context.
  page = await (await browser.newContext()).newPage();
});

const nav = (name: string) => page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name, exact: true }).click();

// Actions that change what production serves ask first in a dialog.
// A tab bar is a navigation of its own, named for its page.
const tab = (bar: string, name: string) => page.getByRole('navigation', { name: bar, exact: true }).getByRole('link', { name, exact: true }).click();

const confirm = (action: string) => page.getByRole('dialog').getByRole('button', { name: action, exact: true }).click();

// liveMap is the war room map's Live request: its last 5 full minutes, without a country.
const liveMap = (u: URL) => u.pathname === '/api/traffic' && !u.searchParams.has('country') && Date.parse(u.searchParams.get('to') ?? '') - Date.parse(u.searchParams.get('from') ?? '') === 300_000;

async function saveDraft(revision: number) {
  await page.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByRole('status').filter({ hasText: `Saved revision ${revision}` })).toBeVisible();
}

async function publish(message: string, version: number, canary?: string) {
  await nav('Publish');
  await page.getByLabel('Message').fill(message);
  if (canary) await page.getByLabel('Canary percent').fill(canary);
  await page.getByRole('button', { name: canary ? `Publish to ${canary}% of traffic` : 'Publish to all traffic', exact: true }).click();
  await confirm('Publish');
  await expect(page.getByRole('status').filter({ hasText: `Published version ${version}.` })).toBeVisible();
}

test('a wrong password is refused and the right one signs in', async () => {
  await page.goto('/');
  await page.getByLabel('Username').fill(user);
  await page.getByLabel('Password').fill('not the password at all');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert')).toContainText(/wrong username or password/i);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await nav('Rules');
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible();
});

test('a fresh install publishes its starter draft without editing anything', async () => {
  await expect(page.getByText('The starter draft is not saved yet.')).toBeVisible();
  await saveDraft(1);
  await publish('Starter policy', 1);
  await nav('Versions');
  await expect(page.getByRole('row', { name: /Starter policy/ })).toContainText('live');
});

test('a rule built with And and Or survives a trip through text', async () => {
  await nav('Rules');
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rate limit rule' }).click();
  await page.getByLabel('Rule ID').fill('login');

  const root = page.locator('.ruleGroup').first();
  await root.locator('.ruleGroup-addRule').first().click();
  const first = page.locator('.rule').nth(0);
  await first.locator('.rule-fields').selectOption('http.request.uri.path');
  await first.getByLabel('Value').fill('/login');
  await root.locator('.ruleGroup-addGroup').first().click();
  const inner = page.locator('.ruleGroup .ruleGroup');
  await inner.locator('.ruleGroup-combinators').selectOption('or');
  await inner.locator('.ruleGroup-addRule').click();
  await inner.locator('.ruleGroup-addRule').click();
  await inner.locator('.rule').nth(0).locator('.rule-fields').selectOption('http.request.method');
  await inner.locator('.rule').nth(0).getByLabel('Value').fill('POST');
  await inner.locator('.rule').nth(1).locator('.rule-fields').selectOption('http.request.method');
  await inner.locator('.rule').nth(1).getByLabel('Value').fill('PUT');

  // Switch before the preview catches up: the text must still hold the
  // last edit.
  await page.getByRole('button', { name: 'Edit expression' }).click();
  await expect(page.getByLabel('Expression', { exact: true })).toContainText('PUT');
  const preview = page.getByTestId('preview-text');
  await expect(preview).toContainText('/login');
  await expect(preview).toContainText('PUT');
  const text = await preview.textContent();

  await page.getByRole('button', { name: 'Use builder' }).click();
  await expect(page.locator('.ruleGroup .ruleGroup .rule')).toHaveCount(2);
  await expect(preview).toHaveText(text!);

  await page.getByRole('button', { name: 'Apply to draft' }).click();
  await expect(page.getByRole('link', { name: 'login', exact: true })).toBeVisible();
  await saveDraft(3); // publishing bumped the draft to revision 2
});

test('a new rule published to all traffic goes live', async () => {
  await publish('Add login limit', 2);
  await nav('Versions');
  await expect(page.getByRole('row', { name: /Add login limit/ })).toContainText('live');
});

test('invalid JSON stays on screen and blocks saving until discarded', async () => {
  await nav('Settings');
  await page.getByText('Disable rate limiting').click();
  await page.getByRole('button', { name: 'Edit Defaults as JSON' }).click();
  await page.getByLabel('Defaults', { exact: true }).click();
  await page.keyboard.press('ControlOrMeta+End');
  await page.keyboard.type('x');
  await expect(page.getByRole('alert').filter({ hasText: 'Not valid JSON' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save draft' })).toBeDisabled();
  await page.getByRole('button', { name: 'Discard' }).click();
  await confirm('Discard changes');
  await expect(page.getByRole('alert').filter({ hasText: 'Not valid JSON' })).toBeHidden();
  await expect(page.getByLabel('Disable rate limiting')).not.toBeChecked();
});

test('the guard form saves a percent as a ratio', async () => {
  const edgeFloor = () =>
    page.getByRole('listitem').filter({ has: page.getByText('Edge 5xx', { exact: true }) }).getByLabel('Never below');
  const saveGuard = async () => {
    await page.getByRole('button', { name: 'Save guard settings' }).click();
    await confirm('Save guard settings');
    await expect(page.getByRole('status').filter({ hasText: 'Guard settings saved.' })).toBeVisible();
  };
  await nav('Settings');
  await edgeFloor().fill('2');
  await saveGuard();
  await page.reload();
  await page.getByRole('button', { name: 'Edit as JSON' }).click();
  await expect(page.getByLabel('Guard settings', { exact: true })).toContainText(/"edge_5xx_ratio": \{[^}]*"floor": 0\.02/);
  // Put the default 1% back so later tests see the default guard.
  await page.getByRole('button', { name: 'Use the form' }).click();
  await edgeFloor().fill('1');
  await saveGuard();
});

test('a rule gets its own notification setting, which outlives a reload', async () => {
  const saveNotifications = async () => {
    await page.getByRole('button', { name: 'Save notification settings' }).click();
    await confirm('Save notification settings');
    await expect(page.getByRole('status').filter({ hasText: 'Notification settings saved.' })).toBeVisible();
  };
  await nav('Notifications');
  await expect(page.getByRole('heading', { name: 'Notifications', exact: true })).toBeVisible();
  await tab('Notifications', 'Settings');
  await expect(page.getByText('No rule has its own settings')).toBeVisible();
  await page.getByRole('combobox', { name: 'Rule', exact: true }).selectOption('login');
  // Only signals that apply to a rate limit rule are offered.
  const signal = page.getByRole('combobox', { name: 'Signal', exact: true });
  await expect(signal.getByRole('option', { name: 'Upstream 5xx on a rule' })).toHaveCount(0);
  await signal.selectOption({ label: 'Log-only rule logged requests' });
  await page.getByRole('button', { name: 'Give this rule its own setting' }).click();
  const own = page.getByRole('listitem').filter({ hasText: 'Log-only rule logged requests for rule login' });
  await own.getByRole('combobox', { name: 'Log-only rule logged requests, Severity' }).selectOption('critical');
  await saveNotifications();
  await page.reload();
  await expect(page.getByRole('listitem').filter({ hasText: 'Log-only rule logged requests for rule login' }).getByRole('combobox', { name: 'Log-only rule logged requests, Severity' })).toHaveValue('critical');
  // Back to the defaults, so later tests see none.
  await page.getByRole('button', { name: 'Use the default' }).click();
  await saveNotifications();
  await expect(page.getByText('No rule has its own settings')).toBeVisible();
});

test('going back two entries from one rule editor shows the other rule', async () => {
  await nav('Rules');
  await page.getByRole('link', { name: 'login', exact: true }).click();
  await expect(page.getByLabel('Rule ID')).toHaveValue('login');
  await page.getByRole('button', { name: 'Cancel' }).click();
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rate limit rule' }).click();
  await expect(page.getByLabel('Rule ID')).toHaveValue('');
  await page.evaluate(() => history.go(-2));
  await expect(page.getByRole('heading', { name: 'Edit login' })).toBeVisible();
  await expect(page.getByLabel('Rule ID')).toHaveValue('login');
  await page.getByRole('button', { name: 'Cancel' }).click();
});

test('a new rule cannot take an ID another phase already uses', async () => {
  const config = page.getByRole('list', { name: 'Access rules' }).locator('..');
  await config.getByRole('button', { name: 'Add access rule' }).click();
  await page.getByLabel('Rule ID').fill('login');
  await expect(page.getByText('Rate limit rules already has a rule called “login”')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply to draft' })).toBeDisabled();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible();
});

test('each mistake in a rate limit shows by its field and keeps Apply off until fixed', async () => {
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rate limit rule' }).click();
  await page.getByLabel('Rule ID').fill('search');
  const apply = page.getByRole('button', { name: 'Apply to draft' });

  await page.getByLabel('Limit', { exact: true }).fill('');
  await expect(page.getByRole('alert').filter({ hasText: 'must be 1 to' }).first()).toBeVisible();
  await expect(apply).toBeDisabled();
  await page.getByLabel('Limit', { exact: true }).fill('10');

  // A header alone is a value clients choose, so it needs a partner.
  await page.getByLabel('Count by, part 1').selectOption('header');
  await expect(page.getByRole('alert').filter({ hasText: 'header needs a valid name' }).first()).toBeVisible();
  await page.getByLabel('Request header name, part 1').fill('x-api-key');
  await expect(page.getByRole('alert').filter({ hasText: 'add ip or jwt_claim' }).first()).toBeVisible();
  await expect(apply).toBeDisabled();
  await page.getByRole('button', { name: '+ Add a part' }).click();

  await apply.click();
  await expect(page.getByRole('link', { name: 'search', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Discard' }).click();
  await confirm('Discard changes');
});

test('switching a rate limit to Distinct drops the statuses it can not count', async () => {
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rate limit rule' }).click();
  await page.getByRole('button', { name: '+ Add a status' }).click();
  await page.getByRole('textbox', { name: 'Status 1', exact: true }).fill('404');
  const algorithm = page.getByRole('combobox', { name: /^Algorithm/ });
  const was = await algorithm.inputValue();
  await algorithm.selectOption('distinct');
  await expect(page.getByRole('textbox', { name: 'Status 1', exact: true })).toBeHidden();
  // Back to the first algorithm: the hidden statuses were dropped, not kept.
  await algorithm.selectOption(was);
  await expect(page.getByRole('group', { name: 'Count only responses with status' })).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Status 1', exact: true })).toBeHidden();
  // Nothing is left to lose, so Cancel asks nothing.
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible();
});

test('a penalty typed in seconds stays in seconds as it passes a whole minute', async () => {
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rate limit rule' }).click();
  const penalty = page.locator('label').filter({ has: page.getByText('Penalty', { exact: true }) });
  await penalty.getByLabel('Unit').selectOption('s');
  await penalty.getByRole('spinbutton').pressSequentially('605');
  await expect(penalty.getByRole('spinbutton')).toHaveValue('605');
  await expect(penalty.getByLabel('Unit')).toHaveValue('s');
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible();
});

test('a CORS policy explains each typical mistake by its field and keeps Save off until fixed', async () => {
  await nav('CORS policies');
  await page.getByLabel('New policy name').fill('web');
  await page.getByRole('button', { name: 'Add policy' }).click();
  const save = page.getByRole('button', { name: 'Save draft' });
  const origin = page.getByLabel('Allowed site 1', { exact: true });

  // A pasted URL keeps its capitals and trailing slash; browsers send neither.
  await origin.fill('https://App.example.com/');
  await expect(page.getByRole('alert').filter({ hasText: 'must be an origin such as' }).first()).toBeVisible();
  await expect(save).toBeDisabled();
  await origin.fill('https://App.example.com');
  await expect(page.getByRole('alert').filter({ hasText: 'must be lowercase' }).first()).toBeVisible();
  await origin.fill('https://app.example.com');
  await expect(save).toBeEnabled();

  // Any site plus cookies is refused by browsers, so the server refuses it too.
  await page.getByLabel('Let browsers send cookies and Authorization').check();
  await page.getByRole('button', { name: '+ Add a site' }).click();
  await page.getByLabel('Allowed site 2', { exact: true }).fill('*');
  await expect(page.getByRole('alert').filter({ hasText: "can't be used with credentials" }).first()).toBeVisible();
  await expect(save).toBeDisabled();
  await page.getByRole('button', { name: 'Remove site 2' }).click();
  await expect(save).toBeEnabled();

  await page.getByRole('button', { name: 'Discard' }).click();
  await confirm('Discard changes');
});

test('a trusted client allowlist shows each mistake by its entry and keeps Save off until fixed', async () => {
  await nav('Settings');
  await expect(page.getByText('Routes that require a JWT let these clients in without one.')).toBeVisible();
  await expect(page.getByText('No trusted clients: every request goes through the full policy.')).toBeVisible();
  const save = page.getByRole('button', { name: 'Save draft' });
  await page.getByRole('button', { name: '+ Add a client' }).click();
  const first = page.getByLabel('Trusted client 1', { exact: true });

  // Host bits set: the server says which range was meant.
  await first.fill('203.0.113.7/24');
  await expect(page.getByRole('alert').filter({ hasText: 'write 203.0.113.0/24 for the whole range' }).first()).toBeVisible();
  await expect(save).toBeDisabled();
  await first.fill('203.0.113.0/24');
  await expect(save).toBeEnabled();

  // A second entry inside the first is refused beside the second entry.
  await page.getByRole('button', { name: '+ Add a client' }).click();
  await page.getByLabel('Trusted client 2', { exact: true }).fill('203.0.113.7');
  await expect(page.getByRole('alert').filter({ hasText: 'keep only one of them' }).first()).toBeVisible();
  await expect(save).toBeDisabled();
  await page.getByRole('button', { name: 'Remove client 2' }).click();
  await expect(save).toBeEnabled();

  await page.getByRole('button', { name: 'Discard' }).click();
  await confirm('Discard changes');
});

test('the rule list finds one rule by its ID or what it matches', async () => {
  await nav('Rules');
  const search = page.getByLabel('Find a rule');
  await search.fill('/login');
  await expect(page.getByRole('link', { name: 'login', exact: true })).toBeVisible();
  await search.fill('no such rule');
  await expect(page.getByRole('link', { name: 'login', exact: true })).toBeHidden();
  await expect(page.getByText('No rule matches “no such rule”.').first()).toBeVisible();
  await search.fill('');
});

test('a canary cannot be stepped up or promoted before its wait, and can be aborted', async () => {
  await nav('Settings');
  await page.getByText('Disable rate limiting').click();
  await saveDraft(5);
  await publish('Kill switch drill', 3, '10');
  await expect(page.getByText('Canary: version 3 on 10% of traffic')).toBeVisible();
  await page.getByLabel('Next percent').fill('50');
  // The step has not run the guard's minimum time, so neither is offered.
  await expect(page.getByText(/step up or promote once this step has run until/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Step up' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Promote to all traffic' })).toBeDisabled();
  await page.getByLabel('Abort reason').fill('drill finished');
  await page.route('**/api/canary/abort', (r) => r.abort());
  await page.getByRole('button', { name: 'Abort', exact: true }).click();
  await confirm('Abort canary');
  await expect(page.getByRole('alert')).toBeVisible();
  await page.unroute('**/api/canary/abort');
  await page.getByRole('button', { name: 'Abort', exact: true }).click();
  await confirm('Abort canary');
  await expect(page.getByText('Canary: version 3')).toBeHidden();
  await nav('Versions');
  await expect(page.getByRole('row', { name: /Kill switch drill/ })).toContainText('rolled back');
});

test('versions compare by rule and setting, and revert makes a new version', async () => {
  await page.goto('/versions/compare?a=2&b=3');
  await expect(page.getByTestId('diff')).toContainText('Kill switch: disable rate limiting');

  await page.goto('/versions/3');
  await page.getByLabel('Reason', { exact: true }).fill('bring the drill back');
  await page.getByRole('button', { name: 'Revert to version 3' }).click();
  await confirm('Revert now');
  await expect(page.getByRole('heading', { name: 'Version 4' })).toBeVisible();
  await expect(page.getByText('revert of version 3')).toBeVisible();
});

test('revert to previous puts the earlier version back in one step', async () => {
  await nav('Versions');
  await page.getByLabel('Reason', { exact: true }).fill('emergency drill');
  await page.getByRole('button', { name: 'Revert to previous (version 2)' }).click();
  await confirm('Revert now');
  await expect(page.getByRole('heading', { name: 'Version 5' })).toBeVisible();
  await expect(page.getByText('revert of version 2')).toBeVisible();
});

test('an admin adds a user with roles the server offers', async () => {
  await nav('Users and tokens');
  await page.getByLabel('Username').fill('vera');
  await page.getByLabel('Initial password').fill('plum orchard lantern seventeen');
  await page.getByRole('group', { name: 'Roles', exact: true }).getByLabel('viewer').uncheck();
  await page.getByRole('group', { name: 'Roles', exact: true }).getByLabel('editor').check();
  await page.getByRole('button', { name: 'Add user' }).click();
  await expect(page.getByRole('group', { name: 'Roles of vera' }).getByLabel('editor')).toBeChecked();
});

test('a simulated request becomes a test, and saving it leaves nothing unsaved', async () => {
  await nav('Tests and simulate');
  await page.getByRole('button', { name: 'Simulate', exact: true }).click();
  await page.getByRole('button', { name: 'Add as a test' }).click();
  await page.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByRole('status').filter({ hasText: /Saved revision \d+/ })).toBeVisible();
  // The editor on screen must not report the refetched draft as a new edit.
  await expect(page.getByText('Unsaved changes to the draft.')).toBeHidden();
  await expect(page.getByLabel('Tests', { exact: true })).toContainText('"GET /"');
});

test('routes from access logs are found, explained, grouped and deleted', async () => {
  await nav('Routes');
  const rows = page.locator('tbody tr');
  await page.getByLabel('Search').fill('login');
  await expect(rows).toHaveCount(1);
  await page.getByLabel('Search').fill('');
  await page.getByRole('group', { name: 'Show only' }).getByRole('button', { name: 'Rate limited' }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('/login');

  await rows.first().getByRole('link').click();
  await expect(page.getByText('Shown for a request like POST api.example.com/login')).toBeVisible();
  // The Block step must say so when no access rule blocks the sample, and the flow goes on.
  const blockStep = page.getByRole('listitem').filter({ has: page.getByRole('heading', { name: 'Block', exact: true }) });
  await expect(blockStep).toContainText('Not blocked: no access rule that matches the sample sets block.');
  await expect(page.getByRole('heading', { name: 'Upstream', exact: true })).toBeVisible();
  await expect(page.getByText('Logged: 2 requests (20%) were blocked by a rate limit.')).toBeVisible();
  await page.getByRole('button', { name: 'Add rule for this route' }).click();
  await page.getByRole('dialog').getByRole('button', { name: /^Rate limit rule/ }).click();
  await expect(page.getByText(/Started from a route/)).toContainText('http.request.uri.path eq "/login"');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();

  await nav('Routes');
  await page.getByRole('button', { name: 'Group as one route' }).click();
  const blog = rows.filter({ hasText: '/blog/{*}' });
  await expect(blog).toHaveCount(1);
  await expect(rows.filter({ hasText: '/blog/post-a' })).toHaveCount(0);
  await blog.getByRole('link').click();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await confirm('Delete route');
  await expect(page.getByRole('heading', { name: 'Routes', exact: true })).toBeVisible();
  await expect(blog).toHaveCount(0);
});

test('a route the upstream refused links its 502 and the cause to the log store, and an anomaly without a host has no link', async () => {
  await nav('Routes');
  await page.locator('tbody tr').filter({ hasText: '/orders/{id}' }).getByRole('link').click();
  // LOG_SEARCH_URL is https://logs.example.com/search?q=status%3A{status}%20host%3A{host}&from={from}&to={to}.
  const search = /^https:\/\/logs\.example\.com\/search\?q=status%3A502%20host%3Aapi\.example\.com&from=\d{4}-\d\d-\d\dT\d\d%3A\d\d%3A\d\d\.\d{3}Z&to=\d{4}-/;
  const code = page.getByRole('link', { name: '502', exact: true });
  await expect(code).toHaveAttribute('href', search);
  await expect(code).toHaveAttribute('target', '_blank');
  await expect(page.getByRole('link', { name: 'Nothing accepted the connection' })).toHaveAttribute('href', search);

  await nav('Notifications');
  await expect(page.getByRole('row').filter({ hasText: '5xx the edge sent' })).toHaveCount(1);
  await expect(page.getByRole('link', { name: 'Search the logs' })).toHaveCount(0);
});

test('the audit log lists the changes and its chain verifies', async () => {
  await nav('Audit log');
  await expect(page.getByRole('cell', { name: 'config.publish' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'canary.abort' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'route_pattern.create' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'route.delete' })).toBeVisible();
  await page.getByText('Before and after').first().click();
  await expect(page.getByTestId('diff').first()).toBeVisible();
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'No tampering found' })).toContainText('are intact');
  await page.reload();
  await expect(page.getByRole('status', { name: 'Audit integrity' })).toContainText('intact to event');
});

test('on a phone the menu is a drawer that closes after a link and on Escape', async () => {
  const size = page.viewportSize()!;
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto('/');
  // The sidebar is gone at this width; only the drawer holds the nav.
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeHidden();
  await page.getByRole('button', { name: 'Menu' }).click();
  const drawer = page.getByRole('dialog', { name: 'Menu' });
  await drawer.getByRole('link', { name: 'Audit log', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Audit log', exact: true })).toBeVisible();
  await expect(drawer).toBeHidden();
  await page.getByRole('button', { name: 'Menu' }).click();
  await expect(drawer).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  await page.setViewportSize(size);
});

test('on a narrow window the draft bar stays below the top bar, so Save draft works after scrolling', async () => {
  const size = page.viewportSize()!;
  // Wide enough that Save draft shares the bar's first line, narrow enough
  // for the top bar instead of the sidebar.
  await page.setViewportSize({ width: 600, height: 800 });
  await page.goto('/settings');
  const field = page.getByLabel('Maximum requests in progress per edge');
  const save = async () => {
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    // A tap where the button shows, as a person would. locator.click()
    // would scroll the button clear of anything covering it first.
    const button = page.getByRole('button', { name: 'Save draft' });
    await expect(button).toBeEnabled();
    const b = (await button.boundingBox())!;
    await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2);
    await expect(page.getByRole('status').filter({ hasText: /Saved revision \d+/ })).toBeVisible();
    await expect(page.getByText('Unsaved changes to the draft.')).toBeHidden();
  };
  await field.fill('500');
  await save();
  await field.fill('');
  await save();
  await page.setViewportSize(size);
});

test('on a phone with unsaved changes a jump link lands on its card clear of the draft bar', async () => {
  const size = page.viewportSize()!;
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto('/settings');
  await page.getByLabel('Maximum requests in progress per edge').fill('500');
  const bar = page.locator('div.sticky', { hasText: 'Unsaved changes to the draft.' });
  await expect(bar).toBeVisible();
  await page.getByRole('link', { name: 'Trusted client allowlist' }).click();
  const heading = page.locator('#trusted-clients').getByRole('heading', { name: 'Trusted client allowlist' });
  // Below the fold until the jump lands, so wait for that before comparing.
  await expect.poll(async () => (await heading.boundingBox())!.y).toBeLessThan(400);
  const b = (await bar.boundingBox())!;
  expect((await heading.boundingBox())!.y).toBeGreaterThanOrEqual(b.y + b.height);
  await page.getByRole('button', { name: 'Discard' }).click();
  await page.getByRole('button', { name: 'Discard changes' }).click();
  await page.setViewportSize(size);
});

test('an access rule set to block saves, and the block kill switch saves with it', async () => {
  await nav('Rules');
  const config = page.getByRole('list', { name: 'Access rules' }).locator('..');
  await config.getByRole('button', { name: 'Add access rule' }).click();
  await page.getByLabel('Rule ID').fill('block-tools');
  await page.getByLabel(/^Action/).selectOption('block');
  await page.getByRole('button', { name: 'Apply to draft' }).click();
  const rule = page.getByRole('listitem').filter({ has: page.getByRole('link', { name: 'block-tools', exact: true }) });
  await expect(rule).toContainText('blocks with 403');

  await nav('Settings');
  await page.getByText('Disable blocking by access rules').click();
  await page.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByRole('status').filter({ hasText: /Saved revision \d+/ })).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Disable blocking by access rules')).toBeChecked();
  await nav('Rules');
  await expect(page.getByRole('listitem').filter({ has: page.getByRole('link', { name: 'block-tools', exact: true }) })).toContainText('blocks with 403');
});

test('a route flow names the access rule that blocks or only logs for its sample, and a block ends the flow there', async () => {
  const flow = async () => {
    await nav('Routes');
    await page.locator('tbody tr').filter({ hasText: '/login' }).getByRole('link').click();
    await page.getByRole('group', { name: 'Policy to show' }).getByRole('button', { name: 'Saved draft' }).click();
  };
  const blockStep = page.getByRole('listitem').filter({ has: page.getByRole('heading', { name: 'Block', exact: true }) });
  // Flipping the kill switch in the draft is the only way to see both outcomes of one rule.
  const killSwitch = async () => {
    await nav('Settings');
    await page.getByText('Disable blocking by access rules').click();
    await page.getByRole('button', { name: 'Save draft' }).click();
    await expect(page.getByRole('status').filter({ hasText: /Saved revision \d+/ })).toBeVisible();
  };
  // The previous test left block-tools (matches every request) in the draft with the kill switch on.
  await flow();
  await expect(blockStep).toContainText('Access rule block-tools only logs: the request goes on to the next steps.');
  await expect(blockStep).toContainText(/3 requests \(.+\) were logged instead of blocked by block-tools/);
  const accessStep = page.getByRole('listitem').filter({ has: page.getByRole('heading', { name: 'Access rules choose the settings', exact: true }) });
  await expect(accessStep).toContainText('3 requests logged instead of blocked');
  await expect(blockStep.getByRole('link', { name: 'block-tools', exact: true })).toHaveAttribute('href', '/rules/config/block-tools');
  await expect(page.getByRole('heading', { name: 'Upstream', exact: true })).toBeVisible();
  await killSwitch(); // off
  await flow();
  await expect(blockStep).toContainText('Access rule block-tools answers this request with 403.');
  await expect(blockStep.getByRole('link', { name: 'block-tools', exact: true })).toHaveAttribute('href', '/rules/config/block-tools');
  await expect(page.getByText('This sample request stops here: Blocked by an access rule.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Backstop', exact: true })).toHaveCount(0);
  await killSwitch(); // back on, as the previous test left it
});

test('a time range picked on Stats holds on Routes, after going back, and after a reload', async () => {
  const range = () => page.getByRole('combobox', { name: 'Time range' });
  await nav('Stats');
  await range().selectOption('7d');
  await expect(page).toHaveURL(/\/stats\?range=7d$/);
  await nav('Routes');
  await expect(page).toHaveURL(/\/routes\?range=7d$/);
  await expect(range()).toHaveValue('7d');
  await page.goBack();
  await expect(page).toHaveURL(/\/stats\?range=7d$/);
  await expect(range()).toHaveValue('7d');
  await page.reload();
  await expect(range()).toHaveValue('7d');
});

test('Needs attention lists the firing anomaly with one action', async () => {
  await page.goto('/');
  const item = page.getByRole('region', { name: 'Needs attention' }).getByRole('listitem').filter({ hasText: '5xx the edge sent' });
  await expect(item).toHaveCount(1);
  await expect(item.getByRole('link')).toHaveCount(1);
  await expect(item.getByRole('link')).toHaveAttribute('href', /^\/notifications(\?|$)/);
});

test('a role that reads stats but not config sees Notifications without asking for its settings', async ({ browser }) => {
  const other = await (await browser.newContext()).newPage();
  const asked: string[] = [];
  other.on('request', (r) => r.url().includes('/api/settings/notifications') && asked.push(r.url()));
  await other.goto('/');
  await other.getByLabel('Username').fill(oncall);
  await other.getByLabel('Password').fill(password);
  await other.getByRole('button', { name: 'Sign in' }).click();
  await other.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Notifications', exact: true }).click();
  await expect(other.getByRole('cell').filter({ hasText: 'Edge 5xx' }).first()).toBeVisible();
  await other.waitForLoadState('networkidle');
  expect(asked).toEqual([]);
  await expect(other.getByText('Forbidden')).toHaveCount(0);
  await other.context().close();
});

test('a role that reads stats reaches the war room, which shows Live then Period and holds the flows still when motion is reduced', async ({ browser }) => {
  const other = await (await browser.newContext()).newPage();
  await other.goto('/');
  await other.getByLabel('Username').fill(oncall);
  await other.getByLabel('Password').fill(password);
  await other.getByRole('button', { name: 'Sign in' }).click();
  await other.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'War room', exact: true }).click();
  await expect(other.getByRole('heading', { level: 1, name: 'War room' })).toBeVisible();
  await expect(other.getByRole('button', { name: 'Live', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(other.getByText('NOT LIVE')).toHaveCount(0);
  // The seeded lines are real; the live window is only 5 minutes, so it is mocked below.
  await other.getByRole('button', { name: 'Period', exact: true }).click();
  await expect(other).toHaveURL(/view=period/);
  await expect(other.getByRole('button', { name: 'Period', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(other.getByText('NOT LIVE')).toBeVisible();
  await expect(other.getByRole('button', { name: 'Back to live' }).first()).toBeVisible();
  await expect(other.getByRole('region', { name: 'Where requests come from' }).getByRole('heading', { name: /^Where requests came from, .*\d\d:\d\d to .*\d\d:\d\d UTC$/ })).toBeVisible();
  await expect(other.getByRole('cell', { name: 'United States' })).toBeVisible();
  await expect(other.getByRole('cell', { name: 'Country not known' })).toBeVisible();
  // Read-only: the form to move the edges is on Settings, for roles that manage them.
  await expect(other.getByRole('heading', { name: 'Where the edges are' })).toHaveCount(0);
  // This role has stats.read only: the config, audit and autopilot parts are left out.
  await expect(other.getByRole('region', { name: 'Recent changes' })).toHaveCount(0);
  await expect(other.getByText('Kill switches')).toHaveCount(0);
  await expect(other.getByRole('button', { name: 'Ask autopilot' })).toHaveCount(0);

  const now = Date.now();
  await other.route(liveMap, (r) =>
    r.fulfill({
      json: {
        from: new Date(now - 240_000).toISOString(),
        to: new Date(now).toISOString(),
        countries: [
          { country: 'DE', requests: 900, blocked: 0, estimated: 0 },
          { country: 'US', requests: 300, blocked: 12, estimated: 0 },
        ],
        edge: { lat: 50.11, long: 8.68, name: 'Frankfurt' },
      },
    }),
  );
  await other.getByRole('button', { name: 'Live', exact: true }).click();
  await expect(other.getByRole('button', { name: 'Live', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(other).not.toHaveURL(/view=period/);
  await expect(other.getByRole('region', { name: 'Where requests come from' }).getByRole('heading', { name: 'Requests flowing to the edges' })).toBeVisible();
  const flowAnimation = () => other.locator('.wr-flow').first().evaluate((el) => getComputedStyle(el).animationName);
  await expect.poll(flowAnimation).toBe('wr-flow');

  await other.emulateMedia({ reducedMotion: 'reduce' });
  await expect.poll(flowAnimation).toBe('none');
  await other.context().close();
});

test('war room flow lines start at a drawn mark and the Europe inset covers world lines under it', async ({ browser }) => {
  const other = await (await browser.newContext()).newPage();
  const countries = [
    { country: 'DE', requests: 900, blocked: 0, estimated: 0 },
    { country: 'GB', requests: 700, blocked: 0, estimated: 0 },
    { country: 'US', requests: 300, blocked: 12, estimated: 0 },
    { country: 'BR', requests: 200, blocked: 0, estimated: 0 },
    { country: 'CL', requests: 100, blocked: 0, estimated: 0 },
  ];
  let edge = { lat: -33.87, long: 151.21, name: 'Sydney' };
  await other.route(liveMap, (r) => r.fulfill({ json: { from: new Date(Date.now() - 300_000).toISOString(), to: new Date().toISOString(), countries, edge } }));
  await other.goto('/');
  await other.getByLabel('Username').fill(oncall);
  await other.getByLabel('Password').fill(password);
  await other.getByRole('button', { name: 'Sign in' }).click();
  await other.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'War room', exact: true }).click();
  const map = other.getByRole('region', { name: 'Where requests come from' });
  await expect(map.getByRole('heading', { name: 'Requests flowing to the edges' })).toBeVisible();
  await expect(map.getByText('Edges in Sydney')).toBeVisible();

  // Each line must begin at a circle, else a country shows a line out of bare land.
  const startsAtCircle = () =>
    map.locator('svg').evaluate((svg) => {
      const circles = [...svg.querySelectorAll('circle')].map((c): [number, number] => [c.cx.baseVal.value, c.cy.baseVal.value]);
      const flows = [...svg.querySelectorAll<SVGPathElement>('path.wr-flow')];
      return { flows: flows.length, bare: flows.filter((f) => {
        const p = f.getPointAtLength(0);
        return !circles.some(([x, y]) => Math.hypot(x - p.x, y - p.y) <= 1);
      }).length };
    });
  expect(await startsAtCircle()).toEqual({ flows: 5, bare: 0 });

  // The inset is painted over world lines, so no line shows at a point inside its box.
  const exposed = () =>
    map.locator('svg').evaluate((svg: SVGSVGElement) => {
      const box = svg.querySelector('rect')!;
      const [x0, y0, x1, y1] = [box.x.baseVal.value, box.y.baseVal.value, box.x.baseVal.value + box.width.baseVal.value, box.y.baseVal.value + box.height.baseVal.value];
      const m = svg.getScreenCTM()!;
      let inside = 0;
      let shown = 0;
      for (const f of svg.querySelectorAll<SVGPathElement>('path.wr-flow')) {
        for (let i = 0; i <= 200; i++) {
          const p = f.getPointAtLength((f.getTotalLength() * i) / 200);
          if (p.x <= x0 || p.x >= x1 || p.y <= y0 || p.y >= y1) continue;
          inside++;
          const s = new DOMPoint(p.x, p.y).matrixTransform(m);
          if (document.elementFromPoint(s.x, s.y)?.getAttribute('fill') === 'none') shown++;
        }
      }
      return { inside, shown };
    });
  // A line whose shortest route crosses the map's edge must be one piece that ends at the edge, not two cut pieces.
  const pieces = () =>
    map.locator('svg').evaluate((svg) => {
      const at = /translate\(([-\d.]+) ([-\d.]+)\) rotate\(45\)/.exec([...svg.querySelectorAll('rect')].map((r) => r.getAttribute('transform') ?? '').find((t) => t.includes('rotate(45)')) ?? '')!;
      return [...svg.querySelectorAll<SVGPathElement>('path.wr-flow')].map((f) => {
        const end = f.getPointAtLength(f.getTotalLength());
        return { moves: (f.getAttribute('d')!.match(/M/g) ?? []).length, atEdge: Math.hypot(end.x - Number(at[1]), end.y - Number(at[2])) <= 1 };
      });
    });
  expect(await pieces()).toEqual(Array(5).fill({ moves: 1, atEdge: true }));

  // Chile to Honolulu does not cross the map's edge, so it stays a great circle and passes under the inset.
  edge = { lat: 21.31, long: -157.86, name: 'Honolulu' };
  await other.reload();
  await expect(map.getByText('Edges in Honolulu')).toBeVisible();
  await map.locator('svg').scrollIntoViewIfNeeded();
  const seen = await exposed();
  expect(seen.inside).toBeGreaterThan(0);
  expect(seen.shown).toBe(0);

  edge = { lat: 50.11, long: 8.68, name: 'Frankfurt' };
  await other.reload();
  await expect(map.getByText('Edges in Frankfurt')).toBeVisible();
  expect(await startsAtCircle()).toEqual({ flows: 5, bare: 0 });
  await other.context().close();
});

test('the war room map explains no logs and no countries, marks estimates and unmapped countries, and expands and closes', async ({ browser }) => {
  const other = await (await browser.newContext()).newPage();
  let countries: { country: string; requests: number; blocked: number; estimated: number }[] = [];
  await other.route(liveMap, (r) => r.fulfill({ json: { from: new Date(Date.now() - 300_000).toISOString(), to: new Date().toISOString(), countries, edge: null } }));
  await other.goto('/');
  await other.getByLabel('Username').fill(oncall);
  await other.getByLabel('Password').fill(password);
  await other.getByRole('button', { name: 'Sign in' }).click();
  await other.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'War room', exact: true }).click();
  const map = other.getByRole('region', { name: 'Where requests come from' });
  await expect(map.getByText('No access logs in the last 5 minutes')).toBeVisible();

  countries = [{ country: 'unknown', requests: 40, blocked: 0, estimated: 0 }];
  await other.reload();
  await expect(map.getByText(/carries a country/)).toContainText('CLIENT_IP_SOURCE');

  countries = [
    { country: 'SG', requests: 20, blocked: 0, estimated: 20 },
    { country: '*', requests: 2, blocked: 0, estimated: 0 },
  ];
  await other.reload();
  await expect(map.getByRole('row').filter({ hasText: 'Singapore' }).getByText(/not on the map/)).toBeVisible();
  await expect(map.getByRole('cell', { name: 'Other countries' })).toBeVisible();
  await expect(map.getByRole('cell', { name: /^≈\s*4$/ })).toBeVisible();

  await map.getByRole('button', { name: 'Expand to fill the screen' }).click();
  await expect(map.getByRole('button', { name: 'Close, or press Esc' })).toBeVisible();
  await other.keyboard.press('Escape');
  await expect(map.getByRole('button', { name: 'Expand to fill the screen' })).toBeVisible();
  await other.context().close();
});

test('the mouse wheel zooms the war room map as soon as the page first loads', async () => {
  await page.goto('/traffic?view=period');
  const map = page.getByRole('region', { name: 'Where requests come from' });
  const zoomOut = map.getByRole('button', { name: 'Zoom out' });
  await expect(zoomOut).toBeDisabled();
  await map.getByRole('group', { name: 'Map, scroll to zoom' }).hover();
  await page.mouse.wheel(0, -400);
  await expect(zoomOut).toBeEnabled();
});

test('a settings manager places the edges on Settings, the war room map then draws the flows, and clearing removes them', async () => {
  const flows = page.locator('svg path[vector-effect="non-scaling-stroke"]');
  const hint = page.getByRole('link', { name: 'Set where the edges are in Settings to draw the flows.' });
  await page.goto('/traffic?view=period');
  await expect(page.getByRole('heading', { level: 1, name: 'War room' })).toBeVisible();
  await expect(hint).toBeVisible();
  await expect(flows).toHaveCount(0);

  await page.goto('/settings');
  const form = page.locator('form').filter({ has: page.getByLabel('Latitude') });
  await form.getByLabel('Latitude').fill('91');
  await form.getByLabel('Longitude').fill('8.68');
  await form.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(form.getByRole('alert')).toContainText(/latitude must be from -90 to 90/i);
  await form.getByLabel('Latitude').fill('50.11');
  await form.getByLabel('Place name').fill('Frankfurt');
  await form.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(form.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible();
  // The first place saved can be cleared without reloading the page.
  await expect(form.getByRole('button', { name: 'Clear', exact: true })).toBeEnabled();

  await page.goto('/traffic?view=period');
  await expect(page.getByText('Edges in Frankfurt')).toBeVisible();
  await expect(hint).toHaveCount(0);
  expect(await flows.count()).toBeGreaterThan(0);

  await page.goto('/settings');
  await form.getByRole('button', { name: 'Clear', exact: true }).click();
  await expect(form.getByLabel('Latitude')).toHaveValue('');
  await expect(form.getByRole('button', { name: 'Clear', exact: true })).toBeDisabled();
  await page.goto('/traffic?view=period');
  await expect(hint).toBeVisible();
  await expect(page.getByText('Edges in Frankfurt')).toHaveCount(0);
  await expect(flows).toHaveCount(0);
});

test('selecting a country in the war room shows its trend and links its access logs', async ({ browser }) => {
  const other = await (await browser.newContext()).newPage();
  await other.route('**/api/auth/me', async (r) => {
    const res = await r.fetch();
    const me = (await res.json()) as Record<string, unknown>;
    await r.fulfill({ response: res, json: { ...me, log_search_url: 'https://logs.example.com/search?q=country%3A{country}&from={from}&to={to}' } });
  });
  await other.goto('/');
  await other.getByLabel('Username').fill(oncall);
  await other.getByLabel('Password').fill(password);
  await other.getByRole('button', { name: 'Sign in' }).click();
  await expect(other.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await other.goto('/traffic?view=period');
  const map = other.getByRole('region', { name: 'Where requests come from' });
  await map.getByRole('button', { name: 'United States', exact: true }).click();
  await expect(map.getByRole('img', { name: /^Requests from United States/ })).toBeVisible();
  await expect(map.getByRole('link', { name: 'Search its access logs' })).toHaveAttribute('href', /q=country%3AUS&from=/);
  await other.context().close();
});

test('a firing critical anomaly is counted in the war room status and listed, with no Acknowledge for a role that cannot ack', async ({ browser }) => {
  const other = await (await browser.newContext()).newPage();
  // Mocked: the seed cannot make an anomaly fire.
  const at = new Date().toISOString();
  await other.route('**/api/anomalies', (r) =>
    r.fulfill({
      json: {
        alertmanager: false,
        anomalies: [
          { id: 904, signal: 'traffic_surge', rule: '', phase: '', severity: 'critical', state: 'firing', tripped: 2, passed: 0, started_at: at, fired_at: at, resolved_at: null, notified_at: null, summary: 'Requests surged to test the war room status', case_id: null },
        ],
      },
    }),
  );
  await other.goto('/');
  await other.getByLabel('Username').fill(oncall);
  await other.getByLabel('Password').fill(password);
  await other.getByRole('button', { name: 'Sign in' }).click();
  await expect(other.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await other.goto('/traffic');
  await expect(other.getByText(/1 ITEM NEEDS A PERSON/)).toBeVisible();
  const needs = other.getByRole('region', { name: 'Needs a person' });
  await expect(needs.locator('.wr-item')).toHaveCount(1);
  await needs.locator('.wr-item').click();
  // oncall reads stats but has no attention.ack.
  await expect(needs.getByRole('button', { name: 'Acknowledge' })).toHaveCount(0);
  await other.context().close();
});

test('dragging across the war room outcome chart picks a span, and Escape removes it', async () => {
  // Mocked: the seed serves no per-minute stats, and an empty chart has nothing to pick.
  const now = Math.floor(Date.now() / 60_000) * 60_000;
  const rows = Array.from({ length: 60 }, (_, i) => ({
    minute: new Date(now - (60 - i) * 60_000).toISOString(), version: 2, requests: 100, edge_5xx: 0, upstream_5xx: 0, auth_failures: 0,
    rate_limit_rules: [], top_limited: [], rules: [], status_codes: { upstream: { '200': 100 } }, upstream_errors: {},
  }));
  await page.route('**/api/stats?*', (r) => r.fulfill({ json: rows }));
  try {
    await page.goto('/traffic?view=period&range=1h');
    const plot = page.getByRole('region', { name: 'Requests by outcome' }).getByRole('img').first();
    await expect(plot).toHaveAccessibleName(/Average a minute: [1-9]\d* passed on/);
    // Locator hovers scroll the plot into view; raw coordinates below the fold miss it.
    await plot.scrollIntoViewIfNeeded();
    const box = (await plot.boundingBox())!;
    await plot.hover({ position: { x: box.width * 0.3, y: box.height / 2 } });
    await page.mouse.down();
    await plot.hover({ position: { x: box.width * 0.5, y: box.height / 2 } });
    await plot.hover({ position: { x: box.width * 0.7, y: box.height / 2 } });
    await page.mouse.up();
    const picked = page.getByLabel('Time range').locator('option', { hasText: /^Picked:/ });
    await expect(picked).toHaveCount(1);
    // The map names its window to the minute and routes to whole hours, so match the form, not the times.
    await expect(page.getByRole('region', { name: 'Where requests come from' }).getByRole('heading', { name: /^Where requests came from, .*\d\d:\d\d to .*\d\d:\d\d UTC$/ })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Routes hit hardest' }).getByRole('heading', { name: /^Routes hit hardest, .*\d\d:\d\d to .*\d\d:\d\d UTC$/ })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(picked).toHaveCount(0);
  } finally {
    await page.unroute('**/api/stats?*');
  }
});

test('the war room does not scroll sideways on a phone', async ({ browser }) => {
  const other = await (await browser.newContext({ viewport: { width: 375, height: 812 } })).newPage();
  await other.goto('/');
  await other.getByLabel('Username').fill(oncall);
  await other.getByLabel('Password').fill(password);
  await other.getByRole('button', { name: 'Sign in' }).click();
  // Navigating before sign-in answers would cancel it.
  await expect(other.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await other.goto('/traffic?view=period');
  await expect(other.getByRole('cell', { name: 'United States' })).toBeVisible();
  await other.waitForLoadState('networkidle');
  expect(await other.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await other.context().close();
});

test('an acknowledged item leaves the list for the acknowledged items, and undo brings it back', async () => {
  // Mocked: the seed cannot make an anomaly fire. The ack itself goes to the real admin.
  const at = new Date().toISOString();
  await page.route('**/api/anomalies', (r) =>
    r.fulfill({
      json: {
        alertmanager: false,
        anomalies: [
          { id: 903, signal: 'traffic_surge', rule: '', phase: '', severity: 'warning', state: 'firing', tripped: 2, passed: 0, started_at: at, fired_at: at, resolved_at: null, notified_at: null, summary: 'Requests surged to test acknowledging', case_id: null },
        ],
      },
    }),
  );
  try {
    await page.goto('/');
    const attention = page.getByRole('region', { name: 'Needs attention' });
    const firing = attention.getByRole('listitem').filter({ hasText: 'Requests surged to test acknowledging' });
    await firing.getByRole('button', { name: 'Acknowledge' }).click();
    const list = attention.getByRole('group').filter({ hasText: '1 acknowledged item' });
    await expect(list).toBeVisible();
    await expect(firing.getByRole('button', { name: 'Acknowledge' })).toHaveCount(0);
    await list.getByText('1 acknowledged item').click();
    await expect(list.getByText('Requests surged to test acknowledging')).toBeVisible();
    await list.getByRole('button', { name: 'Undo' }).click();
    await expect(firing.getByRole('button', { name: 'Acknowledge' })).toBeVisible();
    await expect(list).toHaveCount(0);
  } finally {
    await page.unroute('**/api/anomalies');
  }
});

// Adds, reads or removes acks through the page's own session, as the dashboard does.
const ackKeys = () => page.evaluate(async () => ((await (await fetch('/api/attention/acks')).json()) as { key: string }[]).map((a) => a.key));
const dropAck = (key: string) => page.evaluate((k) => fetch(`/api/attention/acks?key=${encodeURIComponent(k)}&reason=undo`, { method: 'DELETE' }).then(() => undefined), key);
const addAck = (key: string) =>
  page.evaluate(async (k) => {
    const r = await fetch('/api/attention/acks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: k, summary: k }) });
    if (!r.ok) throw new Error(`ack ${k}: ${r.status}`);
  }, key);
const anomaly = (id: number, signal: string, rule: string, phase: string, summary: string) => {
  const at = new Date().toISOString();
  return { id, signal, rule, phase, severity: 'critical', state: 'firing', tripped: 2, passed: 0, started_at: at, fired_at: at, resolved_at: null, notified_at: null, summary };
};
const surge = (id: number, state: 'firing' | 'resolved') => {
  const at = new Date().toISOString();
  return { alertmanager: false, anomalies: state === 'firing' ? [{ id, signal: 'traffic_surge', rule: '', phase: '', severity: 'warning', state, tripped: 2, passed: 0, started_at: at, fired_at: at, resolved_at: null, notified_at: null, summary: `Requests surged for ack ${id}`, case_id: null }] : [] };
};

test('an acknowledged anomaly clears for everyone once it stops firing', async () => {
  // Mocked: the seed cannot make an anomaly fire. The ack and its clearing go to the real admin.
  await page.route('**/api/anomalies', (r) => r.fulfill({ json: surge(904, 'firing') }));
  try {
    await page.goto('/');
    const attention = page.getByRole('region', { name: 'Needs attention' });
    await attention.getByRole('listitem').filter({ hasText: 'Requests surged for ack 904' }).getByRole('button', { name: 'Acknowledge' }).click();
    await expect(attention.getByText('1 acknowledged item')).toBeVisible();
    await page.unroute('**/api/anomalies');
    await page.route('**/api/anomalies', (r) => r.fulfill({ json: surge(904, 'resolved') }));
    await page.reload();
    await expect.poll(ackKeys).not.toContain('anomaly:904');
    await page.goto('/audit');
    await expect(page.getByRole('row').filter({ hasText: 'noted this has cleared:' }).filter({ hasText: 'Requests surged for ack 904' }).first()).toBeVisible();
  } finally {
    await page.unroute('**/api/anomalies');
    await dropAck('anomaly:904');
  }
});

test('an acknowledgement stays when the dashboard cannot read its source', async () => {
  await page.route('**/api/anomalies', (r) => r.fulfill({ json: surge(905, 'firing') }));
  try {
    await page.goto('/');
    const attention = page.getByRole('region', { name: 'Needs attention' });
    await attention.getByRole('listitem').filter({ hasText: 'Requests surged for ack 905' }).getByRole('button', { name: 'Acknowledge' }).click();
    await expect(attention.getByText('1 acknowledged item')).toBeVisible();
    await page.unroute('**/api/anomalies');
    await page.route('**/api/anomalies', (r) => r.fulfill({ status: 500, json: { error: 'anomalies are unavailable' } }));
    const failed = page.waitForResponse((r) => r.url().includes('/api/anomalies') && r.status() === 500);
    await page.reload();
    await failed;
    await page.waitForLoadState('networkidle');
    expect(await ackKeys()).toContain('anomaly:905');
  } finally {
    await page.unroute('**/api/anomalies');
    await dropAck('anomaly:905');
  }
});

test('a rule anomaly for the same signal as a fleet anomaly is listed under it, not on its own', async () => {
  // Mocked: a rule anomaly needs a published config rule, and the seed runs before the flow publishes anything.
  await page.route('**/api/anomalies', (r) =>
    r.fulfill({
      json: {
        alertmanager: false,
        anomalies: [
          anomaly(901, 'upstream_5xx_ratio', '', '', '5xx from the upstream: 10.0% of requests in the last 5 minutes, against 0.0% in the hour before'),
          anomaly(902, 'rule_upstream_5xx_ratio', 'admin-api', 'config', '100.0% of its requests got a 5xx from the upstream in the last 5 minutes, against 0.0% in the hour before and 10.0% of all requests'),
        ],
      },
    }),
  );
  try {
    await page.goto('/');
    const attention = page.getByRole('region', { name: 'Needs attention' });
    const group = attention.getByRole('listitem').filter({ hasText: '5xx from the upstream: 10.0%' }).filter({ has: page.getByRole('list') });
    await expect(group).toHaveCount(1);
    await expect(group.getByRole('list').getByRole('listitem')).toHaveCount(1);
    await expect(group.getByRole('list').getByRole('listitem')).toContainText('admin-api');
    await expect(attention.getByText('admin-api')).toHaveCount(1);
    await expect(group.getByRole('link')).toHaveCount(1);
  } finally {
    await page.unroute('**/api/anomalies');
  }
});

test('an acknowledged rule anomaly listed under a fleet one stays acknowledged while it fires', async () => {
  // Mocked: the seed cannot make an anomaly fire. 907 has stopped firing, so its
  // clear shows the dashboard did clear what was gone in the same pass.
  await page.route('**/api/anomalies', (r) =>
    r.fulfill({
      json: {
        alertmanager: false,
        anomalies: [
          anomaly(908, 'upstream_5xx_ratio', '', '', '5xx from the upstream: 10.0% of requests in the last 5 minutes, against 0.0% in the hour before'),
          anomaly(906, 'rule_upstream_5xx_ratio', 'admin-api', 'config', '100.0% of its requests got a 5xx from the upstream in the last 5 minutes'),
        ],
      },
    }),
  );
  try {
    await addAck('anomaly:906');
    await addAck('anomaly:907');
    await page.goto('/');
    await expect.poll(ackKeys).not.toContain('anomaly:907');
    // The clears of one pass are sent together; let them all land.
    await page.waitForLoadState('networkidle');
    expect(await ackKeys()).toContain('anomaly:906');
  } finally {
    await page.unroute('**/api/anomalies');
    await dropAck('anomaly:906');
    await dropAck('anomaly:907');
  }
});

test('log-only rules that were acknowledged do not take the three places a newer one needs', async () => {
  // Mocked: the seed has no log-only rule over its limit. Four are added to
  // version 2's rules and to one stats row it served.
  const ids = ['shadow-a', 'shadow-b', 'shadow-c', 'shadow-d'];
  const row = {
    minute: new Date().toISOString(), version: 2, requests: 1000, edge_5xx: 0, upstream_5xx: 0, auth_failures: 0,
    rate_limit_rules: ids.map((id, i) => ({ id, evaluated: 1000, limited: 0, logged: 400 - i * 100, failed: 0 })),
    top_limited: [], rules: [], status_codes: {}, upstream_errors: {},
  };
  await page.route('**/api/stats?*', (r) => r.fulfill({ json: [row] }));
  await page.route('**/api/versions/2', async (r) => {
    const v = (await (await r.fetch()).json()) as VersionDetail;
    v.config.rate_limit_rules = [...(v.config.rate_limit_rules ?? []), ...ids.map((id) => ({ id, expression: true, action: 'log', limit: 1, period: '1m', key: ['ip.src'] }))];
    await r.fulfill({ json: v });
  });
  try {
    for (const id of ids.slice(0, 3)) await addAck(`shadow:${id}`);
    await page.goto('/');
    const attention = page.getByRole('region', { name: 'Needs attention' });
    await expect(attention.getByText('3 acknowledged items')).toBeVisible();
    await expect(attention.getByRole('listitem').filter({ hasText: 'rule shadow-d checked' }).getByRole('button', { name: 'Acknowledge' })).toBeVisible();
  } finally {
    await page.unroute('**/api/stats?*');
    await page.unroute('**/api/versions/2');
    for (const id of ids) await dropAck(`shadow:${id}`);
  }
});

test('the traffic chart marks each publish and the kill switch changes, and a mark opens its version', async () => {
  await page.goto('/');
  const traffic = page.getByRole('region', { name: /^Traffic, / });
  await expect(traffic.getByRole('link', { name: /^Version 2\b/ }).first()).toHaveAttribute('href', /^\/versions\/2(\?|$)/);
  // Version 5 reverted to version 2, turning rate limiting back on.
  const kill = traffic.getByRole('link', { name: /^Version 5\b.*Kill switch changed/ });
  await expect(kill).toBeVisible();
  await kill.click();
  await expect(page.getByRole('heading', { name: 'Version 5', exact: true })).toBeVisible();
});

test('Cmd or Ctrl+K finds a rule, a version, a route, a user and an IP, and Enter opens each', async () => {
  await page.goto('/');
  // Find's key handler is registered by the app shell, so wait for the shell.
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  const find = async (text: string, option: RegExp) => {
    await page.keyboard.press('ControlOrMeta+k');
    const box = page.getByRole('dialog', { name: 'Find' }).getByRole('combobox', { name: 'Find' });
    await box.fill(text);
    await expect(page.getByRole('listbox').getByRole('option', { name: option }).first()).toBeVisible();
    await box.press('Enter');
  };
  // Rules come before routes, so the rule is the first match for its ID.
  await find('login', /login/);
  await expect(page).toHaveURL(/\/rules\/rate_limit\/login$/);
  await expect(page.getByRole('heading', { name: 'Edit login' })).toBeVisible();
  await find('version 2', /Version 2\b/);
  await expect(page.getByRole('heading', { name: 'Version 2', exact: true })).toBeVisible();
  await find('api.example.com/login', /POST api\.example\.com\/login/);
  await expect(page).toHaveURL(/\/routes\/\d+$/);
  await expect(page.getByRole('heading', { name: 'POST api.example.com/login', exact: true })).toBeVisible();
  await find(user, new RegExp(`^${user}\\b`));
  await expect(page).toHaveURL(/\/users$/);
  await expect(page.getByRole('heading', { name: 'Users and tokens', exact: true })).toBeVisible();
  // The seed has no AS number or IPv6 client, so only an IPv4 one is opened.
  await find('198.51.100.7', /198\.51\.100\.7/);
  await expect(page).toHaveURL(/\/subjects\/198\.51\.100\.7$/);
  await expect(page.getByRole('heading', { name: '198.51.100.7', exact: true })).toBeVisible();
});

test('a rule page shows its live counts over the range and its published history', async () => {
  await page.goto('/rules/rate_limit/login');
  const live = page.getByRole('region', { name: 'Traffic', exact: true });
  await expect(live).toContainText('3,500 matched');
  await expect(live).toContainText('1,120 logged instead of limited');
  await expect(page.getByRole('heading', { name: 'Published history' })).toBeVisible();
});

test('a client a log only rule found over its limit on Stats opens its subject page, which lists that rule as a sampled estimate', async () => {
  await page.goto('/stats');
  await page.getByRole('link', { name: '198.51.100.7', exact: true }).click();
  await expect(page).toHaveURL(/\/subjects\/198\.51\.100\.7(\?|$)/);
  await expect(page.getByRole('heading', { name: '198.51.100.7', exact: true })).toBeVisible();
  await expect(page.getByText(/sampled estimate/i).first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'login', exact: true })).toHaveAttribute('href', /^\/rules\/rate_limit\/login(\?|$)/);
});

test('the rule list shows each rule\'s live counts and marks a log only rule', async () => {
  await page.goto('/rules');
  const row = (id: string) => page.getByRole('listitem').filter({ has: page.getByRole('link', { name: id, exact: true }) });
  await expect(row('login')).toContainText('3,500 matched');
  await expect(row('login')).toContainText('1,120 logged instead of limited');
  // login was added with the default action, log only; block-tools blocks.
  await expect(row('login').getByText('log only', { exact: true })).toBeVisible();
  await expect(row('block-tools').getByText('log only', { exact: true })).toHaveCount(0);
});

test('the audit log narrows to releases, and a version links to its page', async () => {
  await page.goto('/audit');
  const releases = page.getByRole('group', { name: 'Category' }).getByRole('button', { name: 'Releases', exact: true });
  await releases.click();
  await expect(releases).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByRole('cell', { name: 'config.publish' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'route.delete' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'version 2', exact: true }).first()).toHaveAttribute('href', /^\/versions\/2(\?|$)/);
});

// The case the rule editor's Investigate opens, for the page sweep below.
let investigated = '';

test('the autopilot page shows the runner, budgets, spend, precision, settings and prices', async () => {
  await nav('Autopilot');
  await expect(page.getByRole('heading', { name: 'Autopilot', exact: true })).toBeVisible();
  // TestUISmoke's scripted runner claims every few hundred milliseconds.
  await expect(page.getByText(/^Runner runner-a 0\.1\.0, credentials for claude/)).toBeVisible();
  await expect(page.getByText('Auto: blocks once the measurements hold').first()).toBeVisible();
  for (const meter of ['Enforce rules', 'Sensors', 'Cases started this hour']) await expect(page.getByText(meter, { exact: true })).toBeVisible();
  const headings = async (...names: string[]) => {
    for (const h of names) await expect(page.getByRole('heading', { name: h, exact: true })).toBeVisible();
  };
  await headings('Status', 'Live rules', 'Cases');
  await expect(page.getByText('No autopilot rule is live.')).toBeVisible();
  await tab('Autopilot', 'Spend');
  await headings('Spend', 'Precision');
  await expect(page.getByText('No enforce rule ended in the last 7 days.')).toBeVisible();
  await tab('Autopilot', 'Settings');
  await headings('Settings', 'Model prices');
});

test('an autopilot setting the server refuses shows its reason by the field, and a valid change saves', async () => {
  await page.goto('/autopilot?tab=settings');
  // The unit picker sits in the label, so its value ends the name.
  const observe = page.getByRole('spinbutton', { name: /^Log before blocking for/ });
  const field = page.locator('div').filter({ has: observe }).last();
  await field.getByRole('combobox', { name: 'Unit' }).selectOption('s');
  await observe.fill('30');
  await page.getByRole('button', { name: 'Save autopilot settings' }).click();
  await confirm('Save autopilot settings');
  await expect(field.getByRole('alert')).toHaveText('must be 1m to 1h');
  await expect(page.getByRole('alert').filter({ hasText: 'Not saved: fix the settings marked above.' })).toBeVisible();
  // Half an hour of logging first, so approving early below is always
  // refused. An hour would need a default ttl over 61m30s for enforce rules.
  await field.getByRole('combobox', { name: 'Unit' }).selectOption('m');
  await observe.fill('30');
  await page.getByRole('combobox', { name: /^Mode( |$)/ }).selectOption('observe');
  await page.getByRole('button', { name: 'Save autopilot settings' }).click();
  await confirm('Save autopilot settings');
  await expect(page.getByRole('status').filter({ hasText: 'Autopilot settings saved.' })).toBeVisible();
  await tab('Autopilot', 'Overview');
  await expect(page.getByText('Observe: a person approves each block').first()).toBeVisible();
});

test('turning the hourly sweep off is saved, shown in the status card, and turned back on', async () => {
  await page.goto('/autopilot?tab=settings');
  const triggers = ['Hourly sweep', 'Daily review', 'Anomaly investigation'];
  for (const name of triggers) await expect(page.getByRole('checkbox', { name })).toBeChecked();
  await page.getByRole('checkbox', { name: 'Hourly sweep' }).uncheck();
  await page.getByRole('button', { name: 'Save autopilot settings' }).click();
  await confirm('Save autopilot settings');
  await expect(page.getByRole('status').filter({ hasText: 'Autopilot settings saved.' })).toBeVisible();

  await page.reload();
  await expect(page.getByRole('checkbox', { name: 'Hourly sweep' })).not.toBeChecked();
  await expect(page.getByRole('checkbox', { name: 'Daily review' })).toBeChecked();
  await expect(page.getByRole('checkbox', { name: 'Anomaly investigation' })).toBeChecked();
  // The status card is on Overview, the checkboxes on Settings.
  const status = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Status', exact: true }) }).last();
  await tab('Autopilot', 'Overview');
  await expect(status.getByText('Off in settings: hourly sweep.')).toBeVisible();
  await tab('Autopilot', 'Settings');

  await page.getByRole('checkbox', { name: 'Daily review' }).uncheck();
  await page.getByRole('button', { name: 'Save autopilot settings' }).click();
  await confirm('Save autopilot settings');
  await expect(page.getByRole('status').filter({ hasText: 'Autopilot settings saved.' })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('checkbox', { name: 'Hourly sweep' })).not.toBeChecked();
  await expect(page.getByRole('checkbox', { name: 'Daily review' })).not.toBeChecked();
  await tab('Autopilot', 'Overview');
  await expect(status.getByText('Off in settings: hourly sweep and daily review.')).toBeVisible();
  await tab('Autopilot', 'Settings');

  // Later tests rely on the sweep and the review.
  await page.getByRole('checkbox', { name: 'Hourly sweep' }).check();
  await page.getByRole('checkbox', { name: 'Daily review' }).check();
  await page.getByRole('button', { name: 'Save autopilot settings' }).click();
  await confirm('Save autopilot settings');
  await expect(page.getByRole('status').filter({ hasText: 'Autopilot settings saved.' })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('checkbox', { name: 'Hourly sweep' })).toBeChecked();
  await expect(page.getByRole('checkbox', { name: 'Daily review' })).toBeChecked();
});

test('Investigate from a rule opens a case that leads with its answer, and Find opens it by its rule', async () => {
  await page.goto('/rules/rate_limit/login');
  await page.getByRole('button', { name: 'Investigate', exact: true }).click();
  await page.getByRole('dialog').getByLabel('Question, if any').fill('Is someone guessing passwords?');
  await page.getByRole('dialog').getByRole('button', { name: 'Start investigating' }).click();
  await expect(page).toHaveURL(/\/autopilot\/cases\/\d+$/);
  investigated = new URL(page.url()).pathname;
  // Exact: get_case's answer, once the runner calls it, quotes the question too.
  await expect(page.getByText('Is someone guessing passwords?', { exact: true })).toBeVisible();
  await expect(page.getByText('Attack', { exact: true })).toBeVisible({
    timeout: 20_000,
  });
  // The answer comes first, then what admin did, then the folded evidence.
  await expect(page.locator('main h2')).toHaveText(['Trigger', 'Verdict', 'Policy checks', 'Actions', 'Evidence', 'Tool calls', 'Cost']);
  await expect(page.locator('main details').first()).not.toHaveAttribute('open');
  // The innermost section with the heading: the page is a section too.
  const card = (name: string) => page.locator('section').filter({ has: page.getByRole('heading', { name, exact: true }) }).last();
  const verdict = card('Verdict');
  await expect(verdict.getByText('Needs you', { exact: true })).toBeVisible();
  await expect(verdict.getByRole('link', { name: /^ap-login-stuffing-\d+$/ })).toHaveAttribute('href', investigated);
  await expect(verdict.getByText('Approve blocking once it has logged for a day')).toBeVisible();
  await expect(verdict.getByText('Tell the login team about the password guessing')).toBeVisible();
  await expect(verdict.getByText('Proposed enforcing 1 rule: all accepted.', { exact: true })).toBeVisible();
  const details = 'so the rule counts failed logins per address';
  await expect(verdict.getByText(details)).toBeHidden();
  await verdict.getByText('How it decided', { exact: true }).click();
  await expect(verdict.getByText(details)).toBeVisible();
  // Evidence, tool calls and passed checks are folded until opened.
  await expect(card('Evidence').getByText('rule_logged on login')).toBeHidden();
  await card('Evidence').getByText(/^Evidence for \d+ proposals?$/).click();
  await expect(card('Evidence').getByText('rule_logged on login')).toBeVisible();
  await card('Tool calls').getByText(/^\d+ tool calls?$/).click();
  await expect(page.getByText('get_case', { exact: true })).toBeVisible();
  await card('Policy checks').getByText(/^Passed all \d+ checks$/).first().click();
  await expect(page.getByText('Passed: Counts per IP or JWT claim')).toBeVisible();

  // The next autopilot run publishes it log only.
  const rule = page.getByRole('region').filter({ has: page.getByText(/^ap-login-stuffing-\d+$/) });
  await expect(rule.getByText('enforce rule, logging only')).toBeVisible({
    timeout: 20_000,
  });
  // Find opens the case that made a live autopilot rule.
  const name = (await rule.getByText(/^ap-login-stuffing-\d+$/).textContent())!;
  await page.goto('/');
  // Find's key handler is registered by the app shell, so wait for the shell.
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  await page.keyboard.press('ControlOrMeta+k');
  const box = page.getByRole('dialog', { name: 'Find' }).getByRole('combobox', { name: 'Find' });
  await box.fill(name);
  await expect(page.getByRole('listbox').getByRole('option', { name: new RegExp(`^${name}\\s*autopilot rule$`) })).toBeVisible();
  await box.press('Enter');
  await expect(page).toHaveURL(new RegExp(`${investigated}$`));
});

// The note TestUISmoke's runner records on the case above, for Find and
// the page sweep below.
let noted = '';
const statement = 'Password guessing on login keeps one client over the limit all hour';

test("the autopilot's memory lists a note with its trust and claim in words, opens it with statistics, links and evidence, and a person retracts it with a reason; re-evaluating a note no rule cites shows why not", async () => {
  await page.goto('/autopilot/notes');
  await expect(page.getByRole('heading', { name: 'Memory', exact: true })).toBeVisible();
  const row = page.getByRole('row').filter({ hasText: statement });
  await expect(row.getByText('unconfirmed', { exact: true })).toBeVisible();
  await expect(row).toContainText('attack signature');
  await expect(row).toContainText(/rule login\b.*\bat least 100 in the 60 minutes before it was checked/);
  const link = row.getByRole('link', { name: /^Note \d+$/ });
  const name = (await link.textContent())!;
  await link.click();
  await expect(page).toHaveURL(/\/autopilot\/notes\/\d+$/);
  noted = new URL(page.url()).pathname;
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  await expect(page.locator('main h2')).toHaveText(['Claim', 'Statistics', 'Links', 'Evidence', 'Uses', 'Blast radius', 'History']);
  const card = (name: string) => page.locator('section').filter({ has: page.getByRole('heading', { name, exact: true }) }).last();
  // A rule's counts are counted, not sampled, and the seed has only today.
  await expect(card('Statistics').getByText('Exact', { exact: true })).toBeVisible();
  await expect(card('Statistics')).toContainText('no earlier days');
  await expect(card('Links').locator('a[href="/rules/rate_limit/login"]')).toBeVisible();
  await expect(card('Links').locator('a[href^="/stats?range="]')).toBeVisible();
  await expect(card('Evidence')).toContainText('get_rule_stats');

  await page.getByRole('button', { name: 'Retract', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('button', { name: 'Retract', exact: true })).toBeDisabled();
  await dialog.getByLabel('Reason').fill('It describes our own login load test');
  await dialog.getByRole('button', { name: 'Retract', exact: true }).click();
  await expect(page.getByText('retracted', { exact: true }).first()).toBeVisible();
  await expect(card('History')).toContainText('It describes our own login load test');

  // The case's rule never cited the note, so there is nothing to re-evaluate.
  await page.getByRole('button', { name: 'Re-evaluate', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: /no rule enforces citing note \d+/i })).toBeVisible();

  await page.goto('/autopilot/notes?trust=retracted');
  await expect(row.getByText('retracted', { exact: true })).toBeVisible();
});

test("the Autopilot page shows spend by day and model, and a live rule's counts while logging and blocking", async () => {
  await page.goto('/autopilot?tab=spend');
  await expect(page.getByRole('navigation', { name: 'Autopilot', exact: true }).getByRole('link', { name: 'Memory', exact: true })).toHaveAttribute('href', '/autopilot/notes');
  const card = (name: string) => page.locator('section').filter({ has: page.getByRole('heading', { name, exact: true }) }).last();
  const spend = card('Spend');
  await expect(spend.getByRole('heading', { name: 'By day and model', exact: true })).toBeVisible();
  await expect(spend.getByRole('columnheader')).toHaveText(['Day', 'Model', 'Runs', 'Cases', 'At your prices', 'Per case', "Provider's estimate"]);
  // The smoke has no price for its model, so a case's cost is unknown.
  const today = spend.getByRole('row').filter({ hasText: new Date().toISOString().slice(0, 10) }).filter({ hasText: 'claude-opus-5-5' });
  await expect(today.getByRole('cell', { name: /^n\/a: \d+ unpriced$/ })).toBeVisible();
  // The rule Investigate made is logging only, until the next test retires it.
  await tab('Autopilot', 'Overview');
  const live = page.getByRole('list', { name: 'Live autopilot rules' }).getByRole('listitem').filter({ has: page.getByRole('link', { name: /^ap-login-stuffing-\d+$/ }) });
  await expect(live).toContainText(/[\d,]+ logged/);
  await expect(live).toContainText(/[\d,]+ blocking/);
});

test('an autopilot rule can be approved only after logging, adopted and marked a false positive', async () => {
  await page.goto(investigated);
  const rule = page.getByRole('region').filter({ has: page.getByText(/^ap-login-stuffing-\d+$/) });
  await rule.getByRole('button', { name: 'Approve blocking' }).click();
  await expect(rule.getByRole('alert')).toContainText('Too early to approve');
  await rule.getByRole('button', { name: 'Adopt', exact: true }).click();
  await expect(rule.getByText('adopted, leaves autopilot on next publish')).toBeVisible();
  await rule.getByRole('button', { name: 'Mark false positive' }).click();
  await page.getByRole('dialog').getByLabel('Reason').fill('Our own login load test');
  await page.getByRole('dialog').getByRole('button', { name: 'Mark false positive' }).click();
  await expect(rule.getByText('retired', { exact: false }).first()).toBeVisible();
  await expect(rule.getByText('marked a false positive')).toBeVisible();
});

test('Investigate from a route opens a case on that route', async () => {
  await page.goto('/routes');
  await page.locator('tbody tr').filter({ hasText: '/login' }).getByRole('link').first().click();
  await page.getByRole('button', { name: 'Investigate', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Start investigating' }).click();
  await expect(page).toHaveURL(/\/autopilot\/cases\/\d+$/);
  await expect(page.getByRole('link', { name: /^route \d+$/ })).toBeVisible();
  await expect(page.getByText('Benign', { exact: true })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByText('Proposed nothing.', { exact: true })).toBeVisible();
});

test('Find opens a case and a note', async () => {
  await page.goto('/');
  // Find's key handler is registered by the app shell, so wait for the shell.
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  const find = async (text: string, option: RegExp) => {
    await page.keyboard.press('ControlOrMeta+k');
    const box = page.getByRole('dialog', { name: 'Find' }).getByRole('combobox', { name: 'Find' });
    await box.fill(text);
    await expect(page.getByRole('listbox').getByRole('option', { name: option })).toBeVisible();
    await box.press('Enter');
  };
  const c = investigated.split('/').pop()!;
  await find(`case ${c}`, new RegExp(`^Case ${c}\\s*case$`));
  await expect(page).toHaveURL(new RegExp(`${investigated}$`));
  await expect(page.getByRole('heading', { name: `Case ${c}`, exact: true })).toBeVisible();
  const n = noted.split('/').pop()!;
  await find(`note ${n}`, new RegExp(`^Note ${n}: ${statement}\\s*note$`));
  await expect(page).toHaveURL(new RegExp(`${noted}$`));
  await expect(page.getByRole('heading', { name: `Note ${n}`, exact: true })).toBeVisible();
});

test('a template opens from the list, and an HTML body added to it previews in a sandboxed frame', async () => {
  await nav('Templates');
  await page.getByRole('link', { name: /^rate_limited\b/ }).click();
  await expect(page.getByRole('heading', { name: 'rate_limited', exact: true })).toBeVisible();
  // The starter's template already has an HTML body; remove it to add one.
  await page.getByRole('tab', { name: /^HTML/ }).click();
  await page.getByRole('button', { name: 'Remove HTML' }).click();
  await expect(page.getByRole('tab', { name: /^HTML/ })).toHaveCount(0);
  await page.getByLabel('Add content type').selectOption({ label: 'HTML' });
  await expect(page.getByRole('tab', { name: /^HTML/ })).toHaveAttribute('aria-selected', 'true');
  const frame = page.locator('iframe[title="Preview"]');
  await expect(frame).toHaveAttribute('sandbox', '');
  await expect(page.frameLocator('iframe[title="Preview"]').getByRole('heading', { name: 'Too many requests' })).toBeVisible();
});

test('Add default HTML and text pages restores the bodies a template lacks', async () => {
  await nav('Templates');
  await page.getByRole('link', { name: /^rate_limited\b/ }).click();
  await page.getByRole('tab', { name: /^text/ }).click();
  await page.getByRole('button', { name: /^Remove text/ }).click();
  await nav('Templates');
  await expect(page.getByText('Adds them to 1 template.')).toBeVisible();
  await page.getByRole('button', { name: 'Add default HTML and text pages' }).click();
  await expect(page.getByRole('button', { name: 'Add default HTML and text pages' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: /^rate_limited\b/ })).toContainText('JSON problem, HTML, text');
});

test('Make default moves a body to the front, and the default can be restored', async () => {
  await nav('Templates');
  await page.getByRole('link', { name: /^rate_limited\b/ }).click();
  await page.getByRole('tab', { name: /^HTML/ }).click();
  await page.getByRole('button', { name: 'Make default' }).click();
  await expect(page.getByRole('tab', { name: 'HTML, default' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: /^JSON problem/ })).toHaveCount(1);
  // Put the original order back for the tests after this one.
  await page.getByRole('tab', { name: /^JSON problem/ }).click();
  await page.getByRole('button', { name: 'Make default' }).click();
  await expect(page.getByRole('tab', { name: /^JSON problem, default/ })).toHaveAttribute('aria-selected', 'true');
});

test('an unknown placeholder in a body shows in its preview and names the body in the save bar', async () => {
  await nav('Templates');
  await page.getByRole('link', { name: /^rate_limited\b/ }).click();
  await page.getByRole('tab', { name: /^HTML/ }).click();
  await page.getByLabel('Body of rate_limited, HTML').click();
  await page.keyboard.press('ControlOrMeta+End');
  await page.keyboard.insertText('{{nope}}');
  await expect(page.getByText('Preview', { exact: true }).locator('..').getByRole('alert')).toContainText('unknown placeholder');
  await expect(page.getByText('template rate_limited, HTML, body').first()).toBeVisible();
  // Delete what was typed so the body is the one it was.
  for (let n = 0; n < '{{nope}}'.length; n++) await page.keyboard.press('Backspace');
  await expect(page.getByText('template rate_limited, HTML, body')).toHaveCount(0);
});

test('a viewer switches tabs and previews a template but cannot change it', async ({ browser }) => {
  await withSavedDraft({}, [], async () => {
    const other = await (await browser.newContext()).newPage();
    await other.goto('/');
    await other.getByLabel('Username').fill(viewer);
    await other.getByLabel('Password').fill(password);
    await other.getByRole('button', { name: 'Sign in' }).click();
    await expect(other.getByRole('navigation', { name: 'Main' })).toBeVisible();
    await other.goto('/templates/rate_limited');
    await expect(other.getByText('Your role can read the policy but not change it.')).toBeVisible();
    const second = other.getByRole('tab').nth(1);
    await second.click();
    await expect(second).toHaveAttribute('aria-selected', 'true');
    await expect(other.getByText('Preview', { exact: true })).toBeVisible();
    await expect(other.getByLabel('Add content type')).toHaveCount(0);
    await expect(other.getByRole('button', { name: 'Make default' })).toHaveCount(0);
    await expect(other.getByRole('button', { name: 'Delete template' })).toHaveCount(0);
    await other.context().close();
  });
});

test('the sidebar groups pages by job', async () => {
  await page.goto('/');
  const main = page.getByRole('navigation', { name: 'Main' });
  // Headings and links in document order, so each link sits under its group.
  await expect(main.locator('p, a')).toHaveText([
    'Monitor', 'Dashboard', 'Stats', 'War room', 'Routes', 'Fleet', 'Notifications', 'Autopilot',
    'Policy', 'Rules', 'Value lists', 'IP lists', 'Templates', 'CORS policies', 'Issuers', 'Settings',
    'Release', 'Tests and simulate', 'Publish', 'Versions',
    'Admin', 'Audit log', 'Users and tokens',
  ]);
});

test('Find opens from its button and reaches the kill switch', async () => {
  await page.goto('/');
  await page.getByRole('button', { name: /^Find/ }).click();
  const box = page.getByRole('dialog', { name: 'Find' }).getByRole('combobox', { name: 'Find' });
  await box.fill('kill');
  await expect(page.getByRole('listbox').getByRole('option').first()).toContainText('Kill switch');
  await box.press('Enter');
  await expect(page).toHaveURL(/\/settings#kill-switch$/);
  await expect(page.getByRole('heading', { name: 'Kill switch', exact: true })).toBeInViewport();
});

test('a case offers Replay with another model as a command', async () => {
  await page.goto(investigated);
  const c = investigated.split('/').pop()!;
  const changes: string[] = [];
  const watch = (r: Request) => {
    if (r.method() !== 'GET') changes.push(`${r.method()} ${r.url()}`);
  };
  page.on('request', watch);
  await page.getByRole('button', { name: 'Replay with another model', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText(new RegExp(`npm run replay -- ${c} --provider (claude|openai) --model \\S+`));
  await expect(dialog).toContainText(/token/i);
  page.off('request', watch);
  // A replay runs where the runner does: opening it asks admin for nothing.
  expect(changes).toEqual([]);
});

test('turning autopilot off asks for a reason, and the audit log keeps it', async () => {
  await page.goto('/autopilot');
  await page.getByRole('button', { name: 'Turn autopilot off' }).click();
  const dialog = page.getByRole('dialog', { name: 'Turn autopilot off?' });
  await expect(dialog.getByRole('button', { name: 'Turn autopilot off' })).toBeDisabled();
  await dialog.getByLabel('Reason').fill('Blocking checkout for a partner');
  await dialog.getByRole('button', { name: 'Turn autopilot off' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Autopilot is off.' })).toBeVisible();
  await expect(page.getByText('No autopilot rule is live.')).toBeVisible();
  await tab('Autopilot', 'Settings');
  await expect(page.getByText('Autopilot is off, so none of these open.')).toBeVisible();
  await nav('Audit log');
  await expect(page.getByRole('row').filter({ hasText: 'changed autopilot settings' }).first()).toContainText('Blocking checkout for a partner');
});

test('a model price with a blank rate is refused at that field, and a full one is added', async () => {
  await page.goto('/autopilot?tab=settings');
  const form = page.locator('form').filter({ has: page.getByRole('heading', { name: 'Add a price', exact: true }) });
  // Page-rooted, since a has filter looks for it inside each div.
  const rate = (name: string) => page.getByRole('spinbutton', { name: new RegExp(`^${name}`) });
  // Not the smoke runner's model, whose cases stay unpriced.
  await form.getByLabel('Model ID').fill('claude-haiku-5-5');
  await rate('Input').fill('1');
  await rate('Output').fill('5');
  await rate('Cache read').fill('0.1');
  await form.getByRole('button', { name: 'Add price' }).click();
  await expect(form.locator('div').filter({ has: rate('Cache write') }).last().getByRole('alert')).toHaveText('is required');
  await rate('Cache write').fill('1.25');
  await form.getByRole('button', { name: 'Add price' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'claude-haiku-5-5' })).toContainText('$1.25');
});

test('the audit log files a model price under Settings', async () => {
  await page.goto('/audit');
  await page.getByRole('group', { name: 'Category' }).getByRole('button', { name: 'Settings', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'settings.autopilot_price' }).first()).toBeVisible();
});

test('at 1280 pixels wide no page scrolls sideways or has a serious accessibility problem', async () => {
  const size = page.viewportSize()!;
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/routes');
  const route = await page.locator('tbody tr').filter({ hasText: '/login' }).getByRole('link').first().getAttribute('href');
  const pages: [string, string][] = [
    ['/', 'Dashboard'],
    ['/rules', 'Rules'],
    ['/rules/rate_limit/login', 'Edit login'],
    ['/templates', 'Templates'],
    ['/templates/rate_limited', 'rate_limited'],
    ['/cors', 'CORS policies'],
    ['/issuers', 'Issuers'],
    ['/settings', 'Settings'],
    ['/tests', 'Tests and simulate'],
    ['/publish', 'Publish'],
    ['/versions', 'Versions'],
    ['/versions/1', 'Version 1'],
    ['/routes', 'Routes'],
    [route!, 'POST api.example.com/login'],
    ['/fleet', 'Fleet'],
    ['/stats', 'Stats'],
    ['/traffic', 'War room'],
    ['/traffic?view=period', 'War room'],
    ['/notifications', 'Notifications'],
    ['/autopilot', 'Autopilot'],
    [investigated, `Case ${investigated.split('/').pop()}`],
    ['/autopilot/notes', 'Memory'],
    [noted, `Note ${noted.split('/').pop()}`],
    ['/audit', 'Audit log'],
    ['/users', 'Users and tokens'],
    ['/account', 'Account'],
    ['/subjects/198.51.100.7', '198.51.100.7'],
  ];
  // Soft, so one run lists every page that fails.
  for (const [path, heading] of pages) {
    await page.goto(path, { waitUntil: 'networkidle' });
    await expect.soft(page.getByRole('heading', { name: heading, exact: true }), `${path} heading`).toBeVisible();
    const sideways = await page.evaluate(() => ({
      page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      boxes: [...document.querySelectorAll('.overflow-x-auto')].filter((e) => e.scrollWidth > e.clientWidth).map((e) => e.outerHTML.slice(0, 120)),
    }));
    expect.soft(sideways.page, `${path} scrolls sideways`).toBe(0);
    expect.soft(sideways.boxes, `${path} has a box that scrolls sideways`).toEqual([]);
    const { violations } = await new AxeBuilder({ page }).analyze();
    const serious = violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
    expect.soft(serious, `${path} accessibility`).toEqual([]);
  }
  await page.setViewportSize(size);
});

test('a long similar route does not widen the page', async () => {
  const size = page.viewportSize()!;
  await page.setViewportSize({ width: 1024, height: 800 });
  // Mocked: access logs would need a very long host and many paths under it.
  await page.route(/\/api\/observed-routes\?/, async (r) => {
    const body = (await (await r.fetch()).json()) as { suggestions: object[] };
    body.suggestions.push({ host: `${'long-host-label-'.repeat(12)}.example.com`, pattern: `/${'long-path-segment-'.repeat(12)}*`, routes: 12 });
    await r.fulfill({ json: body });
  });
  try {
    await page.goto('/routes');
    await expect(page.getByRole('heading', { name: 'Similar routes', exact: true })).toBeVisible();
    const sideways = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(sideways).toBeLessThanOrEqual(0);
  } finally {
    await page.unroute(/\/api\/observed-routes\?/);
    await page.setViewportSize(size);
  }
});

test('fleet hides gone edges until asked', async () => {
  const at = Date.now();
  const edge = (instance: string, live: boolean, ago: number) => ({
    instance, live, last_seen: new Date(at - ago).toISOString(), config_source: 'admin', bootstrap_age_seconds: 0, versions: [1], upstream: 'https://lb.example.com', settings_differ: false,
  });
  // Gone edges first, to show the table puts the reporting edge on top.
  await page.route('**/api/fleet', (r) => r.fulfill({ json: [edge('edge-gone-a', false, 3_600_000), edge('edge-gone-b', false, 7_200_000), edge('edge-live', true, 5_000)] }));
  try {
    // This admin sets no VERIFIED_BOT_SOURCES, so once its answer is in, the crawler card stays away.
    const crawlers = page.waitForResponse('**/api/verified-bots');
    await page.goto('/fleet');
    await crawlers;
    await expect(page.getByRole('heading', { name: 'Verified crawler ranges' })).toHaveCount(0);
    const rows = page.locator('tbody tr');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('edge-live');
    await expect(rows.first()).toContainText('reporting');
    await page.getByRole('button', { name: 'Show 2 gone edges' }).click();
    await expect(rows).toHaveCount(3);
    await expect(rows.first()).toContainText('edge-live');
    await expect(rows.nth(1)).toContainText('gone');
  } finally {
    await page.unroute('**/api/fleet');
  }
});

test('fleet holds publishing only for a reporting edge whose settings differ', async () => {
  const at = Date.now();
  const edge = (instance: string, live: boolean, ago: number) => ({
    instance, live, last_seen: new Date(at - ago).toISOString(), config_source: 'admin', bootstrap_age_seconds: 0, versions: [1], upstream: 'https://lb.example.com', settings_differ: true,
  });
  await page.route('**/api/fleet', (r) => r.fulfill({ json: [edge('edge-live', true, 5_000), edge('edge-gone', false, 3_600_000)] }));
  try {
    await page.goto('/fleet');
    await expect(page.locator('tbody tr').filter({ hasText: 'edge-live' })).toContainText('settings differ');
    const notice = page.getByRole('status').filter({ hasText: 'Publishing is held' });
    await expect(notice).toContainText('Publishing is held: edge-live runs');
    await expect(notice).not.toContainText('edge-gone');
  } finally {
    await page.unroute('**/api/fleet');
  }
});

const crawlerRows = () => {
  const at = Date.now();
  const iso = (ago: number) => new Date(at - ago).toISOString();
  const row = (source: string, o: object) => ({ source, prefixes: 0, ranges_changed_at: null, last_success_at: null, last_attempt_at: iso(60_000), failures: 0, last_error: null, stale: false, ...o });
  return [
    row('https://ranges.example/refreshing.json', { prefixes: 1, last_success_at: iso(60_000) }),
    row('https://ranges.example/failing.json', { prefixes: 1500, last_success_at: iso(3_600_000), failures: 1, last_error: 'source fetch: status 503' }),
    row('https://ranges.example/stale.json', { prefixes: 12, last_success_at: iso(86_400_000), failures: 5, last_error: 'dial tcp: i/o timeout', stale: true }),
    row('https://ranges.example/never.json', { failures: 4, last_error: 'no such host', stale: true }),
    row('https://ranges.example/new.json', { last_attempt_at: null }),
    // Ranges stored before refresh status was recorded: in use, with no attempt recorded yet.
    row('https://ranges.example/upgraded.json', { prefixes: 40, ranges_changed_at: iso(7_200_000), last_success_at: iso(7_200_000), last_attempt_at: null }),
  ];
};

test('fleet lists crawler range sources with their state in words', async () => {
  const size = page.viewportSize()!;
  await page.route('**/api/verified-bots', (r) => r.fulfill({ json: crawlerRows() }));
  try {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/fleet', { waitUntil: 'networkidle' });
    const card = page.locator('#crawler-ranges');
    await expect(card.getByRole('heading', { name: 'Verified crawler ranges', exact: true })).toBeVisible();
    const row = (source: string) => card.getByRole('row').filter({ hasText: source });
    const badge = (source: string) => row(source).locator('td[data-label="State"]');
    await expect(badge('refreshing.json')).toHaveText('refreshing');
    await expect(badge('failing.json')).toHaveText('failing');
    await expect(badge('stale.json')).toHaveText('stale');
    await expect(badge('never.json')).toHaveText('never fetched');
    await expect(badge('new.json')).toHaveText('not fetched yet');
    await expect(badge('upgraded.json')).toHaveText('refreshing');
    await expect(row('refreshing.json')).toContainText('1 prefix');
    await expect(row('failing.json')).toContainText('1,500 prefixes');
    await expect(row('failing.json')).toContainText('Last error: source fetch: status 503');
    await expect(row('never.json')).toContainText('none');
    await expect(row('never.json')).toContainText('Last error: no such host');
    await expect(row('new.json')).toContainText('not yet');
    await expect(row('refreshing.json')).not.toContainText('Last error');
    const notice = card.getByRole('status');
    await expect(notice).toContainText('1 stale source: requests from addresses in its last good ranges still count as verified crawlers');
    await expect(notice).toContainText('A source never fetched counts no address as its crawler');
    const sideways = () =>
      page.evaluate(() => ({
        page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        boxes: [...document.querySelectorAll('.overflow-x-auto')].filter((e) => e.scrollWidth > e.clientWidth).length,
      }));
    expect(await sideways()).toEqual({ page: 0, boxes: 0 });
    const { violations } = await new AxeBuilder({ page }).analyze();
    expect(violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);

    await page.setViewportSize({ width: 375, height: 812 });
    await expect(card.locator('td[data-label="Failures in a row"]').first()).toBeVisible();
    await expect(card.locator('thead')).toBeHidden();
    expect((await sideways()).page).toBe(0);
  } finally {
    await page.unroute('**/api/verified-bots');
    await page.setViewportSize(size);
  }
});

test('settings choose which CDN headers are trusted, and the default can be restored', async () => {
  // The draft is checked on every edit, so the request shows what saving would store.
  const trusted = async (act: () => Promise<void>) => {
    const sent = page.waitForRequest((r) => r.url().endsWith('/api/draft/check') && r.method() === 'POST');
    await act();
    return ((await sent).postDataJSON() as { config: { global: { cdn_trusted_headers?: string[] } } }).config.global.cdn_trusted_headers;
  };
  await nav('Settings');
  const card = page.locator('#trusted-cdn-headers');
  await expect(card.getByRole('heading', { name: 'Trusted CDN headers', exact: true })).toBeVisible();
  // The intro opens from the title's info button, so it is in the page while closed.
  await expect(card.getByText("A rule on one gets no client-controlled warning, and the signals that read it can be used. The edge doesn't check")).toBeAttached();
  // CloudFront adds none of its listed headers to every request, so its default trusts none.
  await expect(card.getByText('Using the default: none trusted.')).toBeVisible();
  await expect(card.getByLabel('cloudfront-viewer-city', { exact: true })).not.toBeChecked();
  // Another edit keeps the draft unsaved, so restoring the default is checked too and shows what saving would store.
  expect(await trusted(() => page.getByLabel('Maximum requests in progress per edge').fill('500'))).toBeUndefined();
  expect(await trusted(() => card.getByLabel('cloudfront-viewer-city', { exact: true }).check())).toEqual(['cloudfront-viewer-city']);
  await expect(card.getByText('Using the default')).toBeHidden();
  expect(await trusted(() => card.getByRole('button', { name: 'Use the default' }).click())).toBeUndefined();
  await expect(card.getByLabel('cloudfront-viewer-city', { exact: true })).not.toBeChecked();
  await expect(card.getByText('Using the default: none trusted.')).toBeVisible();
  await page.getByRole('button', { name: 'Discard' }).click();
  await page.getByRole('button', { name: 'Discard changes' }).click();
});

test('fleet lists the CDN headers and the rule builder suggests them as header keys', async () => {
  const size = page.viewportSize()!;
  try {
    for (const width of [1280, 375]) {
      await page.setViewportSize({ width, height: 800 });
      await page.goto('/fleet', { waitUntil: 'networkidle' });
      const card = page.locator('#cdn-headers');
      await expect(card.getByRole('heading', { name: 'CDN headers', exact: true })).toBeVisible();
      await expect(card.getByText('cloudfront-viewer-city', { exact: true })).toBeVisible();
      // CloudFront-Viewer-Country is mapped to a field, so rules may not read it, but it is still logged.
      await expect(card.getByText('Also logged')).toContainText('cloudfront-viewer-country');
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
    }
    await page.setViewportSize({ width: 1280, height: 800 });
    await nav('Rules');
    const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
    await limits.getByRole('button', { name: 'Add rate limit rule' }).click();
    await page.locator('.ruleGroup-addRule').first().click();
    await page.locator('.rule').first().locator('.rule-fields').selectOption('http.request.headers');
    const key = page.locator('.rule').first().getByLabel('Key');
    await expect(key).toHaveAttribute('list', /.+/);
    await expect(page.locator('datalist option[value="cloudfront-viewer-city"]')).toHaveCount(1);
  } finally {
    await page.setViewportSize(size);
  }
});

test('fleet shows an error when crawler range status cannot load', async () => {
  await page.route('**/api/verified-bots', (r) => r.fulfill({ status: 500, contentType: 'application/problem+json', body: JSON.stringify({ title: 'crawler status unavailable' }) }));
  try {
    await page.goto('/fleet');
    await expect(page.locator('#crawler-ranges').getByRole('alert')).toContainText(/crawler status unavailable/i);
  } finally {
    await page.unroute('**/api/verified-bots');
  }
});

test('notification settings list stale crawler ranges under Whole fleet', async () => {
  await page.goto('/notifications?tab=settings');
  const fleet = page.getByRole('heading', { name: 'Whole fleet', exact: true }).locator('xpath=following-sibling::ul[1]');
  await expect(fleet.getByRole('listitem').filter({ hasText: 'Verified crawler ranges stopped refreshing' }).getByLabel('Failed refreshes in a row')).toBeVisible();
});

test('an anomaly on a crawler source or an autopilot case names its subject', async () => {
  const at = new Date().toISOString();
  const source = 'https://ranges.example/googlebot.json';
  const anomaly = (id: number, signal: string, rule: string, phase: string) => ({
    id, signal, rule, phase, severity: 'warning', state: 'firing', tripped: 2, passed: 0, started_at: at, fired_at: at, resolved_at: null, notified_at: null,
    summary: `Summary of ${rule || signal}`, case_id: null, case_state: null, case_verdict: null, withheld: '',
  });
  await page.route('**/api/anomalies', (r) =>
    r.fulfill({ json: { alertmanager: false, anomalies: [anomaly(931, 'verified_bots_stale', source, 'verified_bots'), anomaly(932, 'autopilot_needs_person', 'case 12', 'autopilot'), anomaly(933, 'traffic_surge', '', '')] } }),
  );
  await page.route('**/api/verified-bots', (r) => r.fulfill({ json: crawlerRows() }));
  try {
    await page.goto('/notifications');
    const crawler = page.getByRole('row').filter({ hasText: `Summary of ${source}` });
    await expect(crawler).toContainText(`Verified crawler ranges stopped refreshing for source ${source}`);
    const own = page.getByRole('row').filter({ hasText: 'Summary of case 12' });
    await expect(own).toContainText('for case 12');
    await expect(own).not.toContainText('rule case 12');
    await expect(crawler.getByRole('button', { name: 'Investigate' })).toHaveCount(0);
    await expect(own.getByRole('button', { name: 'Investigate' })).toHaveCount(0);
    // Positive control: a traffic anomaly offers it, so the absences above are not a missing permission.
    await expect(page.getByRole('row').filter({ hasText: 'Summary of traffic_surge' }).getByRole('button', { name: 'Investigate' })).toBeVisible();

    await page.goto('/');
    const item = page.getByRole('region', { name: 'Needs attention' }).getByRole('listitem').filter({ hasText: source });
    await expect(item).toContainText(`for source ${source}`);
    await item.getByRole('link', { name: 'Fleet', exact: true }).click();
    await expect(page).toHaveURL(/\/fleet(\?[^#]*)?#crawler-ranges$/);
    await expect(page.locator('#crawler-ranges')).toBeInViewport();
  } finally {
    await page.unroute('**/api/anomalies');
    await page.unroute('**/api/verified-bots');
  }
});

test('notifications hide resolved anomalies until asked', async () => {
  const at = new Date().toISOString();
  const anomaly = (id: number, state: string, summary: string) => ({
    id, signal: 'upstream_5xx_ratio', rule: '', phase: '', severity: 'critical', state, tripped: 2, passed: 0, started_at: at, fired_at: at,
    resolved_at: state === 'resolved' ? at : null, notified_at: null, summary, case_id: null, case_state: null, case_verdict: null, withheld: '',
  });
  await page.route('**/api/anomalies', (r) =>
    r.fulfill({ json: { alertmanager: false, anomalies: [anomaly(911, 'firing', 'Open anomaly summary'), anomaly(912, 'resolved', 'Resolved anomaly summary')] } }),
  );
  try {
    await page.goto('/notifications');
    await expect(page.getByRole('row').filter({ hasText: 'Open anomaly summary' })).toHaveCount(1);
    await expect(page.getByRole('row').filter({ hasText: 'Resolved anomaly summary' })).toHaveCount(0);
    await page.getByRole('button', { name: 'Show 1 resolved anomaly' }).click();
    await expect(page.getByRole('row').filter({ hasText: 'Resolved anomaly summary' })).toHaveCount(1);
    await expect(page).toHaveURL(/resolved=1/);
  } finally {
    await page.unroute('**/api/anomalies');
  }
});

test('a draft that fails to load shows the error instead of a blank page', async () => {
  await page.route('**/api/draft', (r) => r.fulfill({ status: 500, contentType: 'application/problem+json', body: JSON.stringify({ title: 'draft store unavailable' }) }));
  await page.reload();
  await expect(page.getByRole('alert')).toContainText(/draft store unavailable/i);
  await page.unroute('**/api/draft');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
});

test('an IP list is added and fetched, and a banned IP is lifted after a confirmation', async () => {
  await nav('IP lists');
  await expect(page.getByRole('heading', { name: 'IP lists', exact: true })).toBeVisible();
  await page.getByLabel('Name', { exact: true }).fill('smoke-list');
  await page.getByLabel('Download from a URL').check();
  await page.getByLabel('List address').fill(process.env.SMOKE_LIST_URL!);
  await page.getByRole('button', { name: 'Add list' }).click();
  const row = page.getByRole('row').filter({ hasText: process.env.SMOKE_LIST_URL! });
  // The POST must finish before a reload below can abort it.
  await expect(row).toBeVisible();
  // The smoke run fetches every second; the page rereads once a minute, so reload.
  await expect(async () => {
    await page.reload();
    await expect(row.getByText('up to date')).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 30_000 });
  await expect(row.getByRole('cell', { name: '2', exact: true })).toBeVisible();
  await page.getByLabel('Is this IP listed?').fill('203.0.113.50');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByText('203.0.113.50 is on smoke-list (203.0.113.50/32)')).toBeVisible();
  const ban = page.getByRole('row').filter({ hasText: '203.0.113.9' });
  await expect(ban).toContainText('/wp-login.php');
  await ban.getByRole('button', { name: 'Lift ban' }).click();
  await expect(page.getByRole('dialog')).toContainText('ends on every edge within about a minute. Other rules still apply, and 203.0.113.9 is banned again if it trips the trap');
  // The table cell's nowrap must not reach the dialog, or its text is cut off.
  expect(await page.getByRole('dialog').evaluate((d) => d.scrollWidth <= d.clientWidth)).toBe(true);
  await confirm('Lift ban');
  await expect(ban.getByText('lifted, reaching the edges')).toBeVisible();
  await nav('Audit log');
  await expect(page.getByRole('cell', { name: 'ban.lifted' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'ip_list.added' })).toBeVisible();
  // The rule builder offers every IP list to pick, with whether it is on.
  await nav('Rules');
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rate limit rule' }).click();
  await page.locator('.ruleGroup-addRule').first().click();
  await page.locator('.rule').first().locator('.rule-fields').selectOption('client.ip_lists');
  // The value is picked from the lists, searchable; the field's operator may take one name or many.
  await expect(page.getByText('smoke-list (on)')).toBeVisible();
  await page.getByLabel('Find a list').fill('zzz-no-such');
  await expect(page.getByText('No list matches.')).toBeVisible();
  await page.getByLabel('Find a list').fill('');
  // The default operator takes one name, so the lists are radios.
  await expect(page.getByLabel('smoke-list (on)')).toHaveAttribute('type', 'radio');
  await page.getByLabel('smoke-list (on)').check();
  await expect(page.getByTestId('preview-text')).toContainText('client.ip_lists eq "smoke-list"');
  // "in" takes many names, so the lists become checkboxes.
  await page.locator('.rule').first().locator('.rule-operators').selectOption('in');
  await expect(page.getByLabel('smoke-list (on)')).toHaveAttribute('type', 'checkbox');
  await page.getByLabel('smoke-list (on)').check();
  await expect(page.getByTestId('preview-text')).toContainText('client.ip_lists in {"smoke-list"}');
  // A typed name that is not a list stays picked and is named as missing.
  await page.getByRole('button', { name: 'Edit expression' }).click();
  await page.getByLabel('Expression', { exact: true }).click();
  await page.keyboard.press('ControlOrMeta+a');
  // insertText, not type: CodeMirror closes brackets and quotes typed one key at a time.
  await page.keyboard.insertText('client.ip_lists in {"smoke-lst"}');
  await page.getByRole('button', { name: 'Use builder' }).click();
  await expect(page.getByLabel('smoke-lst (no such list)')).toBeChecked();
});

// The flows below leave the draft unsaved and discard it, so revision numbers
// in the tests around them do not move.
async function discardDraft() {
  await page.getByRole('button', { name: 'Discard' }).click();
  await page.getByRole('button', { name: 'Discard changes' }).click();
}

async function newAccessRule(id: string) {
  await nav('Rules');
  const config = page.getByRole('list', { name: 'Access rules' }).locator('..');
  await config.getByRole('button', { name: 'Add access rule' }).click();
  await page.getByLabel('Rule ID').fill(id);
  await page.locator('.ruleGroup-addRule').first().click();
  return page.locator('.rule').first();
}

test('a value list made on the Value lists page is used in a rule with Use a list', async () => {
  // The IP list test above leaves an unapplied rule open, whose leave guard would hold a link.
  await page.goto('/value-lists');
  await page.getByRole('button', { name: 'New value list' }).click();
  await page.getByLabel('Name', { exact: true }).fill('bad-agents');
  await page.getByRole('combobox', { name: /^Holds/ }).selectOption({ label: 'User agents' });
  await page.getByLabel('Values', { exact: true }).fill('curl/\npython-requests/');
  await expect(page.getByText('2 of 10,000')).toBeVisible();
  await page.getByRole('button', { name: 'Apply to draft' }).click();
  await expect(page.getByRole('link', { name: 'bad-agents' })).toBeVisible();

  const cond = await newAccessRule('list-agents');
  await cond.locator('.rule-fields').selectOption('http.user_agent');
  await cond.locator('.rule-operators').selectOption('contains');
  await page.getByLabel(/^Action/).selectOption('log');
  await cond.getByLabel('Use a list').check();
  await cond.getByLabel('Value list', { exact: true }).selectOption('bad-agents');
  await expect(cond).toContainText('contains any of the 2');
  await expect(cond).toContainText("Counts as 2 of this rule's 32 conditions");
  await expect(page.getByTestId('preview-text')).toContainText('$bad-agents');
  await page.getByRole('button', { name: 'Apply to draft' }).click();

  await nav('Value lists');
  await expect(page.getByRole('link', { name: 'list-agents' })).toBeVisible();
  await page.getByRole('link', { name: 'bad-agents' }).click();
  await expect(page.getByRole('combobox', { name: /^Holds/ })).toHaveCount(0);
  await expect(page.getByText('It cannot change while rules use the value list')).toBeVisible();
  await discardDraft();
});

test('a value list name the server refuses keeps Apply to draft off', async () => {
  await page.goto('/value-lists/_new');
  await page.getByLabel('Name', { exact: true }).fill('Bad Name');
  await page.getByRole('combobox', { name: /^Holds/ }).selectOption({ label: 'User agents' });
  await expect(page.getByRole('alert').filter({ hasText: 'lowercase letters, digits' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply to draft' })).toBeDisabled();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Cancel' }).click();
});

test('renaming a value list rewrites the rules that use it', async () => {
  await page.goto('/value-lists/_new');
  await page.getByLabel('Name', { exact: true }).fill('old-agents');
  await page.getByRole('combobox', { name: /^Holds/ }).selectOption({ label: 'User agents' });
  await page.getByLabel('Values', { exact: true }).fill('curl/');
  await page.getByRole('button', { name: 'Apply to draft' }).click();
  const cond = await newAccessRule('rename-agents');
  await cond.locator('.rule-fields').selectOption('http.user_agent');
  await cond.locator('.rule-operators').selectOption('contains');
  await page.getByLabel(/^Action/).selectOption('log');
  await cond.getByLabel('Use a list').check();
  await cond.getByLabel('Value list', { exact: true }).selectOption('old-agents');
  await page.getByRole('button', { name: 'Apply to draft' }).click();

  // A rule in another phase, with the condition inside a nested group.
  await nav('Rules');
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rate limit rule' }).click();
  await page.getByLabel('Rule ID').fill('rename-limit');
  await page.locator('.ruleGroup-addGroup').first().click();
  const inner = page.locator('.ruleGroup .ruleGroup');
  await inner.locator('.ruleGroup-addRule').click();
  const nested = inner.locator('.rule').first();
  await nested.locator('.rule-fields').selectOption('http.user_agent');
  await nested.locator('.rule-operators').selectOption('contains');
  await nested.getByLabel('Use a list').check();
  await nested.getByLabel('Value list', { exact: true }).selectOption('old-agents');
  await page.getByRole('button', { name: 'Apply to draft' }).click();

  await nav('Value lists');
  await page.getByRole('link', { name: 'old-agents' }).click();
  await page.getByLabel('Name', { exact: true }).fill('new-agents');
  await expect(page.getByText('Renaming also updates the rules that use it: rename-agents, rename-limit.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply to draft' })).toBeEnabled();
  await page.getByRole('button', { name: 'Apply to draft' }).click();
  await expect(page.getByRole('link', { name: 'new-agents' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'old-agents' })).toHaveCount(0);

  const used = page.getByRole('listitem').filter({ hasText: 'new-agents' });
  await expect(used).toContainText('rename-agents');
  await expect(used).toContainText('rename-limit');
  for (const id of ['rename-agents', 'rename-limit']) {
    await page.getByRole('link', { name: id }).click();
    await expect(page.getByTestId('preview-text')).toContainText('$new-agents');
    await page.getByRole('button', { name: 'Cancel' }).click();
    await nav('Value lists');
  }
  await expect(page.getByText('has problems')).toHaveCount(0);
  await discardDraft();
});

// Moves by link, not by URL: a reload would drop the unsaved draft.
async function addAgentList(name: string) {
  await nav('Value lists');
  await page.getByRole('button', { name: 'New value list' }).click();
  await page.getByLabel('Name', { exact: true }).fill(name);
  await page.getByRole('combobox', { name: /^Holds/ }).selectOption({ label: 'User agents' });
  await page.getByLabel('Values', { exact: true }).fill('curl/');
  await page.getByRole('button', { name: 'Apply to draft' }).click();
}

test('renaming a value list to a name another list has keeps Apply to draft off', async () => {
  await addAgentList('dup-a');
  await addAgentList('dup-b');
  await page.getByRole('link', { name: 'dup-b' }).click();
  await page.getByLabel('Name', { exact: true }).fill('dup-a');
  await expect(page.getByText('A value list called dup-a already exists.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply to draft' })).toBeDisabled();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Cancel' }).click();
  await discardDraft();
});

test('Delete value list removes the list from the draft', async () => {
  await addAgentList('gone-list');
  await page.getByRole('link', { name: 'gone-list' }).click();
  await page.getByRole('button', { name: 'Delete value list' }).click();
  await confirm('Delete value list');
  await expect(page.getByRole('heading', { name: 'Value lists', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'gone-list' })).toHaveCount(0);
  await discardDraft();
});

// Saves a draft holding these value lists and access rules through the admin
// API, as a save from another session would, runs the flow on it, and puts the
// saved draft back.
async function withSavedDraft(lists: Record<string, { field: string; values: string[] }>, rules: object[], run: () => Promise<void>) {
  const put = (config: unknown) =>
    page.evaluate(async (c) => {
      const cur = (await (await fetch('/api/draft')).json()) as { revision: number; tests: unknown };
      const res = await fetch('/api/draft', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'If-Match': `"${cur.revision}"` }, body: JSON.stringify({ config: c, tests: cur.tests ?? [] }) });
      if (!res.ok) throw new Error(`PUT /api/draft ${res.status}: ${await res.text()}`);
    }, config);
  await page.goto('/value-lists');
  const before = await page.evaluate(async () => ((await (await fetch('/api/draft')).json()) as { config: { global: object; config_rules: object[] | null } }).config);
  await put({ ...before, global: { ...before.global, lists }, config_rules: [...(before.config_rules ?? []), ...rules] });
  try {
    await page.goto('/value-lists');
    await run();
  } finally {
    await put(before);
    await page.goto('/value-lists');
  }
}

test('a draft already over the cap on value list values in rules still applies a rename, and shows the cap', async () => {
  // 20 rules each use one 10,000 value list: exactly the 200,000 the server accepts.
  const values = Array.from({ length: 10_000 }, (_, i) => `/p${i}`);
  const rules = Array.from({ length: 20 }, (_, i) => ({
    id: `use-${String(i).padStart(2, '0')}`,
    expression: { combinator: 'and', rules: [{ field: 'http.request.uri.path', operator: 'in', value: { list: 'huge-paths' } }] },
    settings: { block: 'log' },
  }));
  await withSavedDraft({ 'huge-paths': { field: 'http.request.uri.path', values } }, rules, async () => {
    // A 21st use takes the unsaved draft over the cap, which the rule editor does not hold against its own rule.
    const cond = await newAccessRule('use-20');
    await cond.locator('.rule-fields').selectOption('http.request.uri.path');
    await cond.locator('.rule-operators').selectOption('in');
    await page.getByLabel(/^Action/).selectOption('log');
    await cond.getByLabel('Use a list').check();
    await cond.getByLabel('Value list', { exact: true }).selectOption('huge-paths');
    await page.getByRole('button', { name: 'Apply to draft' }).click();
    await nav('Value lists');
    await page.getByRole('link', { name: 'huge-paths', exact: true }).click();
    await page.getByLabel('Name', { exact: true }).fill('huge-renamed');
    await expect(page.getByText(/rules use value lists holding 210,000 values in all; at most 200,000 are allowed/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Apply to draft' })).toBeEnabled();
    await page.getByRole('button', { name: 'Apply to draft' }).click();
    await expect(page.getByRole('link', { name: 'huge-renamed', exact: true })).toBeVisible();
    await discardDraft();
  });
});

test('a value list that takes the draft over the value list count shows it and keeps Apply to draft off', async () => {
  const lists = Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`seed-${String(i).padStart(3, '0')}`, { field: 'http.user_agent', values: ['curl/'] }]));
  await withSavedDraft(lists, [], async () => {
    await page.goto('/value-lists/_new');
    await page.getByLabel('Name', { exact: true }).fill('one-too-many');
    await page.getByRole('combobox', { name: /^Holds/ }).selectOption({ label: 'User agents' });
    await page.getByLabel('Values', { exact: true }).fill('curl/');
    await expect(page.getByText('has 101 value lists; at most 100 are allowed')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Apply to draft' })).toBeDisabled();
    await expect(page.getByText('This change breaks rules')).toHaveCount(0);
    page.once('dialog', (dialog) => void dialog.accept());
    await page.getByRole('button', { name: 'Cancel' }).click();
  });
});

test('a check answered with an error that has no title or reason phrase does not count as passed', async () => {
  await page.goto('/value-lists/_new');
  // HTTP/2 and HTTP/3 send no reason phrase, which a Response built here also lacks.
  await page.evaluate(() => {
    const real = window.fetch;
    window.fetch = (input, init) =>
      (typeof input === 'string' ? input : input instanceof URL ? input.href : input.url).includes('/api/draft/check') ? Promise.resolve(new Response('<html>bad gateway</html>', { status: 502, headers: { 'content-type': 'text/html' } })) : real(input, init);
  });
  await page.getByLabel('Name', { exact: true }).fill('no-answer');
  await page.getByRole('combobox', { name: /^Holds/ }).selectOption({ label: 'User agents' });
  await page.getByLabel('Values', { exact: true }).fill('curl/');
  await expect(page.getByText('Could not check the value list: HTTP 502')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply to draft' })).toBeDisabled();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Cancel' }).click();
  await page.reload();
});

test('a value list that does not exist says so', async () => {
  await page.goto('/value-lists/nope');
  await expect(page.getByText('Value list not found')).toBeVisible();
});

test('a viewer reads a value list and a rule with no word about Apply, even when the check fails', async ({ browser }) => {
  // Saved, so the viewer's own session reads them.
  const rule = { id: 'reader-rule', expression: { combinator: 'and', rules: [{ field: 'http.user_agent', operator: 'contains', value: { list: 'reader-agents' } }] }, settings: { block: 'log' } };
  await withSavedDraft({ 'reader-agents': { field: 'http.user_agent', values: ['curl/'] } }, [rule], async () => {
    const other = await (await browser.newContext()).newPage();
    await other.goto('/');
    await other.getByLabel('Username').fill(viewer);
    await other.getByLabel('Password').fill(password);
    await other.getByRole('button', { name: 'Sign in' }).click();
    await expect(other.getByRole('navigation', { name: 'Main' })).toBeVisible();
    await other.route('**/api/draft/check', (r) => r.fulfill({ status: 502, contentType: 'text/html', body: '<html>bad gateway</html>' }));
    const checked = other.waitForResponse((r) => r.url().endsWith('/api/draft/check'));
    await other.goto('/value-lists/reader-agents');
    await expect(other.getByText('Your role can read the policy but not change it.')).toBeVisible();
    await expect(other.getByLabel('Values', { exact: true })).toBeDisabled();
    await checked;
    // Let React render what the failed check returned before asserting it shows nothing.
    await other.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
    await expect(other.getByText(/Could not check|Checking the/)).toHaveCount(0);
    await expect(other.getByRole('button', { name: 'Apply to draft' })).toHaveCount(0);
    const ruleChecked = other.waitForResponse((r) => r.url().endsWith('/api/draft/check'));
    await other.goto('/rules/config/reader-rule');
    await expect(other.getByText('Your role can read the policy but not change it.')).toBeVisible();
    await ruleChecked;
    await other.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
    await expect(other.getByText(/Could not check|Checking the/)).toHaveCount(0);
    await other.context().close();
  });
});

test('the Value lists link from a user agent condition opens the editor holding user agents', async () => {
  const cond = await newAccessRule('ua-link');
  await cond.locator('.rule-fields').selectOption('http.user_agent');
  await cond.locator('.rule-operators').selectOption('contains');
  await cond.getByLabel('Use a list').check();
  page.once('dialog', (dialog) => void dialog.accept());
  await cond.getByRole('link', { name: 'Value lists' }).click();
  await expect(page.getByRole('combobox', { name: /^Holds/ })).toHaveValue('http.user_agent');
  await page.getByRole('button', { name: 'Cancel' }).click();
});

test('a value change that breaks a rule using the list keeps Apply to draft off and names the rule', async () => {
  await page.goto('/value-lists/_new');
  await page.getByLabel('Name', { exact: true }).fill('url-paths');
  await page.getByRole('combobox', { name: /^Holds/ }).selectOption({ label: 'URL paths' });
  await page.getByLabel('Values', { exact: true }).fill('/admin');
  await page.getByRole('button', { name: 'Apply to draft' }).click();
  const cond = await newAccessRule('in-paths');
  await cond.locator('.rule-fields').selectOption('http.request.uri.path');
  await cond.locator('.rule-operators').selectOption('in');
  await page.getByLabel(/^Action/).selectOption('log');
  await cond.getByLabel('Use a list').check();
  await cond.getByLabel('Value list', { exact: true }).selectOption('url-paths');
  await page.getByRole('button', { name: 'Apply to draft' }).click();

  await nav('Value lists');
  await page.getByRole('link', { name: 'url-paths' }).click();
  // ".php" is a fine path value for "ends with" but never matches under "in".
  await page.getByLabel('Values', { exact: true }).fill('.php');
  await expect(page.getByText('This change breaks rules')).toBeVisible();
  await expect(page.getByRole('alert').getByRole('link', { name: 'in-paths' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply to draft' })).toBeDisabled();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Cancel' }).click();
  await discardDraft();
});

test('the values box grows with its lines instead of scrolling', async () => {
  await page.goto('/value-lists/_new');
  await page.getByLabel('Values', { exact: true }).fill(Array.from({ length: 30 }, (_, i) => `line-${i}`).join('\n'));
  const grown = await page.getByLabel('Values', { exact: true }).evaluate((e) => e.scrollHeight <= e.clientHeight);
  expect(grown).toBe(true);
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Cancel' }).click();
});

test('typed values are saved as a value list from the rule, which switches to it', async () => {
  await addAgentList('taken-agents');
  const cond = await newAccessRule('inline-agents');
  await cond.locator('.rule-fields').selectOption('http.user_agent');
  await cond.locator('.rule-operators').selectOption('in');
  await page.getByLabel(/^Action/).selectOption('log');
  await cond.getByLabel('Values', { exact: true }).fill('curl/\npython-requests/');
  await cond.getByRole('button', { name: 'Save as list' }).click();
  await cond.getByLabel('List name').fill('Bad Name');
  await expect(cond.getByText(/lowercase letters, digits/)).toBeVisible();
  await expect(cond.getByRole('button', { name: 'Save', exact: true })).toBeDisabled();
  await cond.getByLabel('List name').fill('taken-agents');
  await expect(cond.getByText('“taken-agents” already exists')).toBeVisible();
  await expect(cond.getByRole('button', { name: 'Save', exact: true })).toBeDisabled();
  await cond.getByLabel('List name').fill('saved-agents');
  await expect(cond.getByRole('button', { name: 'Save', exact: true })).toBeEnabled();
  await cond.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(cond.getByLabel('Value list', { exact: true })).toHaveValue('saved-agents');
  await expect(cond).toContainText('is one of the 2 values');
  await page.getByRole('button', { name: 'Apply to draft' }).click();
  await nav('Value lists');
  await expect(page.getByRole('listitem').filter({ hasText: 'saved-agents' })).toContainText('User agents · 2 values');
  await discardDraft();
});

test('a typed IP list is added, edited, and a bad address is named by its line', async () => {
  // An earlier IP list test leaves an unapplied rule open, whose leave guard would hold a link.
  await page.goto('/');
  await nav('IP lists');
  await page.getByLabel('Name', { exact: true }).fill('office-ips');
  await page.getByLabel('Addresses, one per line').fill('203.0.113.10\n198.51.100.0/24');
  await page.getByRole('button', { name: 'Add list' }).click();
  const row = page.getByRole('row').filter({ hasText: 'office-ips' });
  await expect(row).toContainText('Typed in admin');
  await expect(row.getByRole('button', { name: 'Refresh now' })).toHaveCount(0);
  await row.getByRole('button', { name: 'Edit' }).click();
  const edit = page.locator('form').filter({ hasText: 'Saved changes reach every edge' });
  await edit.getByLabel('Addresses, one per line').fill('203.0.113.10\n198.51.100.7/24');
  await edit.getByRole('button', { name: 'Save' }).click();
  await expect(edit).toContainText('line 2:');
  await expect(edit).toContainText('host bits');
  await edit.getByLabel('Addresses, one per line').fill('203.0.113.10\n198.51.100.0/24\n192.0.2.1');
  await edit.getByRole('button', { name: 'Save' }).click();
  await expect(edit).toHaveCount(0);
  await expect(row.getByRole('cell', { name: '3', exact: true })).toBeVisible();
});

test('an always-allow rule asks for an IP list, adds it in one click and shows the Allow badge', async () => {
  await page.goto('/rules');
  const cond = await newAccessRule('allow-office');
  await cond.getByLabel('Value').fill('/office');
  await page.getByLabel(/^Action/).selectOption('allow');
  await expect(page.getByText('an always-allow rule must require').first()).toBeVisible();
  await page.getByLabel('IP list', { exact: true }).selectOption('office-ips');
  await page.getByRole('button', { name: 'Add condition: client is on IP list' }).click();
  await expect(page.getByTestId('preview-text')).toContainText('client.ip_lists');
  await expect(page.getByText('an always-allow rule must require')).toHaveCount(0);
  await page.getByRole('button', { name: 'Apply to draft' }).click();
  const rule = page.getByRole('listitem').filter({ has: page.getByRole('link', { name: 'allow-office', exact: true }) });
  await expect(rule).toContainText('always allow');
  await discardDraft();
});

test('when admin stops answering the screen says traffic is unaffected, and Try again recovers', async () => {
  await page.route('**/api/auth/me', (r) => r.fulfill({ status: 502, body: 'Bad Gateway' }));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Admin is not answering' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('traffic is not affected');
  await page.unroute('**/api/auth/me');
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
});

test('signing out goes back to sign in, and signing in again works', async () => {
  await page.goto('/');
  // The sidebar's button; on a narrow window it is in the drawer instead.
  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  await page.getByLabel('Username').fill(user);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
});

test('an expired session goes back to sign in', async () => {
  await nav('Versions');
  await nav('Rules');
  await page.context().clearCookies();
  await nav('Versions');
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
});
