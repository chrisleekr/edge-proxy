import { expect, type Page, test } from '@playwright/test';

// One admin through the critical flows, in order: sign in, publish the
// starter draft unchanged, build a rule with And/Or, switch to text and
// back, save, publish through a canary, compare versions, revert, and read
// the audit log.
test.describe.configure({ mode: 'serial' });

const user = process.env.SMOKE_USER!;
const password = process.env.SMOKE_PASSWORD!;

let page: Page;
test.beforeAll(async ({ browser }) => {
  page = await browser.newPage();
});

const nav = (name: string) => page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name, exact: true }).click();

// Actions that change what production serves ask first in a dialog.
const confirm = (action: string) => page.getByRole('dialog').getByRole('button', { name: action, exact: true }).click();

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
  const config = page.getByRole('list', { name: 'Config rules' }).locator('..');
  await config.getByRole('button', { name: 'Add config rule' }).click();
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
  await nav('CORS');
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
  await expect(page.getByTestId('diff')).toContainText('kill_switch.rate_limit');

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
  await nav('Users');
  await page.getByLabel('Username').fill('vera');
  await page.getByLabel('Initial password').fill('plum orchard lantern seventeen');
  await page.getByRole('group', { name: 'Roles', exact: true }).getByLabel('viewer').uncheck();
  await page.getByRole('group', { name: 'Roles', exact: true }).getByLabel('editor').check();
  await page.getByRole('button', { name: 'Add user' }).click();
  await expect(page.getByRole('group', { name: 'Roles of vera' }).getByLabel('editor')).toBeChecked();
});

test('a simulated request becomes a test, and saving it leaves nothing unsaved', async () => {
  await nav('Tests');
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

test('the audit log lists the changes and its chain verifies', async () => {
  await nav('Audit');
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
  await drawer.getByRole('link', { name: 'Audit', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Audit log', exact: true })).toBeVisible();
  await expect(drawer).toBeHidden();
  await page.getByRole('button', { name: 'Menu' }).click();
  await expect(drawer).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  await page.setViewportSize(size);
});

test('a draft that fails to load shows the error instead of a blank page', async () => {
  await page.route('**/api/draft', (r) => r.fulfill({ status: 500, contentType: 'application/problem+json', body: JSON.stringify({ title: 'draft store unavailable' }) }));
  await page.reload();
  await expect(page.getByRole('alert')).toContainText(/draft store unavailable/i);
  await page.unroute('**/api/draft');
  await page.goto('/');
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
