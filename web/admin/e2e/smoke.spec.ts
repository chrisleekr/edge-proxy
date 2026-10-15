import { expect, type Page, test } from '@playwright/test';

// One admin through the critical flows, in order: sign in,
// build a rule with And/Or, switch to text and back, save, publish through
// a canary, compare versions, revert, and read the audit log.
test.describe.configure({ mode: 'serial' });

const user = process.env.SMOKE_USER!;
const password = process.env.SMOKE_PASSWORD!;

let page: Page;
test.beforeAll(async ({ browser }) => {
  page = await browser.newPage();
});

const nav = (name: string) => page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name, exact: true }).click();

async function saveDraft(revision: number) {
  await page.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByRole('status').filter({ hasText: `Saved revision ${revision}` })).toBeVisible();
}

async function publish(message: string, version: number, canary?: string) {
  await nav('Publish');
  await page.getByLabel('Message').fill(message);
  if (canary) await page.getByLabel('Canary percent (empty for all traffic)').fill(canary);
  await page.getByRole('button', { name: 'Publish', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: `Published version ${version}.` })).toBeVisible();
}

test('a wrong password is refused and the right one signs in', async () => {
  await page.goto('/');
  await page.getByLabel('Username').fill(user);
  await page.getByLabel('Password').fill('not the password at all');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert')).toContainText('wrong username or password');
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible();
});

test('a rule built with And and Or survives a trip through text', async () => {
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rule' }).click();
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
  await saveDraft(1);
});

test('the first publish goes to all traffic', async () => {
  await publish('Add login limit', 1);
  await nav('Versions');
  await expect(page.getByRole('row', { name: /Add login limit/ })).toContainText('active');
});

test('invalid JSON stays on screen and blocks saving until discarded', async () => {
  await nav('Settings');
  await page.getByText('Disable rate limiting').click();
  await page.getByLabel('Defaults', { exact: true }).click();
  await page.keyboard.press('ControlOrMeta+End');
  await page.keyboard.type('x');
  await expect(page.getByRole('alert').filter({ hasText: 'Not valid JSON' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save draft' })).toBeDisabled();
  await page.getByRole('button', { name: 'Discard' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Not valid JSON' })).toBeHidden();
  await expect(page.getByLabel('Disable rate limiting')).not.toBeChecked();
});

test('going back two entries from one rule editor shows the other rule', async () => {
  await nav('Rules');
  await page.getByRole('link', { name: 'login', exact: true }).click();
  await expect(page.getByLabel('Rule ID')).toHaveValue('login');
  await page.getByRole('button', { name: 'Cancel' }).click();
  const limits = page.getByRole('list', { name: 'Rate limit rules' }).locator('..');
  await limits.getByRole('button', { name: 'Add rule' }).click();
  await expect(page.getByLabel('Rule ID')).toHaveValue('');
  await page.evaluate(() => history.go(-2));
  await expect(page.getByRole('heading', { name: 'Edit login' })).toBeVisible();
  await expect(page.getByLabel('Rule ID')).toHaveValue('login');
  await page.getByRole('button', { name: 'Cancel' }).click();
});

test('a canary can be stepped only after its wait, and aborted', async () => {
  await nav('Settings');
  await page.getByText('Disable rate limiting').click();
  await saveDraft(3); // publishing bumped the draft to revision 2
  await publish('Kill switch drill', 2, '10');
  await expect(page.getByText('Canary: version 2 on 10% of traffic')).toBeVisible();
  await page.getByLabel('Next percent').fill('50');
  await page.route('**/api/canary/step', (r) => r.abort());
  await page.getByRole('button', { name: 'Step up' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await page.unroute('**/api/canary/step');
  await page.getByRole('button', { name: 'Step up' }).click();
  await expect(page.getByRole('alert')).toContainText('wait at least');
  await page.getByLabel('Abort reason').fill('drill finished');
  await page.getByRole('button', { name: 'Abort' }).click();
  await expect(page.getByText('Canary: version 2')).toBeHidden();
  await nav('Versions');
  await expect(page.getByRole('row', { name: /Kill switch drill/ })).toContainText('rolled back');
});

test('versions compare by rule and setting, and revert makes a new version', async () => {
  await page.goto('/versions/compare?a=1&b=2');
  await expect(page.getByTestId('diff')).toContainText('kill_switch.rate_limit');

  await page.goto('/versions/2');
  await page.getByLabel('Reason', { exact: true }).fill('bring the drill back');
  await page.getByRole('button', { name: 'Revert to version 2' }).click();
  await expect(page.getByRole('heading', { name: 'Version 3' })).toBeVisible();
  await expect(page.getByText('revert of version 2')).toBeVisible();
});

test('revert to previous puts the earlier version back in one step', async () => {
  await nav('Versions');
  await page.getByLabel('Reason').fill('emergency drill');
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Revert to previous (version 1)' }).click();
  await expect(page.getByRole('heading', { name: 'Version 4' })).toBeVisible();
  await expect(page.getByText('revert of version 1')).toBeVisible();
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

test('the audit log lists the changes and its chain verifies', async () => {
  await nav('Audit');
  await expect(page.getByRole('cell', { name: 'config.publish' }).first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'canary.abort' })).toBeVisible();
  await page.getByText('Before and after').first().click();
  await expect(page.getByTestId('diff').first()).toBeVisible();
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Chain verified' })).toContainText('Chain verified through event');
  await page.reload();
  await expect(page.getByRole('status', { name: 'Audit integrity' })).toContainText('verified to event');
});

test('a draft that fails to load shows the error instead of a blank page', async () => {
  await page.route('**/api/draft', (r) => r.fulfill({ status: 500, contentType: 'application/problem+json', body: JSON.stringify({ title: 'draft store unavailable' }) }));
  await page.reload();
  await expect(page.getByRole('alert')).toContainText('draft store unavailable');
  await page.unroute('**/api/draft');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible();
});

test('an expired session goes back to sign in', async () => {
  await nav('Versions');
  await nav('Rules');
  await page.context().clearCookies();
  await nav('Versions');
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
});
