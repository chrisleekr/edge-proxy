import AxeBuilder from '@axe-core/playwright';
import { expect, type Page, type Request, test } from '@playwright/test';

// One admin through the critical flows, in order: sign in, publish the
// starter draft unchanged, build a rule with And/Or, switch to text and
// back, save, publish through a canary, compare versions, revert, and read
// the audit log.
test.describe.configure({ mode: 'serial' });

const user = process.env.SMOKE_USER!;
const password = process.env.SMOKE_PASSWORD!;

let page: Page;
test.beforeAll(async ({ browser }) => {
  // An explicit context: axe refuses a page that owns its own context.
  page = await (await browser.newContext()).newPage();
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

test('a rule gets its own notification setting, which outlives a reload', async () => {
  const saveNotifications = async () => {
    await page.getByRole('button', { name: 'Save notification settings' }).click();
    await confirm('Save notification settings');
    await expect(page.getByRole('status').filter({ hasText: 'Notification settings saved.' })).toBeVisible();
  };
  await nav('Notifications');
  await expect(page.getByRole('heading', { name: 'Notifications', exact: true })).toBeVisible();
  await expect(page.getByText('No rule has its own settings')).toBeVisible();
  await page.getByRole('combobox', { name: 'Rule', exact: true }).selectOption('login');
  // Only signals that apply to a rate limit rule are offered.
  const signal = page.getByRole('combobox', { name: 'Signal', exact: true });
  await expect(signal.getByRole('option', { name: 'Upstream 5xx on a rule' })).toHaveCount(0);
  await signal.selectOption({ label: 'Log-only rule would block' });
  await page.getByRole('button', { name: 'Give this rule its own setting' }).click();
  const own = page.getByRole('listitem').filter({ hasText: 'Log-only rule would block for rule login' });
  await own.getByRole('combobox', { name: 'Log-only rule would block, Severity' }).selectOption('critical');
  await saveNotifications();
  await page.reload();
  await expect(page.getByRole('listitem').filter({ hasText: 'Log-only rule would block for rule login' }).getByRole('combobox', { name: 'Log-only rule would block, Severity' })).toHaveValue('critical');
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

test('on a narrow window the draft bar stays below the top bar, so Save draft works after scrolling', async () => {
  const size = page.viewportSize()!;
  // Wide enough that Save draft shares the bar's first line, narrow enough
  // for the top bar instead of the sidebar.
  await page.setViewportSize({ width: 600, height: 800 });
  await page.goto('/settings');
  const field = page.getByLabel('Most requests in progress per edge');
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

test('a config rule set to block saves, and the block kill switch saves with it', async () => {
  await nav('Rules');
  const config = page.getByRole('list', { name: 'Config rules' }).locator('..');
  await config.getByRole('button', { name: 'Add config rule' }).click();
  await page.getByLabel('Rule ID').fill('block-tools');
  await page.getByLabel(/^Block/).selectOption('block');
  await page.getByRole('button', { name: 'Apply to draft' }).click();
  const rule = page.getByRole('listitem').filter({ has: page.getByRole('link', { name: 'block-tools', exact: true }) });
  await expect(rule).toContainText('blocks with 403');

  await nav('Settings');
  await page.getByText('Disable blocking by config rules').click();
  await page.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByRole('status').filter({ hasText: /Saved revision \d+/ })).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Disable blocking by config rules')).toBeChecked();
  await nav('Rules');
  await expect(page.getByRole('listitem').filter({ has: page.getByRole('link', { name: 'block-tools', exact: true }) })).toContainText('blocks with 403');
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

test('a rule anomaly for the same signal as a fleet anomaly is listed under it, not on its own', async () => {
  // Mocked: a rule anomaly needs a published config rule, and the seed runs before the flow publishes anything.
  const at = new Date().toISOString();
  const anomaly = (id: number, signal: string, rule: string, phase: string, summary: string) => ({
    id, signal, rule, phase, severity: 'critical', state: 'firing', tripped: 2, passed: 0, started_at: at, fired_at: at, resolved_at: null, notified_at: null, summary,
  });
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
  const live = page.getByRole('region', { name: 'Live' });
  await expect(live).toContainText('3,500 matched');
  await expect(live).toContainText('1,120 over limit, log only');
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
  await expect(row('login')).toContainText('1,120 over limit, log only');
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
  for (const h of ['Status', 'Live rules', 'Cases', 'Spend', 'Precision', 'Settings', 'Model prices'])
    await expect(page.getByRole('heading', { name: h, exact: true })).toBeVisible();
  await expect(page.getByText('No autopilot rule is live.')).toBeVisible();
  await expect(page.getByText('No enforce rule ended in the last 7 days.')).toBeVisible();
});

test('an autopilot setting the server refuses shows its reason by the field, and a valid change saves', async () => {
  await page.goto('/autopilot');
  // The unit picker sits in the label, so its value ends the name.
  const observe = page.getByRole('spinbutton', { name: /^Log before blocking for/ });
  const field = page.locator('div').filter({ has: observe }).last();
  await field.getByRole('combobox', { name: 'Unit' }).selectOption('s');
  await observe.fill('30');
  await page.getByRole('button', { name: 'Save autopilot settings' }).click();
  await confirm('Save autopilot settings');
  await expect(field.getByRole('alert')).toHaveText('must be 1m to 1h');
  await expect(page.getByRole('alert').filter({ hasText: 'Not saved: fix the settings marked above.' })).toBeVisible();
  // An hour of logging first, so approving early below is always refused.
  await field.getByRole('combobox', { name: 'Unit' }).selectOption('m');
  await observe.fill('60');
  await page.getByRole('combobox', { name: /^Mode( |$)/ }).selectOption('observe');
  await page.getByRole('button', { name: 'Save autopilot settings' }).click();
  await confirm('Save autopilot settings');
  await expect(page.getByRole('status').filter({ hasText: 'Autopilot settings saved.' })).toBeVisible();
  await expect(page.getByText('Observe: a person approves each block').first()).toBeVisible();
});

test('Investigate from a rule opens a case that reads as a story, and Find opens it by its rule', async () => {
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
  // The story order, top to bottom.
  await expect(page.locator('main h2')).toHaveText(['Trigger', 'Evidence', 'Tool calls', 'Verdict', 'Policy checks', 'Actions', 'Cost']);
  await expect(page.locator('main details').first()).not.toHaveAttribute('open');
  await expect(page.getByText('get_case', { exact: true })).toBeVisible();
  // The innermost section with the heading: the page is a section too.
  const card = (name: string) => page.locator('section').filter({ has: page.getByRole('heading', { name, exact: true }) }).last();
  await expect(card('Evidence').getByText('rule_would_block on login')).toBeVisible();
  await expect(page.getByText('Passed: Counts per IP or JWT claim')).toBeVisible();

  // The next autopilot run publishes it log only.
  const rule = page.getByRole('region').filter({ has: page.getByText(/^ap-login-stuffing-\d+$/) });
  await expect(rule.getByText('enforce rule, logging only')).toBeVisible({
    timeout: 20_000,
  });
  // Find opens the case that made a live autopilot rule.
  const name = (await rule.getByText(/^ap-login-stuffing-\d+$/).textContent())!;
  await page.goto('/');
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
  await page.goto('/autopilot');
  await expect(page.getByRole('link', { name: 'Memory', exact: true })).toHaveAttribute('href', '/autopilot/notes');
  const card = (name: string) => page.locator('section').filter({ has: page.getByRole('heading', { name, exact: true }) }).last();
  const spend = card('Spend');
  await expect(spend.getByRole('heading', { name: 'By day and model', exact: true })).toBeVisible();
  await expect(spend.getByRole('columnheader')).toHaveText(['Day', 'Model', 'Runs', 'Cases', 'At your prices', 'Per case', "Provider's estimate"]);
  // The smoke has no price for its model, so a case's cost is unknown.
  const today = spend.getByRole('row').filter({ hasText: new Date().toISOString().slice(0, 10) }).filter({ hasText: 'claude-opus-5-5' });
  await expect(today.getByRole('cell', { name: /^n\/a: \d+ unpriced$/ })).toBeVisible();
  // The rule Investigate made is logging only, until the next test retires it.
  const live = page.getByRole('list', { name: 'Live autopilot rules' }).getByRole('listitem').filter({ has: page.getByRole('link', { name: /^ap-login-stuffing-\d+$/ }) });
  await expect(live).toContainText(/[\d,]+ while logging/);
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
});

test('Find opens a case and a note', async () => {
  await page.goto('/');
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
  await nav('Audit');
  await expect(page.getByRole('row').filter({ hasText: 'changed autopilot settings' }).first()).toContainText('Blocking checkout for a partner');
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
