import { expect, type Page, test } from '@playwright/test';

// The admin pages the user docs show, from the data TestDocScreenshots
// seeds. The browser clock is frozen at the same moment as admin's, so
// "19 minutes ago" and chart axes don't change between runs.
const shot = async (page: Page, name: string, heading: string) => {
  await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await expect(page).toHaveScreenshot(`${name}.png`);
};

test('docs screenshots', async ({ page }) => {
  await page.clock.setFixedTime(new Date(process.env.SHOT_TIME!));
  await page.goto('/');
  await page.getByLabel('Username').fill(process.env.SHOT_USER!);
  await page.getByLabel('Password').fill(process.env.SHOT_PASSWORD!);
  await page.getByRole('button', { name: 'Sign in' }).click();
  // Navigating before sign-in answers would cancel it.
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();

  // Audit rows carry random user and token IDs, and the issuers' keys URL
  // and audit rows carry the test IdP's random port. Their widths size
  // columns and fields, so fixed values keep the layout the same every run.
  // Set after sign-in, so the session cookie is set by the browser itself.
  await page.route('**/api/**', async (route) => {
    const res = await route.fetch();
    let body = (await res.text()).replace(/https:\/\/127\.0\.0\.1:\d+/g, 'https://idp.example.com');
    if (route.request().url().includes('/api/audit')) body = body.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '00000000-0000-4000-8000-000000000000');
    // Audit rows of case claims, case runs and precision rows carry the
    // prompt's hash, which changes with every prompt edit.
    body = body.replace(/"prompt_sha256":"[0-9a-f]{64}"/g, `"prompt_sha256":"${'5e'.repeat(32)}"`);
    // A tool call's time is measured in real time.
    if (route.request().url().includes('/api/autopilot/cases/')) body = body.replace(/"duration_ms":\d+/g, '"duration_ms":4');
    // Postgres stamps a token's creation with the real time, not admin's
    // clock; the fixture creates the edge token 4 days before the shots.
    if (route.request().url().includes('/api/tokens')) body = body.replace(/"created_at":"[^"]*"/g, `"created_at":"${new Date(Date.parse(process.env.SHOT_TIME!) - 4 * 86_400_000).toISOString()}"`);
    // The body's length can change, so the original length must not be sent.
    const headers = res.headers();
    delete headers['content-length'];
    await route.fulfill({ response: res, headers, body });
  });

  // The fixture has an hour of stats, so pages that chart them show the last hour.
  const pages: [string, string, string][] = [
    ['dashboard', '/?range=1h', 'Dashboard'],
    ['rules', '/rules?range=1h', 'Rules'],
    ['publish', '/publish', 'Publish'],
    ['versions', '/versions', 'Versions'],
    ['fleet', '/fleet', 'Fleet'],
    ['audit', '/audit', 'Audit log'],
    ['routes', '/routes', 'Routes'],
    ['templates', '/templates', 'Templates'],
    ['cors', '/cors', 'CORS policies'],
    ['issuers', '/issuers', 'Issuers'],
    ['settings', '/settings', 'Settings'],
    ['stats', '/stats?range=1h', 'Stats'],
    ['users', '/users', 'Users and tokens'],
    ['account', '/account', 'Account'],
    // The client the fixture's api-burst rule limits most.
    ['subject', '/subjects/203.0.113.24?range=1h', '203.0.113.24'],
  ];
  for (const [name, path, heading] of pages) {
    await page.goto(path);
    await shot(page, name, heading);
  }

  // Needs attention fills the dashboard's first screen, so the traffic
  // chart and its release marks get a shot of their own.
  await page.goto('/?range=1h');
  const traffic = page.getByRole('region', { name: 'Traffic, last hour' });
  await expect(traffic.getByRole('link', { name: /^Version 4 published/ })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await expect(traffic).toHaveScreenshot('dashboard-traffic.png');

  await page.goto('/routes');
  await page.getByRole('link', { name: '/login' }).click();
  await shot(page, 'route-detail', 'POST api.example.com/login');

  await page.goto('/rules?range=1h');
  await page.getByRole('link', { name: 'login-per-ip', exact: true }).click();
  await shot(page, 'rule-editor', 'Edit login-per-ip');

  await page.goto('/notifications');
  await shot(page, 'notifications', 'Notifications');

  await page.goto('/autopilot');
  await shot(page, 'autopilot', 'Autopilot');
  await page.getByRole('link', { name: /^ap-login-stuffing-\d+$/ }).click();
  await expect(page.getByText('Attack', { exact: true })).toBeVisible();
  await shot(page, 'autopilot-case', 'Case 1');

  await page.goto('/autopilot/notes');
  await shot(page, 'autopilot-memory', 'Memory');
  // The attack signature the login case recorded on login-per-ip.
  const note = page.getByRole('row').filter({ hasText: 'login-per-ip' }).filter({ hasText: 'attack signature' }).getByRole('link', { name: /^Note \d+$/ });
  const name = (await note.textContent())!;
  await note.click();
  await shot(page, 'autopilot-note', name);

  await page.goto('/tests');
  // The simulate form below the results loads with the expression schema.
  // Scrolling before it renders stops short at the page's end, so the
  // shot's scroll position would depend on which request answers first.
  await expect(page.getByRole('combobox', { name: 'Method' })).toBeVisible();
  await page.getByRole('button', { name: 'Run tests on the saved draft' }).click();
  // The results are below the tests' editor.
  await page.getByRole('list', { name: 'Test results' }).scrollIntoViewIfNeeded();
  await shot(page, 'tests', 'Tests and simulate');
});
