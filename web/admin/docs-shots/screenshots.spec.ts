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
  // Audit rows carry random user and token IDs and the test IdP's random
  // port. Their widths size the table's columns, so fixed values keep the
  // layout the same every run.
  await page.route('**/api/audit*', async (route) => {
    const res = await route.fetch();
    const body = (await res.text())
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '00000000-0000-4000-8000-000000000000')
      .replace(/https:\/\/127\.0\.0\.1:\d+/g, 'https://idp.example.com');
    // The body's length can change, so the original length must not be sent.
    const headers = res.headers();
    delete headers['content-length'];
    await route.fulfill({ response: res, headers, body });
  });
  await page.goto('/');
  await page.getByLabel('Username').fill(process.env.SHOT_USER!);
  await page.getByLabel('Password').fill(process.env.SHOT_PASSWORD!);
  await page.getByRole('button', { name: 'Sign in' }).click();
  // Navigating before sign-in answers would cancel it.
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();

  const pages: [string, string, string][] = [
    ['dashboard', '/', 'Dashboard'],
    ['rules', '/rules', 'Rules'],
    ['publish', '/publish', 'Publish'],
    ['versions', '/versions', 'Versions'],
    ['fleet', '/fleet', 'Fleet'],
    ['audit', '/audit', 'Audit log'],
    ['routes', '/routes', 'Routes'],
  ];
  for (const [name, path, heading] of pages) {
    await page.goto(path);
    await shot(page, name, heading);
  }

  await page.getByRole('link', { name: '/login' }).click();
  await shot(page, 'route-detail', 'POST api.example.com/login');

  await page.goto('/rules');
  await page.getByRole('link', { name: 'login-per-ip', exact: true }).click();
  await shot(page, 'rule-editor', 'Edit login-per-ip');
});
