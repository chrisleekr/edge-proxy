import { expect, test } from '@playwright/test';

// Credentials of the throwaway demo user created by loadtest/tools seed.
const user = 'loadtest';
const password = 'load test password for local runs only';
const out = (name: string) => `../../docs/assets/screenshots/${name}.png`;

test('dashboard screenshots', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Username').fill(user);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Rules', exact: true })).toBeVisible();

  const shots: [string, string, string][] = [
    ['rules', '/', 'Rules'],
    ['publish', '/publish', 'Publish'],
    ['versions', '/versions', 'Versions'],
    ['fleet', '/fleet', 'Fleet'],
    ['audit', '/audit', 'Audit log'],
  ];
  for (const [name, path, heading] of shots) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: out(name) });
  }

  await page.goto('/');
  await page.getByRole('link', { name: 'login', exact: true }).click();
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: out('rule-editor') });
});
