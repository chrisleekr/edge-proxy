import { defineConfig } from '@playwright/test';

// Runs against a real admin started by TestUISmoke (internal/admin), which
// sets BASE_URL. The admin serves TLS with a test certificate.
export default defineConfig({
  testDir: 'e2e',
  forbidOnly: !!process.env.CI,
  timeout: 60_000,
  use: { baseURL: process.env.BASE_URL, ignoreHTTPSErrors: true, trace: 'retain-on-failure' },
});
