import { defineConfig } from '@playwright/test';

// Captures the screenshots in docs/assets/screenshots from a running
// `make demo` (admin on 127.0.0.1:8081). Not a test gate.
export default defineConfig({
  testDir: 'docs-shots',
  forbidOnly: !!process.env.CI,
  timeout: 60_000,
  use: { baseURL: process.env.BASE_URL ?? 'http://127.0.0.1:8081', viewport: { width: 1280, height: 800 } },
});
