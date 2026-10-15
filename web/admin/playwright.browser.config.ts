import { defineConfig, devices } from '@playwright/test';

// Runs against an edge started by TestBrowserStreams (internal/edge), which
// sets BASE_URL. One worker: the upstream reports the edge's stream count,
// which must not include another browser's streams.
export default defineConfig({
  testDir: 'edge-streams',
  forbidOnly: !!process.env.CI,
  timeout: 30_000,
  workers: 1,
  use: { baseURL: process.env.BASE_URL, trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
