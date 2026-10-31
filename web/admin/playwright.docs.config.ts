import { defineConfig } from '@playwright/test';

// Renders the pages shown in the docs and compares them with
// docs/assets/screenshots. TestDocScreenshots (internal/admin) starts admin
// with fixed data at a fixed time and a pinned browser server in Docker, and
// sets BASE_URL, PW_WS and SHOT_TIME. Run it with scripts/ci/screenshots.sh.
export default defineConfig({
  testDir: 'docs-shots',
  forbidOnly: !!process.env.CI,
  timeout: 300_000,
  snapshotPathTemplate: '../../docs/assets/screenshots/{arg}{ext}',
  // The browser image is pinned, so pages render the same bytes every run;
  // any pixel that differs fails.
  expect: { toHaveScreenshot: { threshold: 0, maxDiffPixels: 0 } },
  use: {
    baseURL: process.env.BASE_URL,
    ignoreHTTPSErrors: true,
    browserName: 'chromium',
    viewport: { width: 1280, height: 800 },
    timezoneId: 'UTC',
    locale: 'en-US',
    colorScheme: 'light',
    // Partial raster repaints only a tile's changed part, which shades
    // antialiased edges a little differently from a full repaint.
    launchOptions: { args: ['--disable-partial-raster'] },
    // The browser runs in Docker; this sends its requests for admin's
    // address back through the runner, and no other local service.
    connectOptions: {
      wsEndpoint: process.env.PW_WS ?? '',
      exposeNetwork: new URL(process.env.BASE_URL ?? 'http://127.0.0.1').host,
    },
  },
});
