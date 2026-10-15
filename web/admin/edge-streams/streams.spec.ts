import { expect, test } from '@playwright/test';

// The page is internal/edge/testdata/browser/index.html, served by the
// upstream through the edge; each check is one of its functions.
type Page = Window & Record<string, () => Promise<unknown>>;
const call = (page: import('@playwright/test').Page, name: string) => page.evaluate((n) => (window as unknown as Page)[n]!(), name);

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test('SSE counts as a stream and resumes with Last-Event-ID after the upstream ends it', async ({ page }) => {
  expect(await call(page, 'sse')).toEqual(['streams=1 inflight=0', 'resumed after 1']);
});

test('an edge rejection closes the EventSource instead of retrying', async ({ page }) => {
  expect(await call(page, 'sseRejected')).toBe(2); // EventSource.CLOSED
});

test('a streamed fetch body arrives chunk by chunk', async ({ page }) => {
  expect(await call(page, 'ndjson')).toEqual(['{"n":1}\n', '{"n":2}\n']);
});

test('a WebSocket echoes through the edge with its subprotocol and Origin', async ({ page, baseURL }) => {
  expect(await call(page, 'ws')).toEqual({ data: `hello origin=${baseURL}`, protocol: 'chat' });
});

test('a refused upgrade closes the WebSocket abnormally', async ({ page }) => {
  expect(await call(page, 'wsRejected')).toBe(1006);
});
