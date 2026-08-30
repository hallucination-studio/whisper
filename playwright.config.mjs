import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  workers: 1,
  timeout: 15_000,
  expect: { timeout: 5_000 },
  use: {
    baseURL: 'http://127.0.0.1:4173',
    channel: 'chrome',
    headless: true,
    serviceWorkers: 'block',
    viewport: { width: 1440, height: 960 },
  },
  webServer: {
    command: 'node tests/browser/serve-ui.mjs',
    port: 4173,
    reuseExistingServer: false,
  },
});
