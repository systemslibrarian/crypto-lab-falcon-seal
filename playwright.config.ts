import { defineConfig } from '@playwright/test';

// Runs the e2e suite against the production build; the preview server (and the
// build it serves) are started automatically by the webServer entry below.
export default defineConfig({
  testDir: 'e2e',
  timeout: 180_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://localhost:4210/crypto-lab-falcon-seal/',
    trace: 'retain-on-failure'
  },
  webServer: {
    // Build first: `vite preview` only serves the existing dist/, so without
    // this a broken build leaves the last good bundle in place and the suite
    // passes green against source that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4210 --strictPort',
    url: 'http://localhost:4210/crypto-lab-falcon-seal/',
    reuseExistingServer: !process.env.CI
  }
});
