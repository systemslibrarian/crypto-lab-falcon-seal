import { defineConfig } from '@playwright/test';

// Runs the e2e suite against the production build: `npm run build` first, then
// `npm run test:e2e` (the preview server is started automatically).
export default defineConfig({
  testDir: 'e2e',
  timeout: 180_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://localhost:4210/crypto-lab-falcon-seal/',
    trace: 'retain-on-failure'
  },
  webServer: {
    command: 'npm run preview -- --port 4210 --strictPort',
    url: 'http://localhost:4210/crypto-lab-falcon-seal/',
    reuseExistingServer: !process.env.CI
  }
});
