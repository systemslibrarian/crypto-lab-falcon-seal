import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Keep vitest out of e2e/ — those are Playwright specs.
    include: ['tests/**/*.test.ts']
  }
});
