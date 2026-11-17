import { test, expect } from '@playwright/test';

test('combined sampler leakage note exposes the source and hardware scope', async ({ page }) => {
  await page.goto('./#joint-sampler-leakage');
  const note = page.locator('#joint-sampler-leakage');
  await expect(note).toBeVisible();
  for (const text of ['28 October 2026', 'preprint', 'physical power measurements and profiling', '38 of 50', 'constant-time CLZ', 'does not reproduce the hardware experiment']) {
    await expect(note).toContainText(text);
  }
  await expect(note.locator('a')).toHaveAttribute('href', 'https://eprint.iacr.org/2026/2656');
});


test('key-expansion research keeps the target and experiment boundaries', async ({ page }) => {
  await page.goto('./#single-trace-expansion');
  const note = page.locator('#single-trace-expansion');
  await expect(note).toBeVisible();
  for (const text of ['16 November 2026', 'one power trace', 'PQClean Falcon-512 sign_dyn', 'ARM Cortex-M4', '-O0, -Os and -O3', '53 of 100', 'ten traces', 'physical power observation', 'not establish a mathematical break', 'does not reproduce', 'accepted to TCHES 2027']) {
    await expect(note).toContainText(text);
  }
  await expect(note.locator('a')).toHaveAttribute('href', 'https://eprint.iacr.org/2025/2159');
});
