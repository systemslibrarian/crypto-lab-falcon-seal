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
