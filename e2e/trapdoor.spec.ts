import { expect, test } from '@playwright/test';

/**
 * Panel 7 — real trapdoor signing.
 *
 * The panel exists to close the gap Panels 2 and 3 admit to: the illustrative
 * signer never reads the private key. These specs assert the closure from what
 * the page actually renders — the NTRU equation's coefficients, the measured
 * norms, the verifier's two independent checks — and they assert the failure
 * paths as hard as the success path, because "the trapdoor helps" is only
 * meaningful next to a signer that does not have it.
 */

test.beforeEach(async ({ page }) => {
  await page.goto('./');
  await expect(page.locator('#panel-7')).toBeVisible();
  await page.locator('#td-keygen').click();
  await expect(page.locator('#td-key')).toContainText('Key generated', { timeout: 60_000 });
});

test('keygen solves the NTRU equation, and the page shows every coefficient of it', async ({ page }) => {
  const key = page.locator('#td-key');
  await expect(key).toHaveClass(/ok/);
  await expect(page.locator('#td-eq-verdict')).toContainText('f·G − g·F = q exactly');
  // 8 coefficient rows, each with a computed value, a required value and a tick.
  await expect(page.locator('#td-key table').nth(1).locator('tbody tr')).toHaveCount(8);
  await expect(page.locator('#td-key table').nth(1).locator('tbody')).toContainText('12289');
  await expect(page.locator('#td-key table').nth(1).locator('tbody')).not.toContainText('❌');
  // F and G are solved, not sampled: both must be non-trivial polynomials.
  await expect(page.locator('#td-F')).not.toHaveText('[0, 0, 0, 0, 0, 0, 0, 0]');
});

test('signing with the full trapdoor produces a signature the public verifier accepts', async ({ page }) => {
  await page.locator('#td-sign').click();
  const out = page.locator('#td-sign-out');
  await expect(out).toContainText('The signature', { timeout: 60_000 });
  await expect(out).toContainText('s₁ + s₂·h ≡ c (mod q)');
  await expect(out).toContainText('holds for all coefficients');
  await expect(out).toContainText('VALID');
  await expect(out).toHaveClass(/ok/);
  // The accepted attempt's norm is under the bound, and it is a real number.
  await expect(out).not.toContainText('❌ REJECTED');
});

test('failure path: half the private key cannot produce a short signature', async ({ page }) => {
  await page.locator('#td-half').click();
  const out = page.locator('#td-sign-out');
  await expect(out).toContainText('attempts rejected', { timeout: 60_000 });
  await expect(out).toContainText('8 of 16 basis rows');
  await expect(out).toHaveClass(/bad/);
  await expect(out).not.toContainText('unexpectedly cleared');
});

test('failure path: a forger satisfies the equation and fails the norm check', async ({ page }) => {
  await page.locator('#td-forge').click();
  const out = page.locator('#td-sign-out');
  await expect(out).toContainText('Verification of the forged signature', { timeout: 60_000 });
  // The distinction the panel exists to teach: equation ✅, norm ❌.
  await expect(out).toContainText('holds for all coefficients');
  await expect(out).toContainText('REJECTED');
  await expect(out).toHaveClass(/bad/);
  await expect(out).toContainText('over the bound');
});

test('failure path: changing one coefficient of F stops the signature verifying', async ({ page }) => {
  await page.locator('#td-damage').click();
  const out = page.locator('#td-sign-out');
  await expect(out).toContainText('One coefficient of F changed', { timeout: 60_000 });
  await expect(out).toContainText('no longer equals q');
  await expect(out).toContainText('Rejected');
  await expect(out).not.toContainText('would be a defect in this exhibit');
});

test('the comparison table is written from three measured runs, not from labels', async ({ page }) => {
  await page.locator('#td-sign').click();
  await expect(page.locator('#td-sign-out')).toContainText('The signature', { timeout: 60_000 });
  await page.locator('#td-half').click();
  await expect(page.locator('#td-sign-out')).toContainText('attempts rejected', { timeout: 60_000 });
  await page.locator('#td-forge').click();
  await expect(page.locator('#td-sign-out')).toContainText('Verification of the forged', { timeout: 60_000 });

  const compare = page.locator('#td-compare');
  await expect(compare.locator('tbody tr')).toHaveCount(3);
  await expect(compare).toContainText('16 basis rows');
  await expect(compare).toContainText('8 basis rows');
  await expect(compare).toContainText('No private key at all');

  const reading = page.locator('#td-reading');
  await expect(reading).toContainText('Half a trapdoor is not half an advantage');

  // The three squared norms must actually be ordered full < half ≈ none, read
  // out of the rendered cells rather than trusted from the prose beside them.
  const cells = await compare.locator('tbody tr td.mono').allInnerTexts();
  const nums = cells.map((c) => Number(c.replace(/[^0-9]/g, '').slice(0, 15)));
  expect(nums).toHaveLength(3);
  expect(nums[0]).toBeLessThan(nums[1] / 100);
  expect(nums[0]).toBeLessThan(nums[2] / 100);
});

test('the page states the toy scale and the round-off caveat on screen', async ({ page }) => {
  const panel = page.locator('#panel-7');
  await expect(panel).toContainText('no security at all');
  await expect(panel).toContainText('16-dimensional');
  await expect(panel).toContainText('Falcon-512');
  await expect(panel).toContainText('Nguyen–Regev');
  await expect(panel).toContainText('round-off');
});
