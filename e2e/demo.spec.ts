import { expect, test } from '@playwright/test';

test('full demo flow in a real browser, including the WASM panel', async ({ page }) => {
  await page.goto('./');
  await expect(page.locator('h1')).toHaveText('Falcon Seal');

  // Guided tour opens and closes.
  await page.locator('#tour-btn').click();
  await expect(page.locator('.tour-card')).toBeVisible();
  await expect(page.locator('.tour-progress')).toContainText('Step 1 of');
  await page.keyboard.press('Escape');
  await expect(page.locator('.tour-card')).toHaveCount(0);

  // Lattice playground: click places a target; the public basis misses more.
  await page.locator('#lattice-svg').click({ position: { x: 200, y: 100 } });
  await expect(page.locator('.target-x')).toBeVisible();
  await expect(page.locator('.babai-snap')).toBeVisible();
  await page.locator('input[name="lattice-basis"][value="public"]').check();
  await expect(page.locator('.basis-line.public').first()).toBeVisible();

  // Keyboard nudge keeps working across SVG re-renders.
  await page.locator('#lattice-svg').focus();
  await page.keyboard.press('ArrowRight');
  await page.keyboard.press('ArrowUp');
  await expect(page.locator('.target-x')).toBeVisible();

  // Keygen (real NTT inversion).
  await page.locator('#keygen-btn').click();
  await expect(page.locator('#key-info')).toContainText('keypair ready', { timeout: 60_000 });

  // Sign → rejection attempts + challenge strip render.
  await page.locator('#sign-btn').click();
  await expect(page.locator('#sign-info')).toContainText('published sig size', { timeout: 60_000 });
  await expect(page.locator('.attempts-block')).toBeVisible();
  await expect(page.locator('.c-strip')).toBeVisible();

  // Verify, then tamper.
  await page.locator('#verify-btn').click();
  await expect(page.locator('#verify-info')).toContainText('Verified');
  await page.locator('#tamper-btn').click();
  await expect(page.locator('#verify-info')).toContainText('Rejected');

  // Naive forgery fails; the "pro" forgery exposes the toy scheme by design.
  await page.locator('#forge-btn').click();
  await expect(page.locator('#forge-info')).toContainText('Rejected', { timeout: 30_000 });
  await page.locator('#forge-pro-btn').click();
  await expect(page.locator('#forge-info')).toContainText('It verified', { timeout: 30_000 });

  // Timing lab: histogram, then the attack flatlines against constant-time.
  await page.locator('#sample-btn').click();
  await expect(page.locator('.histo')).toBeVisible();
  await page.locator('#attack-btn').click();
  await expect(page.locator('#attack-viz')).toContainText('Attack failed', { timeout: 60_000 });

  // ...and succeeds against the leaky sampler.
  await page.locator('input[name="sampler-mode"][value="leaky"]').check();
  await page.locator('#attack-btn').click();
  await expect(page.locator('#attack-viz')).toContainText('Attack succeeded', { timeout: 60_000 });

  // Quiz scoring persists.
  await page.locator('.quiz[data-quiz-id="q1"] .quiz-option[data-correct="true"]').click();
  await expect(page.locator('#quiz-score')).toContainText('Quiz score: 1/5');

  // Panel 6: the real Falcon-1024 reference implementation in WebAssembly.
  await page.locator('#real-falcon-btn').click();
  await expect(page.locator('#real-falcon-info')).toContainText('✅ valid', { timeout: 150_000 });
  await expect(page.locator('#real-falcon-info')).toContainText('rejected, as it must be');

  // Visual record of both themes.
  await page.screenshot({ path: 'test-results/screenshot-dark.png', fullPage: true });
  await page.locator('#cl-theme-toggle').click();
  await page.screenshot({ path: 'test-results/screenshot-light.png', fullPage: true });
});
