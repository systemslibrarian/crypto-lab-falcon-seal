import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW, WIDE, reportCollected } from './gate';

/**
 * WCAG gate for Falcon Seal.
 *
 * Four configurations — {dark, light} x {1280, 380} — because this lab's two
 * palettes are genuinely different stylesheets' worth of colour (`:root` is the
 * light one, `:root[data-theme='dark']` re-specifies fourteen tokens), and
 * because almost everything on the page has a `min-width` that only matters at
 * phone width: two comparison tables at 700px, a key-size table at 400px, an
 * SVG lattice figure, and five polynomial dumps in Panel 7.
 *
 * The spec this replaces ran two configurations, both at the default viewport,
 * and its whole drive was Panel 7. It injected
 * `*{animation:none;transition:none}` before scanning, forced every `<details>`
 * open from script, checked one hand-rolled 1.4.11 ratio on the one control the
 * stylesheet's `--control-border` token is actually used on, and then scanned
 * once with axe's `violations` array.
 *
 * `test.setTimeout` is generous because the drive scans after every step, each
 * scan runs axe plus a full composite-aware contrast walk, and Panel 6 compiles
 * and runs reference Falcon-1024 in WebAssembly.
 */

test.setTimeout(900_000);

test.describe('desktop viewport', () => {
  test.use({ viewport: WIDE });

  for (const theme of ['dark', 'light'] as const) {
    test(`WCAG gate — ${theme}, 1280px`, async ({ page }) => {
      await boot(page, theme);
      await driveAllStates(page, `${theme}/1280`);
      reportCollected();
    });
  }
});

test.describe('narrow viewport', () => {
  test.use({ viewport: NARROW });

  for (const theme of ['dark', 'light'] as const) {
    test(`WCAG gate — ${theme}, 380px`, async ({ page }) => {
      await boot(page, theme);
      await driveAllStates(page, `${theme}/380`);
      reportCollected();
    });
  }
});
