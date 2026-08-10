import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * The desktop half, pinned rather than inherited.
 *
 * `playwright.config.ts` sets no viewport, so an unpinned test would run at
 * whatever Playwright's default happens to be — 1280x720 today, and silently
 * something else after an upgrade. A gate whose second configuration is "the
 * default" is a gate that does not know what it measured.
 */
export const WIDE = { width: 1280, height: 900 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this replaces
 *     called `addStyleTag({ content: '*{animation:none;transition:none}' })`
 *     before every scan, which BYPASSES this lab's own motion handling rather
 *     than exercising it — and that matters more here than usual, because all
 *     four of this lab's animation blocks are `@media (prefers-reduced-motion:
 *     no-preference)` and one of them (`attempt-in`) sets `opacity: 0` as its
 *     starting frame. If that block ever loses its media query, every
 *     rejection-sampling row renders invisible for a reader with the preference
 *     set, and an injected `animation: none` would hide exactly that. It also
 *     forced every `<details>` open by setting `d.open = true` from script
 *     instead of clicking the summary. Here reduced motion is requested through
 *     `emulateMedia` and then *asserted*, and the disclosure is opened by
 *     clicking it.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing — and nearly every result surface on this page (`#key-info`,
 *     `#sign-info`, `#attempts-info`, `#challenge-info`, `#verify-info`,
 *     `#forge-info`, `#paste-info`, `#real-falcon-info`, `#td-key`,
 *     `#td-sign-out`, `#td-compare`) is an empty `<div>` with
 *     `.output:empty { display: none }` until a button is pressed.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The spec this replaces
 *     drove one panel, force-opened the disclosure, checked ONE hand-rolled
 *     1.4.11 ratio (the `textarea` border against its own fill — the single
 *     place in the stylesheet where `--control-border` is used), and then
 *     scanned once with `violations` alone.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}


/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the lab's shipped defaults rather than assuming them.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is set through the same `localStorage` key the shared header's
 * toggle writes (`'theme'`) and the anti-flash script in `index.html` reads. If
 * those two ever drift apart the theme silently stops persisting, and asserting
 * `data-theme` after a seeded load is what would catch it.
 *
 * Note the inversion in this lab: `:root` holds the LIGHT palette and
 * `:root[data-theme='dark']` overrides it, while `index.html` stamps
 * `saved ?? 'dark'`. So the shipped default is dark, "light" is the bare
 * `:root` reached by a `data-theme` value that matches no override, and a gate
 * that scanned only the unstamped document would have measured the palette
 * nobody sees first.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is rendered from `src/ui.ts` into an empty `<main id="app">`,
  // so "the document loaded" and "there is anything to scan" are different
  // questions. Assert the seven panels and the hero exist before measuring.
  await expect(page.locator('#app .panel')).toHaveCount(8);
  for (const n of [1, 2, 3, 4, 5, 6, 7]) {
    await expect(page.locator(`#panel-${n}`)).toBeVisible();
  }
  await expect(page.locator('#message-input')).not.toBeEmpty();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender several times over: two comparison tables at
 * `min-width: 700px`, a key-size table at 400px, five polynomial dumps in
 * Panel 7, and an SVG lattice figure — all at a viewport of 380px.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. THIS LAB HAS THAT RULE
    // (`body { overflow-x: hidden }`, styles/main.css), so written the ordinary
    // way this oracle would be permanently green here. Detect the clipping
    // directly instead of trusting the scroll geometry.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // 700px table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This
    // page has six such wrappers, so without this filter every report would
    // name a decoy.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. With `body { overflow-x: hidden }` propagating to
      // the viewport, body itself answers "hidden" to this walk — so every
      // element on the page reads as clipped, `escaping` is always empty, and
      // the oracle reports nothing at all. A viewport-level clip is the DEFECT,
      // not a legitimate scroller; only a real scrolling container INSIDE the
      // page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab has six scroller shapes and not one of them holds anything
 * focusable: `.table-wrap` and `.key-size-table` wrap `min-width` tables,
 * `.viz` wraps the lattice SVG, and every `.output` is `overflow-x: auto`
 * around unbroken polynomial dumps. Only a driven state can see most of
 * them — the outputs are `display: none` until they have content.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 *
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set fails at the end via
 * `reportCollected`, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/** Run a throwing assertion, collecting instead of throwing when collecting. */
async function soft(run: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return run();
  try {
    await run();
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less `<div>` or `<span>` hides, a defect
 *    that never reaches the violations array at all and one this page has in
 *    quantity.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 *
 * Two classes have no oracle here at all and were measured by hand from
 * screenshot pixels instead: WCAG 1.4.11 non-text contrast, and generated
 * content. See the note at the top of `contrast.ts`.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await soft(() => expectNotBlank(page, label));
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * Seven panels, a guided tour and five quizzes, each with branches that only
 * exist after a button is pressed. The order below follows the page: lattice
 * playground (both bases, plus the empty state), parameter sets (both), keygen,
 * sign / verify / tamper, all three forgery paths, the paste-a-signature
 * disclosure with both a rejected and an accepted payload, both sampler modes
 * through both the histogram and the attack, real Falcon in WebAssembly, the
 * trapdoor panel's locked state and then all five of its steps, the tour, and
 * a right and a wrong answer in the quiz.
 *
 * Waits are on real completion signals — rendered output, a verdict string, a
 * button becoming enabled — never on a fixed timeout.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const S = (s: string): string => `${theme} / ${s}`;
  const out = (sel: string) => page.locator(sel);

  await scan(page, S('first paint'));

  // ---- the two skip links, which are off-screen until focused --------------
  // Both are styled on `:focus-visible`/`:focus`, so they are driven with real
  // Tab presses rather than `.focus()`: `.skip-link` moves only on
  // `:focus-visible`, which programmatic focus does not reliably match.
  await page.keyboard.press('Tab');
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await scan(page, S('shared header skip link focused'));
  // The lab's own skip link sits AFTER the shared header in the DOM, so it is
  // the sixth tab stop, not the second — a keyboard user reaches it only after
  // tabbing through the whole header it exists to skip. Tab until it is focused
  // rather than assuming a position, with a bound so a header change that made
  // it unreachable would fail rather than hang.
  for (let stops = 0; !(await page.locator('.skip-link').evaluate((e) => e === document.activeElement)); stops++) {
    expect(stops, 'the lab skip link must be reachable by Tab').toBeLessThan(12);
    await page.keyboard.press('Tab');
  }
  await expect(page.locator('.skip-link')).toBeFocused();
  expect(
    await page.locator('.skip-link').evaluate((e) => e.getBoundingClientRect().left),
    'focus must bring the lab skip link back on screen'
  ).toBeGreaterThan(-100);
  await scan(page, S('lab skip link focused'));
  await page.locator('.skip-link').blur();

  // ---- Panel 1: the lattice playground, both bases and the empty state -----
  await expect(page.locator('input[name="lattice-basis"][value="private"]')).toBeChecked();
  await page.locator('#lattice-random-btn').click();
  await expect(page.locator('#lattice-svg .target-x')).toHaveCount(1);
  await scan(page, S('panel 1 — random target, private short basis'));

  await page.locator('input[name="lattice-basis"][value="public"]').check();
  await expect(page.locator('#lattice-svg .basis-line.public').first()).toBeVisible();
  await scan(page, S('panel 1 — same target, public long basis'));

  await page.locator('#lattice-clear-btn').click();
  await expect(page.locator('#lattice-svg .target-x')).toHaveCount(0);
  await scan(page, S('panel 1 — target cleared'));
  await page.locator('input[name="lattice-basis"][value="private"]').check();

  // ---- Panel 2: both parameter sets, then a real keygen --------------------
  await expect(page.locator('input[name="paramset"][value="Falcon-512"]')).toBeChecked();
  await page.locator('input[name="paramset"][value="Falcon-1024"]').check();
  await expect(page.locator('#keygen-btn')).toContainText('Falcon-1024');
  await scan(page, S('panel 2 — Falcon-1024 selected'));
  await page.locator('input[name="paramset"][value="Falcon-512"]').check();
  await expect(page.locator('#keygen-btn')).toContainText('Falcon-512');

  await expect(out('#key-info')).toBeEmpty();
  await page.locator('#keygen-btn').click();
  await expect(out('#key-info')).toContainText('keypair ready', { timeout: 120_000 });
  await scan(page, S('panel 2 — keypair generated'));

  // ---- Panel 3: sign, verify, tamper, and all three forgery paths ----------
  await page.locator('#sign-btn').click();
  await expect(out('#sign-info')).toContainText('published sig size', { timeout: 120_000 });
  await expect(out('#attempts-info .attempt-row').first()).toBeVisible();
  await expect(out('#challenge-info .c-strip')).toBeVisible();
  await scan(page, S('panel 3 — signed: attempts, challenge strip, signature'));

  await page.locator('#verify-btn').click();
  await expect(out('#verify-info')).toContainText('Verified', { timeout: 120_000 });
  await scan(page, S('panel 3 — verify passes'));

  await page.locator('#tamper-btn').click();
  await expect(out('#verify-info')).toContainText('Rejected', { timeout: 120_000 });
  await scan(page, S('panel 3 — tampered message rejected'));

  for (const [id, expected, label] of [
    ['#forge-btn', 'Rejected', 'random s is not short enough'],
    ['#flip-btn', 'Coefficient s[', 'one coefficient nudged, the digest breaks'],
    ['#forge-pro-btn', 'It verified', "short s verifies \u2014 this build's own hole"],
  ] as const) {
    await page.locator(id).click();
    await expect(out('#forge-info')).toContainText(expected, { timeout: 120_000 });
    await scan(page, S(`panel 3 — ${id.slice(1)}: ${label}`));
  }

  // ---- Panel 3: the paste-a-signature disclosure, opened by clicking it ----
  const summary = page.locator('.paste-details summary');
  await summary.click();
  await expect(page.locator('.paste-details')).toHaveAttribute('open', '');
  await scan(page, S('panel 3 — paste disclosure open, input empty'));

  await page.locator('#paste-input').fill('not json at all');
  await page.locator('#paste-verify-btn').click();
  await expect(out('#paste-info')).not.toBeEmpty({ timeout: 120_000 });
  await scan(page, S('panel 3 — pasted payload rejected'));

  // ---- Panel 5: both sampler modes, histogram and attack -------------------
  await expect(page.locator('input[name="sampler-mode"][value="constant-time"]')).toBeChecked();
  for (const mode of ['constant-time', 'leaky'] as const) {
    await page.locator(`input[name="sampler-mode"][value="${mode}"]`).check();
    await page.locator('#sample-btn').click();
    await expect(page.locator('#timing-viz .histo-col').first()).toBeVisible({ timeout: 120_000 });
    await scan(page, S(`panel 5 — ${mode} sampler, timing histogram`));

    await page.locator('#attack-btn').click();
    await expect(page.locator('#attack-viz')).toContainText(
      mode === 'leaky' ? 'Attack succeeded' : 'Attack failed',
      { timeout: 180_000 }
    );
    await expect(page.locator('#attack-viz .attack-meter-fill').first()).toBeVisible();
    await expect(page.locator('#attack-viz .attack-spark-col').first()).toBeVisible();
    await scan(page, S(`panel 5 — ${mode} sampler, timing attack run`));
  }

  // ---- Panel 6: real Falcon-1024 in WebAssembly ----------------------------
  await page.locator('#real-falcon-btn').click();
  await expect(out('#real-falcon-info')).toContainText('\u2705 valid', { timeout: 300_000 });
  await expect(out('#real-falcon-info')).toContainText('rejected, as it must be');
  await scan(page, S('panel 6 — real Falcon-1024 run'));

  // ---- Panel 7: the locked state BEFORE the unlock, then all five steps ----
  for (const id of ['#td-sign', '#td-half', '#td-forge', '#td-damage']) {
    await expect(page.locator(id), `${id} must be locked until a key exists`).toBeDisabled();
  }
  await expect(out('#td-key')).toBeEmpty();
  await scan(page, S('panel 7 — trapdoor steps 2-5 locked'));

  await page.locator('#td-keygen').click();
  await expect(out('#td-key')).toContainText('Key generated', { timeout: 180_000 });
  for (const id of ['#td-sign', '#td-half', '#td-forge', '#td-damage']) {
    await expect(page.locator(id)).toBeEnabled();
  }
  await scan(page, S('panel 7 — real trapdoor key, NTRU equation solved'));

  for (const [id, needle, label] of [
    ['#td-sign', 'The signature', 'full trapdoor signs, verifier accepts'],
    ['#td-half', 'attempts rejected', 'only (f, g): 8 of 16 basis rows, no short vector'],
    ['#td-forge', 'Verification of the forged signature', 'no key: equation holds, norm fails'],
    ['#td-damage', 'One coefficient of F changed', 'damaged F, the signature stops verifying'],
  ] as const) {
    await page.locator(id).click();
    await expect(out('#td-sign-out')).toContainText(needle, { timeout: 180_000 });
    await scan(page, S(`panel 7 — ${label}`));
  }
  // The comparison table is written only once two of the three signers have
  // actually run — `comparisonHtml` returns '' below two rows — so it is a
  // state of its own, reached at the end of the sequence above rather than
  // after any single step.
  await expect(out('#td-compare')).toContainText('No private key at all');
  await expect(page.locator('#td-reading')).toBeVisible();
  await scan(page, S('panel 7 — three signers compared, measured'));

  // ---- the quiz: a wrong answer and a right one ---------------------------
  const wrong = page.locator('.quiz[data-quiz-id] .quiz-option[data-correct="false"]').first();
  await wrong.click();
  await expect(page.locator('.quiz-option.quiz-wrong').first()).toBeVisible();
  await expect(page.locator('.quiz-option.quiz-correct').first()).toBeVisible();
  await scan(page, S('quiz — wrong answer, both options marked'));

  const right = page
    .locator('.quiz[data-quiz-id]')
    .nth(1)
    .locator('.quiz-option[data-correct="true"]')
    .first();
  await right.click();
  await expect(page.locator('#quiz-score')).not.toBeEmpty();
  await scan(page, S('quiz — right answer, score chip populated'));

  // ---- the guided tour: a fixed dialog over the whole page -----------------
  await page.locator('#tour-btn').click();
  await expect(page.locator('.tour-card')).toBeVisible();
  await expect(page.locator('.tour-highlight')).toHaveCount(1);
  await scan(page, S('guided tour — step 1, panel highlighted'));

  await page.locator('.tour-card [data-tour="next"]').click();
  await expect(page.locator('.tour-progress')).toContainText('Step 2');
  await scan(page, S('guided tour — step 2'));

  await page.locator('.tour-card [data-tour="exit"]').click();
  await expect(page.locator('.tour-card')).toHaveCount(0);
  await expect(page.locator('.tour-highlight')).toHaveCount(0);
  await scan(page, S('guided tour — exited, highlight removed'));
}
