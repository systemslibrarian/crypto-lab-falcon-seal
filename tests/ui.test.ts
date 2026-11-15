// @vitest-environment jsdom
import { webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { comparisonRowsLevel1, comparisonRowsLevel5, FALCON_SIG_FOOTNOTE, references } from '../src/compare';
import { FALCON_512, FALCON_1024 } from '../src/falcon';

// jsdom ships getRandomValues but not crypto.subtle; the demo needs both.
Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });

let copiedJson = '';

beforeAll(() => {
  // Node's experimental localStorage global can shadow jsdom's and silently
  // reject writes; use a plain in-memory stub so persistence is testable.
  const store = new Map<string, string>();
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, String(v)),
      removeItem: (k: string) => void store.delete(k),
      clear: () => store.clear()
    }
  });
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    value: () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })
  });
  Element.prototype.scrollIntoView = () => {};
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: {
      writeText: async (text: string) => {
        copiedJson = text;
      }
    }
  });
});

async function waitFor(cond: () => boolean, timeout = 10000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeout) throw new Error('waitFor timed out');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function text(id: string): string {
  return document.getElementById(id)?.textContent ?? '';
}

describe('UI smoke test (jsdom)', () => {
  it('walks the full keygen → sign → verify → tamper → forge → paste-verify flow', async () => {
    const { renderApp } = await import('../src/ui');
    document.body.innerHTML = '<main id="app"></main>';
    const root = document.getElementById('app') as HTMLElement;
    renderApp(root);

    // Panels and controls exist.
    for (const id of ['panel-1', 'panel-2', 'panel-3', 'panel-4', 'panel-5', 'panel-6', 'tour-btn', 'attack-btn', 'forge-btn', 'paste-verify-btn', 'real-falcon-btn']) {
      expect(document.getElementById(id), `#${id} should exist`).toBeTruthy();
    }

    // Lattice playground: place a target, then switch to the public basis.
    document.getElementById('lattice-random-btn')?.click();
    await waitFor(() => document.querySelector('.target-x') !== null);
    const publicRadio = document.querySelector<HTMLInputElement>('input[name="lattice-basis"][value="public"]');
    publicRadio!.checked = true;
    publicRadio!.dispatchEvent(new Event('change'));
    await waitFor(() => document.querySelector('.basis-line.public') !== null);

    // Keygen.
    document.getElementById('keygen-btn')?.click();
    await waitFor(() => text('key-info').includes('keypair ready'), 30000);

    // Sign.
    document.getElementById('sign-form')?.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => text('sign-info').includes('published sig size'), 30000);
    expect(document.querySelector('.attempts-block')).toBeTruthy();
    /* The rejection-loop note explains the real bound by naming the σ Falcon
       samples signatures at. That σ differs between the parameter sets, so the
       note must interpolate the SELECTED set's figure. Default set is
       Falcon-512, whose σ is 165.736617183 (spec v1.2 Table 3.3). The page used
       to print 165.7 for either set, which is wrong for Falcon-1024's
       168.388571447. */
    const attemptsText = document.querySelector('.attempts-block')?.textContent ?? '';
    expect(attemptsText).toContain(`σ ≈ ${FALCON_512.publishedSignatureSigma.toFixed(2)}`);
    expect(attemptsText).toContain('σ ≈ 165.74');
    expect(document.querySelector('.c-strip')).toBeTruthy();

    // Verify.
    document.getElementById('verify-btn')?.click();
    await waitFor(() => text('verify-info').includes('Verified'));

    // Tamper test flips the verdict.
    document.getElementById('tamper-btn')?.click();
    await waitFor(() => text('verify-info').includes('Rejected'));

    // Forgery: recompute check passes, norm check fails, overall rejected.
    document.getElementById('forge-btn')?.click();
    await waitFor(() => text('forge-info').includes('Rejected'), 30000);
    expect(text('forge-info')).toContain('Norm check');

    // Copy as JSON, paste it back, verify against the embedded public key.
    document.getElementById('copy-btn')?.click();
    await waitFor(() => copiedJson.length > 0);
    const pasteInput = document.getElementById('paste-input') as HTMLTextAreaElement;
    pasteInput.value = copiedJson;
    document.getElementById('paste-verify-btn')?.click();
    await waitFor(() => text('paste-info').includes('fingerprint'), 30000);
    expect(text('paste-info')).toContain('Verified');

    // Timing lab: histogram runs, and the attack meter converges for the default mode.
    document.getElementById('sample-btn')?.click();
    await waitFor(() => document.querySelector('.histo') !== null);
    document.getElementById('attack-btn')?.click();
    await waitFor(() => text('attack-viz').includes('Attack'), 30000);

    // Quiz: answer the first question correctly, score persists to localStorage.
    const correctOption = document.querySelector<HTMLButtonElement>('.quiz[data-quiz-id="q1"] .quiz-option[data-correct="true"]');
    correctOption?.click();
    await waitFor(() => text('quiz-score').includes('Quiz score: 1/5'));
    expect(localStorage.getItem('falcon-seal-quiz-v1')).toContain('q1');
  }, 120000);
  it('qualifies Falcon signature sizes as variable-length and leaves the fixed ones bare', async () => {
    const { renderApp } = await import('../src/ui');
    document.body.innerHTML = '<main id="app"></main>';
    renderApp(document.getElementById('app') as HTMLElement);
    const html = document.body.innerHTML;

    // Falcon's quoted sizes are the PADDED constants; the raw signature is
    // variable. Measured over 20,000 signatures each with @noble/post-quantum
    // 0.7.1 (40 keys x 500): 647-664 B at n=512 and 1259-1284 B at n=1024. Those
    // are observed ranges, not bounds - both extremes widened when the sample
    // grew from 4,000, so a fixed interval is the wrong shape for this figure.
    // Falcon-1024 exceeded its padded 1,280 B in 20 of 20,000, so raw is NOT
    // always smaller than padded. Every
    // place the page prints one must say so, or the number reads as exact.
    for (const row of [...comparisonRowsLevel1, ...comparisonRowsLevel5]) {
      if (!/^Falcon/.test(row.parameterSet)) continue;
      expect(row.signatureNote, `${row.parameterSet} must carry a variable-length note`).toBeTruthy();
      expect(html).toContain(`\u2248${row.signatureBytes}<sup title="${row.signatureNote}">`);
    }

    // The footnote the markers resolve to is present and is the shared wording.
    expect(html).toContain(FALCON_SIG_FOOTNOTE);

    // ML-DSA and SLH-DSA signatures are exact and fixed: no note, no marker.
    for (const row of [...comparisonRowsLevel1, ...comparisonRowsLevel5]) {
      if (/^Falcon/.test(row.parameterSet)) continue;
      expect(row.signatureNote, `${row.parameterSet} must NOT be qualified`).toBeUndefined();
      expect(html).toContain(`<td>${row.signatureBytes}</td>`);
      expect(html).not.toContain(`\u2248${row.signatureBytes}`);
    }
  }, 60000);

  /* Figures and citations that were wrong on the page and are now pinned to a
     primary source. Each expectation below fails if its corrected value is
     removed, which is the only reason to assert a number the page merely
     prints. */
  it('pins the specification figures and citations the page used to get wrong', async () => {
    const { renderApp } = await import('../src/ui');
    document.body.innerHTML = '<main id="app"></main>';
    renderApp(document.getElementById('app') as HTMLElement);
    const html = document.body.innerHTML;

    /* Signatures' standard deviation, spec v1.2 Table 3.3. Two different
       figures: no single one covers both sets. */
    expect(FALCON_512.publishedSignatureSigma).toBe(165.736617183);
    expect(FALCON_1024.publishedSignatureSigma).toBe(168.388571447);
    expect(FALCON_1024.publishedSignatureSigma.toFixed(2)).toBe('168.39');
    expect(FALCON_512.publishedSignatureSigma).not.toBe(FALCON_1024.publishedSignatureSigma);

    /* Falcon-1024's PADDED signature length is 1,280 B (Table 3.3, sbytelen).
       1,330 is PQClean's CRYPTO_BYTES, the maximum of the VARIABLE-length
       compressed encoding. The page had the two the wrong way round. */
    expect(FALCON_1024.publishedSignatureBytes).toBe(1280);
    expect(html).toContain('padded</em> format is a fixed 1,280 B');
    expect(html).toContain('the <em>maximum</em> length that encoding can reach, not a padded format');
    expect(html).not.toContain('fixed-size <em>padded</em> signature format');
    expect(html).not.toContain('averages \u22481,280 B');

    /* HashToPoint (spec v1.2 section 3.7, Algorithm 3) outputs a polynomial
       uniform mod q in every coefficient. It is not sparse; the demo's own
       weight-40 c is a demo choice. */
    expect(html).toContain('challenge polynomial c whose every coefficient is uniform mod q');
    expect(html).not.toContain('derives a sparse challenge polynomial c');

    /* The constant-time sampler note is section 3.9.3 (Sampler over the
       Integers). Section 3.8 is Key Pair Generation. */
    expect(html).toContain('\u00a73.9.3');
    expect(html).not.toContain('\u00a73.8');

    /* Falcon timings are the specification's own reference-implementation
       table (v1.2 section 4.5), not unsourced constants 25-60x above it. */
    const falconRows = [...comparisonRowsLevel1, ...comparisonRowsLevel5].filter((r) => /^Falcon/.test(r.parameterSet));
    expect(falconRows).toHaveLength(2);
    const [f512, f1024] = falconRows;
    expect([f512.keygenTimeMs, f512.signTimeMs, f512.verifyTimeMs]).toEqual([8.64, 0.17, 0.036]);
    expect([f1024.keygenTimeMs, f1024.signTimeMs, f1024.verifyTimeMs]).toEqual([27.45, 0.34, 0.073]);
    expect(html).toContain('<td>0.17</td>');
    expect(html).toContain('<td>0.036</td>');
    expect(html).toContain('Falcon v1.2 \u00a74.5');

    /* The specification's title page lists ten authors; Tibouchi and Wallet
       are not among them. */
    const specRef = references.find((r) => r.startsWith('Falcon specification v1.2'));
    expect(specRef).toBeTruthy();
    for (const name of ['Fouque', 'Hoffstein', 'Kirchner', 'Lyubashevsky', 'Pornin', 'Prest', 'Ricosset', 'Seiler', 'Whyte', 'Zhang']) {
      expect(specRef, `${name} is on the title page`).toContain(name);
    }
    expect(specRef).not.toContain('Tibouchi');
    expect(specRef).not.toContain('Wallet');

    /* The FIPS 206 status claim carries the date it was checked. */
    expect(html).toContain('As of 15 November 2026 FIPS 206 has no published draft');
    expect(html).not.toContain('FIPS 206 has not been drafted yet');
  }, 60000);
});
