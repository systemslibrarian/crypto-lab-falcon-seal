// @vitest-environment jsdom
import { webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';

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
});
