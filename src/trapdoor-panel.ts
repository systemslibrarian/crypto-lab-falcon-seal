/**
 * Panel 7 — real trapdoor signing at toy scale.
 *
 * Everything rendered here is computed by `src/trapdoor.ts` from the key the
 * learner just generated: the NTRU equation's left-hand side coefficient by
 * coefficient, the measured squared norms of every signing attempt, the
 * verification equation's mismatch count. Nothing is narrated in advance and
 * nothing is switched on which button was pressed — the four rows of the
 * comparison table all come from the same measurement, so the "trapdoor helps"
 * conclusion is a reading of four numbers rather than a caption.
 */

import {
  TOY_BOUND_SQ,
  TOY_N,
  TOY_Q,
  TOY_SIGMA,
  damageTrapdoor,
  forgeWithoutTrapdoor,
  generateTrapdoorKey,
  signWithTrapdoor,
  strippedBasis,
  trapdoorBasis,
  verifyTrapdoor,
  type ForgeResult,
  type TrapdoorKeyPair,
  type TrapdoorSignResult,
  type TrapdoorVerifyResult
} from './trapdoor';

type PanelState = {
  key: TrapdoorKeyPair | null;
  full: TrapdoorSignResult | null;
  fullVerify: TrapdoorVerifyResult | null;
  half: TrapdoorSignResult | null;
  forged: ForgeResult | null;
  damagedVerify: TrapdoorVerifyResult | null;
  damagedSigned: boolean;
};

const state: PanelState = {
  key: null,
  full: null,
  fullVerify: null,
  half: null,
  forged: null,
  damagedVerify: null,
  damagedSigned: false
};

const fmt = (v: bigint | number): string => v.toLocaleString('en-US');
const poly = (p: bigint[] | number[]): string => `[${p.map((x) => String(x)).join(', ')}]`;

export function trapdoorPanelHtml(): string {
  return `
      <section class="panel" id="panel-7" aria-labelledby="p7-title">
        <h2 id="p7-title">Panel 7 — Real trapdoor signing (toy n = ${TOY_N})</h2>
        <p>
          Panels 2 and 3 run an illustrative flow that, as it says there, <strong>never reads the private key</strong>.
          This panel is the mechanism that flow is missing. It samples (f, g) from Falcon's own key distribution
          (σ = 1.17·√(q/2n) = ${TOY_SIGMA.toFixed(2)} at this n), then <strong>solves the NTRU equation
          f·G − g·F = q</strong> exactly, in BigInt arithmetic, for the trapdoor completion (F, G). Signing is Babai
          round-off against the resulting ${2 * TOY_N}-dimensional basis; verification is Falcon's real equation
          <code class="mono">s₁ + s₂·h ≡ c (mod q)</code> together with the norm bound. The private key is
          load-bearing here, and the buttons below take it away in two different ways to show it.
        </p>
        <p class="small-note">
          <strong>Scale, plainly:</strong> n = ${TOY_N} and q = ${TOY_Q}, so the lattice is ${2 * TOY_N}-dimensional.
          Falcon-512's is 1,024-dimensional. This one offers <strong>no security at all</strong> — LLL would recover
          the trapdoor from h in milliseconds. It is a mechanism exhibit, not a cipher.
          It also uses Babai <strong>round-off</strong>, not Falcon's fast-Fourier Gaussian sampler. Round-off is the
          NTRUSign approach and it <em>leaks</em>: each signature is a point in the fundamental parallelepiped of the
          secret basis, so a few thousand of them recover the private key (Nguyen–Regev, Eurocrypt 2006). Replacing it
          with discrete Gaussian sampling is exactly why Falcon exists, and that replacement is the one piece of Falcon
          this panel does not implement.
        </p>

        <div class="actions" aria-label="Trapdoor controls">
          <button id="td-keygen" class="btn" type="button">1 · Generate a real trapdoor key</button>
          <button id="td-sign" class="btn" type="button" disabled>2 · Sign with the full trapdoor</button>
          <button id="td-half" class="btn" type="button" disabled>3 · Sign with only (f, g)</button>
          <button id="td-forge" class="btn" type="button" disabled>4 · Forge with no private key</button>
          <button id="td-damage" class="btn" type="button" disabled>5 · Damage one coefficient of F</button>
        </div>

        <div id="td-key" class="output" aria-live="polite" aria-label="Trapdoor key generation result"></div>
        <div id="td-sign-out" class="output" aria-live="polite" aria-label="Trapdoor signing result"></div>
        <div id="td-compare" class="output" aria-live="polite" aria-label="Comparison of signer capabilities"></div>
      </section>`;
}

function keyHtml(key: TrapdoorKeyPair): string {
  const lhs = key.equationLhs;
  const wanted = [BigInt(key.q), ...new Array(key.n - 1).fill(0n)];
  const rows = lhs
    .map(
      (v, i) =>
        `<tr><th scope="row">x<sup>${i}</sup></th><td class="mono">${v}</td><td class="mono">${wanted[i]}</td><td>${
          v === wanted[i] ? '✅' : '❌'
        }</td></tr>`
    )
    .join('');
  return `
    <p><strong>Key generated.</strong> ${key.keygenAttempts === 1 ? 'The first' : `Draw ${key.keygenAttempts} of`} (f, g)
    gave coprime resultants, so the NTRU equation was solvable.</p>
    <div class="table-wrap">
      <table>
        <caption>Private basis, computed just now (coefficients in Z[x]/(x<sup>${key.n}</sup>+1))</caption>
        <tbody>
          <tr><th scope="row">f</th><td class="mono" id="td-f">${poly(key.f)}</td></tr>
          <tr><th scope="row">g</th><td class="mono">${poly(key.g)}</td></tr>
          <tr><th scope="row">F <em>(solved)</em></th><td class="mono" id="td-F">${poly(key.F)}</td></tr>
          <tr><th scope="row">G <em>(solved)</em></th><td class="mono">${poly(key.G)}</td></tr>
          <tr><th scope="row">h <em>(public)</em></th><td class="mono">${poly(key.h)}</td></tr>
        </tbody>
      </table>
    </div>
    <div class="table-wrap">
      <table>
        <caption>The NTRU equation f·G − g·F, evaluated coefficient by coefficient</caption>
        <thead><tr><th scope="col">Term</th><th scope="col">Computed</th><th scope="col">Required</th><th scope="col"></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p id="td-eq-verdict">${
      key.equationHolds
        ? `✅ <strong>f·G − g·F = q exactly.</strong> (F, G) is a genuine trapdoor completion, so the basis has all ${
            2 * key.n
          } rows.`
        : '❌ <strong>The NTRU equation does NOT hold.</strong> This basis spans the wrong lattice and nothing signed with it will verify.'
    }</p>
    <p class="small-note">
      ‖(g, −f)‖² = ${fmt(key.shortBasisNormSq)} · ‖(G, −F)‖² = ${fmt(key.completionNormSq)}.
      Both are far below q² = ${fmt(TOY_Q * TOY_Q)}, which is what makes round-off land close to the target.
    </p>`;
}

function attemptsHtml(result: TrapdoorSignResult, title: string): string {
  const rows = result.attempts
    .map(
      (a) =>
        `<tr><th scope="row">${a.attempt}</th><td class="mono">${fmt(a.normSq)}</td><td>${
          a.accepted ? '✅ accepted' : '❌ over the bound'
        }</td></tr>`
    )
    .join('');
  return `
    <div class="table-wrap">
      <table>
        <caption>${title} — every attempt's measured ‖s‖², bound β² = ${fmt(TOY_BOUND_SQ)}</caption>
        <thead><tr><th scope="col">Attempt</th><th scope="col">‖s‖² (measured)</th><th scope="col">Verdict</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function verifyHtml(v: TrapdoorVerifyResult, label: string): string {
  return `
    <div class="table-wrap">
      <table>
        <caption>${label} — verified with h alone</caption>
        <thead><tr><th scope="col">Check</th><th scope="col">Result</th></tr></thead>
        <tbody>
          <tr><th scope="row">s₁ + s₂·h ≡ c (mod q)</th><td>${
            v.equationOk ? '✅ holds for all coefficients' : `❌ fails on ${v.mismatches} of ${TOY_N} coefficients`
          }</td></tr>
          <tr><th scope="row">‖(s₁, s₂)‖² ≤ β²</th><td>${
            v.normOk ? `✅ ${fmt(v.normSq)} ≤ ${fmt(v.bound)}` : `❌ ${fmt(v.normSq)} &gt; ${fmt(v.bound)}`
          }</td></tr>
          <tr><th scope="row">Overall</th><td>${v.overall ? '✅ <strong>VALID</strong>' : '❌ <strong>REJECTED</strong>'}</td></tr>
        </tbody>
      </table>
    </div>`;
}

function comparisonHtml(): string {
  const rows: Array<[string, string, string]> = [];
  if (state.full?.signature) {
    rows.push([
      `Full trapdoor (f, g, F, G) — ${2 * TOY_N} basis rows`,
      fmt(state.full.signature.normSq),
      state.fullVerify?.overall ? '✅ accepted' : '❌ rejected'
    ]);
  }
  if (state.half) {
    rows.push([
      `Half the private key — (f, g) only, ${TOY_N} basis rows`,
      state.half.bestNormSq === null ? '—' : `${fmt(state.half.bestNormSq)} (best of ${state.half.attempts.length})`,
      state.half.signature ? '✅ accepted' : '❌ rejected — every attempt over the bound'
    ]);
  }
  if (state.forged) {
    rows.push([
      'No private key at all — forger',
      `${fmt(state.forged.bestNormSq)} (best of ${state.forged.tries})`,
      '❌ rejected — equation holds, norm does not'
    ]);
  }
  if (rows.length < 2) return '';

  const body = rows
    .map(([who, norm, verdict]) => `<tr><th scope="row">${who}</th><td class="mono">${norm}</td><td>${verdict}</td></tr>`)
    .join('');

  let reading = '';
  if (state.full?.signature && state.half?.bestNormSq && state.forged) {
    const trapdoorAdvantage = Number(state.half.bestNormSq) / Number(state.full.signature.normSq);
    const halfVsNone = Number(state.half.bestNormSq) / Number(state.forged.bestNormSq);
    reading = `<p id="td-reading">Read off the three numbers above: the full trapdoor produced a vector
      <strong>${trapdoorAdvantage.toFixed(0)}×</strong> shorter in squared norm than the best half-key attempt, while the
      half-key signer came within <strong>${halfVsNone.toFixed(1)}×</strong> of someone holding no key whatsoever.
      Half a trapdoor is not half an advantage; it is none. That gap is the entire security argument, and it is the
      thing the illustrative flow in Panel 3 cannot show, because that flow never reads the private key at all.</p>`;
  }

  return `
    <div class="table-wrap">
      <table>
        <caption>Same public key, same message, same verifier — three signers, measured</caption>
        <thead><tr><th scope="col">Signer</th><th scope="col">Shortest ‖s‖² achieved</th><th scope="col">Verifier's answer</th></tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>${reading}`;
}

function setHtml(id: string, html: string, tone: 'ok' | 'warn' | 'bad' | null): void {
  const host = document.getElementById(id);
  if (!host) return;
  host.classList.remove('ok', 'warn', 'bad');
  if (tone) host.classList.add(tone);
  host.innerHTML = html;
}

export function wireTrapdoorPanel(root: HTMLElement, getMessage: () => string): void {
  const keygenBtn = root.querySelector<HTMLButtonElement>('#td-keygen');
  const signBtn = root.querySelector<HTMLButtonElement>('#td-sign');
  const halfBtn = root.querySelector<HTMLButtonElement>('#td-half');
  const forgeBtn = root.querySelector<HTMLButtonElement>('#td-forge');
  const damageBtn = root.querySelector<HTMLButtonElement>('#td-damage');
  if (!keygenBtn || !signBtn || !halfBtn || !forgeBtn || !damageBtn) return;

  const enableAfterKey = () => {
    signBtn.disabled = false;
    halfBtn.disabled = false;
    forgeBtn.disabled = false;
    damageBtn.disabled = false;
  };

  const refreshComparison = () => setHtml('td-compare', comparisonHtml(), null);

  keygenBtn.addEventListener('click', () => {
    state.full = null;
    state.fullVerify = null;
    state.half = null;
    state.forged = null;
    state.damagedVerify = null;
    state.damagedSigned = false;
    setHtml('td-sign-out', '', null);
    setHtml('td-compare', '', null);
    try {
      state.key = generateTrapdoorKey();
    } catch (err) {
      setHtml('td-key', `<p>Key generation failed: ${err instanceof Error ? err.message : 'unknown error'}</p>`, 'bad');
      return;
    }
    setHtml('td-key', keyHtml(state.key), state.key.equationHolds ? 'ok' : 'bad');
    enableAfterKey();
  });

  signBtn.addEventListener('click', async () => {
    if (!state.key) return;
    const message = getMessage();
    state.full = await signWithTrapdoor(state.key, message, trapdoorBasis(state.key));
    state.fullVerify = state.full.signature
      ? await verifyTrapdoor(state.key.h, message, state.full.signature)
      : null;
    const sig = state.full.signature;
    setHtml(
      'td-sign-out',
      `${attemptsHtml(state.full, `Signing “${message}” with all ${state.full.basisRows} basis rows`)}
       ${
         sig
           ? `<div class="table-wrap"><table>
                <caption>The signature</caption>
                <tbody>
                  <tr><th scope="row">nonce</th><td class="mono">${sig.nonceHex}</td></tr>
                  <tr><th scope="row">s₁</th><td class="mono">${poly(sig.s1)}</td></tr>
                  <tr><th scope="row">s₂</th><td class="mono">${poly(sig.s2)}</td></tr>
                  <tr><th scope="row">‖s‖²</th><td class="mono">${fmt(sig.normSq)}</td></tr>
                </tbody></table></div>
              ${state.fullVerify ? verifyHtml(state.fullVerify, 'Verification') : ''}`
           : '<p>❌ No attempt cleared the bound. With the full basis this is rare; press again.</p>'
       }`,
      state.fullVerify?.overall ? 'ok' : 'bad'
    );
    refreshComparison();
  });

  halfBtn.addEventListener('click', async () => {
    if (!state.key) return;
    const message = getMessage();
    state.half = await signWithTrapdoor(state.key, message, strippedBasis(state.key));
    setHtml(
      'td-sign-out',
      `<p><strong>Signing with (f, g) only.</strong> The signer keeps half the private key and loses the
        ${TOY_N} rows that (F, G) contributed, so the basis spans a ${state.half.basisRows}-dimensional
        sublattice of a ${2 * TOY_N}-dimensional one. Round-off still lands in the right coset — the
        verification equation will still hold — but it cannot cancel the target's components in the
        directions the missing rows spanned.</p>
       ${attemptsHtml(state.half, `Signing “${message}” with ${state.half.basisRows} of ${2 * TOY_N} basis rows`)}
       <p>${
         state.half.signature
           ? '⚠️ An attempt unexpectedly cleared the bound.'
           : `❌ <strong>All ${state.half.attempts.length} attempts rejected.</strong> Shortest achieved: ‖s‖² = ${fmt(
               state.half.bestNormSq ?? 0n
             )}, against a bound of ${fmt(TOY_BOUND_SQ)}.`
       }</p>`,
      state.half.signature ? 'warn' : 'bad'
    );
    refreshComparison();
  });

  forgeBtn.addEventListener('click', async () => {
    if (!state.key) return;
    const message = getMessage();
    state.forged = await forgeWithoutTrapdoor(state.key.h, message, TOY_N, TOY_Q, 200);
    const v = await verifyTrapdoor(state.key.h, message, state.forged.signature);
    setHtml(
      'td-sign-out',
      `<p><strong>Forging with h alone.</strong> Anyone can satisfy the verification <em>equation</em>: pick s₂ freely,
        then set s₁ = c − s₂·h (mod q). The forger below did that ${state.forged.tries} times and kept the shortest
        result. Note which check catches it.</p>
       ${verifyHtml(v, 'Verification of the forged signature')}
       <p>Best of ${state.forged.tries} forgery attempts: ‖s‖² = ${fmt(state.forged.bestNormSq)} —
       ${(Number(state.forged.bestNormSq) / Number(TOY_BOUND_SQ)).toFixed(0)}× over the bound. Trying harder does not
       help: s₁ is forced to be uniform over the whole of [−q/2, q/2), so the norm is set by q, not by effort.
       Making it short is the lattice problem, and the trapdoor is the only known shortcut.</p>`,
      'bad'
    );
    refreshComparison();
  });

  damageBtn.addEventListener('click', async () => {
    if (!state.key) return;
    const message = getMessage();
    const damaged = damageTrapdoor(state.key, 3, 7n);
    const signed = await signWithTrapdoor(damaged, message, trapdoorBasis(damaged));
    state.damagedSigned = signed.signature !== null;
    state.damagedVerify = signed.signature
      ? await verifyTrapdoor(state.key.h, message, signed.signature)
      : null;
    const lhs = damaged.equationLhs;
    setHtml(
      'td-sign-out',
      `<p><strong>One coefficient of F changed (F[3] += 7), nothing else touched.</strong> This is the check that the
        private key is load-bearing: if signing ignored it, the signature would be unaffected.</p>
       <p>f·G − g·F is now <code class="mono">${poly(lhs)}</code>, which ${
         damaged.equationHolds ? 'still equals q' : `no longer equals q = ${TOY_Q}`
       }, so the second half of the basis no longer lies in the lattice.</p>
       ${
         signed.signature
           ? `${attemptsHtml(signed, 'Signing with the damaged trapdoor')}
              ${state.damagedVerify ? verifyHtml(state.damagedVerify, 'Verification against the UNDAMAGED public key') : ''}`
           : `<p>No attempt cleared the bound with the damaged basis (best ‖s‖² = ${fmt(
               signed.bestNormSq ?? 0n
             )}), so there is nothing to present to the verifier.</p>`
       }
       <p>${
         state.damagedVerify && !state.damagedVerify.overall
           ? `✅ <strong>Rejected</strong>${
               state.damagedVerify.equationOk
                 ? ' on the norm check.'
                 : ` — the equation failed on ${state.damagedVerify.mismatches} of ${TOY_N} coefficients.`
             } Change seven in one coefficient of the private key and the signature stops verifying. That is what it means for signing to depend on the key.`
           : state.damagedVerify
             ? '⚠️ The damaged key still produced a verifying signature, which would be a defect in this exhibit.'
             : '✅ The damaged key could not even produce a candidate signature.'
       }</p>`,
      state.damagedVerify?.overall ? 'warn' : 'bad'
    );
  });
}
