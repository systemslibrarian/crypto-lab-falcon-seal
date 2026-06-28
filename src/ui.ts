import { comparisonRowsLevel1, comparisonRowsLevel5, references, type SignatureRow } from './compare';
import {
  PARAMETER_SETS,
  generateFalconKeyPair,
  signFalconIllustrative,
  signatureToJson,
  summarizeSignature,
  verifyFalconIllustrative,
  type FalconKeyPair,
  type FalconParameterSet,
  type FalconParameterSetName,
  type SignResult,
  type VerifyResult
} from './falcon';
import {
  DEFAULT_BASIS_2D,
  buildLatticePoints,
  projectShortBasis,
  projectSignatureVector,
  simulateSamplerTimings,
  type Basis2D,
  type SamplerMode,
  type TimingSample
} from './ntru';

type UIState = {
  parameterSetName: FalconParameterSetName;
  keyPair: FalconKeyPair | null;
  signResult: SignResult | null;
  verifyResult: VerifyResult | null;
  signedMessage: string;
  message: string;
  samplerMode: SamplerMode;
};

const state: UIState = {
  parameterSetName: 'Falcon-512',
  keyPair: null,
  signResult: null,
  verifyResult: null,
  signedMessage: '',
  message: 'Falcon keeps signatures compact for bandwidth-constrained links.',
  samplerMode: 'constant-time'
};

function currentSet(): FalconParameterSet {
  return PARAMETER_SETS[state.parameterSetName];
}

function bytesBar(value: number, max: number): string {
  const pct = Math.max(4, Math.round((value / max) * 100));
  return `<div class="bar-wrap" aria-label="bar for ${value} bytes"><div class="bar" style="width:${pct}%"></div><span>${value} B</span></div>`;
}

function tableRows(rows: SignatureRow[]): string {
  return rows
    .map(
      (r) => `
      <tr>
        <th scope="row">${r.parameterSet}</th>
        <td>${r.publicKeyBytes}</td>
        <td>${r.signatureBytes}</td>
        <td>${r.keygenTimeMs}</td>
        <td>${r.signTimeMs}</td>
        <td>${r.verifyTimeMs}</td>
        <td>${r.securityAssumption}</td>
        <td>${r.implementationComplexity}</td>
      </tr>
    `
    )
    .join('');
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function latticeSvg(): string {
  const keyPair = state.keyPair;
  const basis: Basis2D = keyPair ? projectShortBasis(keyPair.privateKey.f, keyPair.privateKey.g) : DEFAULT_BASIS_2D;
  const safeBasis: Basis2D = {
    ax: Math.max(-120, Math.min(120, basis.ax || DEFAULT_BASIS_2D.ax)),
    ay: Math.max(-120, Math.min(120, basis.ay || DEFAULT_BASIS_2D.ay)),
    bx: Math.max(-120, Math.min(120, basis.bx || DEFAULT_BASIS_2D.bx)),
    by: Math.max(-120, Math.min(120, basis.by || DEFAULT_BASIS_2D.by))
  };
  const points = buildLatticePoints(safeBasis);
  const circles = points
    .map((p) => {
      const cx = 150 + p.x;
      const cy = 150 - p.y;
      const cls = p.short ? 'lattice-point short' : 'lattice-point';
      return `<circle class="${cls}" cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="3" />`;
    })
    .join('');

  const basisLineA = `<line x1="150" y1="150" x2="${150 + safeBasis.ax}" y2="${150 - safeBasis.ay}" class="basis-line${keyPair ? ' private' : ''}" />`;
  const basisLineB = `<line x1="150" y1="150" x2="${150 + safeBasis.bx}" y2="${150 - safeBasis.by}" class="basis-line${keyPair ? ' private' : ''}" />`;

  let sigOverlay = '';
  if (state.signResult) {
    const v = projectSignatureVector(state.signResult.signature.s);
    const sx = Math.max(-130, Math.min(130, v.x));
    const sy = Math.max(-130, Math.min(130, v.y));
    sigOverlay = `
      <line x1="150" y1="150" x2="${150 + sx}" y2="${150 - sy}" class="sig-vector" />
      <circle cx="${150 + sx}" cy="${150 - sy}" r="6" class="sig-point" />
      <text x="${150 + sx + 8}" y="${150 - sy - 6}" class="svg-label">s (projected)</text>
    `;
  }

  const targetX = 188;
  const targetY = 74;
  const targetMarker = keyPair
    ? ''
    : `<circle cx="${targetX}" cy="${targetY}" r="7" class="target" /><text x="${targetX + 6}" y="${targetY - 8}" class="svg-label">short-vector target</text>`;

  const caption = keyPair
    ? state.signResult
      ? 'Green basis lines: projection of your private short basis (f, g). Orange dot: signature vector s (projected).'
      : 'Green basis lines: projection of your private short basis (f, g) — the trapdoor. Generate a signature to see where s lands.'
    : 'Green dots: lattice points. Orange dots: short vectors near the origin. Red dot: shortest-vector target. Lines: a generic short basis.';

  return `
    <svg
      class="lattice"
      viewBox="0 0 300 300"
      role="img"
      aria-label="Two-dimensional lattice visualization"
    >
      <rect x="0" y="0" width="300" height="300" class="lattice-bg"></rect>
      ${basisLineA}
      ${basisLineB}
      <circle cx="150" cy="150" r="6" class="origin" />
      ${circles}
      ${targetMarker}
      ${sigOverlay}
    </svg>
    <p class="small-note" aria-label="Lattice visualization legend">${caption}</p>
  `;
}

function renderComparisonBars(): string {
  const rows = [...comparisonRowsLevel1, ...comparisonRowsLevel5];
  const max = Math.max(...rows.map((r) => r.signatureBytes));
  return rows
    .map(
      (r) => `
      <div class="bar-row" aria-label="Signature size bar for ${r.parameterSet}">
        <div class="bar-title">${r.parameterSet}</div>
        ${bytesBar(r.signatureBytes, max)}
      </div>
    `
    )
    .join('');
}

function renderVisceralSize(): string {
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(state.message || '').length;
  const items: { label: string; sigBytes: number }[] = [
    { label: 'Falcon-512', sigBytes: 666 },
    { label: 'Falcon-1024', sigBytes: 1280 },
    { label: 'ML-DSA-44', sigBytes: 2420 },
    { label: 'ML-DSA-87', sigBytes: 4627 },
    { label: 'SLH-DSA-128s', sigBytes: 7856 }
  ];
  const max = items[items.length - 1].sigBytes + msgBytes;
  return items
    .map((it) => {
      const msgPct = Math.max(0.4, (msgBytes / max) * 100);
      const sigPct = (it.sigBytes / max) * 100;
      const ratio = msgBytes === 0 ? '∞' : (it.sigBytes / Math.max(1, msgBytes)).toFixed(1);
      return `
        <div class="vsize-row" aria-label="Size comparison for ${it.label}">
          <div class="vsize-title">${it.label} <span class="vsize-ratio">sig is ${ratio}× your message</span></div>
          <div class="vsize-strip">
            <div class="vsize-msg" style="width:${msgPct}%" title="${msgBytes} B message"></div>
            <div class="vsize-sig" style="width:${sigPct}%" title="${it.sigBytes} B signature"></div>
            <span class="vsize-label">${msgBytes} B msg · ${it.sigBytes} B sig</span>
          </div>
        </div>
      `;
    })
    .join('');
}

function renderTimingHistogram(samples: TimingSample[]): string {
  if (samples.length === 0) return '<p class="small-note">Run the sampler to see a timing histogram.</p>';
  const min = Math.min(...samples.map((s) => s.nanos));
  const max = Math.max(...samples.map((s) => s.nanos));
  const bucketCount = 24;
  const width = Math.max(1, max - min);
  const buckets = new Array<number>(bucketCount).fill(0);
  for (const s of samples) {
    const idx = Math.min(bucketCount - 1, Math.floor(((s.nanos - min) / width) * bucketCount));
    buckets[idx] += 1;
  }
  const peak = Math.max(...buckets, 1);
  const cols = buckets
    .map((count, i) => {
      const height = (count / peak) * 100;
      const lo = Math.round(min + (width * i) / bucketCount);
      const hi = Math.round(min + (width * (i + 1)) / bucketCount);
      return `<div class="histo-col" style="height:${height.toFixed(1)}%" title="${lo}–${hi} ns · ${count} samples" aria-label="${lo} to ${hi} nanoseconds: ${count} samples"></div>`;
    })
    .join('');
  const verdict =
    state.samplerMode === 'leaky'
      ? `Wide spread (${min}–${max} ns). Timing correlates with |sample| — an attacker reading these timings can recover bits of the secret distribution. This is the Espitau et al. 2017 attack vector.`
      : `Tight cluster (${min}–${max} ns). Time is independent of the sampled value. This is what Falcon §3.8 requires.`;
  return `
    <div class="histo" aria-label="Per-sample timing histogram">${cols}</div>
    <p class="small-note">${verdict}</p>
  `;
}

function renderChallengeStrip(): string {
  const sig = state.signResult?.signature;
  if (!sig) return '';
  const buckets = 96;
  const bucketSize = Math.ceil(sig.n / buckets);
  const cells: string[] = [];
  for (let b = 0; b < buckets; b += 1) {
    const start = b * bucketSize;
    const end = Math.min(sig.n, start + bucketSize);
    let pos = 0;
    let neg = 0;
    for (let i = start; i < end; i += 1) {
      if (sig.challengePoly[i] > 0) pos += 1;
      else if (sig.challengePoly[i] < 0) neg += 1;
    }
    const cls = pos > 0 && neg > 0 ? 'mixed' : pos > 0 ? 'pos' : neg > 0 ? 'neg' : 'zero';
    cells.push(`<div class="c-cell ${cls}" title="indices ${start}–${end - 1}: +${pos} / −${neg}"></div>`);
  }
  const hashHexShort = `${sig.hashHex.slice(0, 24)}…${sig.hashHex.slice(-24)}`;
  return `
    <div class="hash-challenge" aria-label="Hash to challenge polynomial">
      <div class="hash-row"><span class="label">SHA-256(message ‖ nonce ‖ h):</span> <code class="mono">${hashHexShort}</code></div>
      <div class="label">Challenge polynomial c (n=${sig.n}, weight=40, ±1 sparse):</div>
      <div class="c-strip" role="img" aria-label="Sparse challenge polynomial coefficients">${cells.join('')}</div>
      <div class="c-legend"><span class="swatch pos"></span>+1 &nbsp; <span class="swatch neg"></span>−1 &nbsp; <span class="swatch zero"></span>0</div>
    </div>
  `;
}

function renderAttempts(): string {
  const result = state.signResult;
  if (!result) return '';
  const bound = result.rejectionBound;
  const rows = result.attempts
    .map((a, i) => {
      const pct = Math.min(140, Math.round((a.squaredNorm / bound) * 100));
      const cls = a.accepted ? 'attempt-row ok' : 'attempt-row bad';
      const label = a.accepted ? 'accepted ✅' : 'rejected ❌';
      return `
        <li class="${cls}" style="animation-delay:${i * 160}ms">
          <span class="attempt-n">try ${a.attempt}</span>
          <div class="attempt-bar"><div class="attempt-fill" style="width:${pct}%"></div><div class="attempt-bound" title="rejection bound"></div></div>
          <span class="attempt-norm mono">‖s‖² = ${a.squaredNorm} / ${bound}</span>
          <span class="attempt-verdict">${label}</span>
        </li>
      `;
    })
    .join('');
  return `
    <div class="attempts-block" aria-label="Rejection sampling attempts">
      <div class="attempts-header">Rejection-sampling loop · bound ‖s‖² ≤ ${bound}</div>
      <ol class="attempts">${rows}</ol>
    </div>
  `;
}

function renderVerify(): string {
  const v = state.verifyResult;
  if (!v) return '';
  const normIcon = v.normCheckOk ? '✅' : '❌';
  const hashIcon = v.recomputeCheckOk ? '✅' : '❌';
  const overall = v.overall
    ? '<span class="badge ok-badge">Verified</span>'
    : '<span class="badge bad-badge">Rejected</span>';
  return `
    <div class="verify-block" aria-label="Verification result">
      <div class="verify-row"><span>${normIcon}</span><span><strong>Norm check:</strong> ‖s‖² = ${v.observedSquaredNorm} ≤ ${v.rejectionBound}? ${v.normCheckOk ? 'yes' : 'no'}</span></div>
      <div class="verify-row"><span>${hashIcon}</span><span><strong>Recompute check:</strong> hash(h·s − c) matches stored digest? ${v.recomputeCheckOk ? 'yes' : 'no'}</span></div>
      <div class="verify-row">${overall}</div>
    </div>
  `;
}

type Quiz = {
  id: string;
  prompt: string;
  options: { text: string; correct?: boolean }[];
  explanation: string;
};

const quizzes: Record<string, Quiz> = {
  q1: {
    id: 'q1',
    prompt: 'Why are Falcon signatures smaller than ML-DSA signatures at the same security level?',
    options: [
      { text: 'Falcon uses elliptic curves instead of lattices.' },
      {
        text: 'Falcon samples short vectors directly via Fast Fourier Sampling over an NTRU lattice, with no rejection-sampling inflation step.',
        correct: true
      },
      { text: 'Falcon stores signatures using a more efficient text encoding.' },
      { text: 'Falcon truncates signatures to fit a fixed budget.' }
    ],
    explanation:
      'ML-DSA (Dilithium) uses module lattices and rejection sampling that produces noticeably larger vectors. Falcon’s NTRU trapdoor plus FFT sampling lets it output a short signature vector directly.'
  },
  q2: {
    id: 'q2',
    prompt: 'In Falcon, what plays the role of the "trapdoor" during signing?',
    options: [
      { text: 'The public modulus q.' },
      {
        text: 'The short polynomial pair (f, g) — a short basis of the NTRU lattice that enables Gaussian sampling.',
        correct: true
      },
      { text: 'The signature nonce.' },
      { text: 'The hash function used to bind the message.' }
    ],
    explanation:
      'The private key is the short basis (f, g). Without it, sampling within the rejection bound is infeasible — this asymmetry is what makes signing hard for everyone except the key holder.'
  },
  q3: {
    id: 'q3',
    prompt: 'Why does Falcon’s verifier check the squared norm of the signature s?',
    options: [
      { text: 'To save bandwidth.' },
      {
        text: 'Because only a holder of the short basis can produce s with ‖s‖² below the bound; the norm check is the actual unforgeability witness.',
        correct: true
      },
      { text: 'To detect replay attacks.' },
      { text: 'To compress the signature for transmission.' }
    ],
    explanation:
      'A random forger can construct an s that hashes consistently with the public equation, but cannot make it short. The norm bound is what closes the loop.'
  },
  q4: {
    id: 'q4',
    prompt: 'When does Falcon clearly beat ML-DSA in practice?',
    options: [
      { text: 'When you want the simplest possible implementation.' },
      { text: 'When you must avoid lattice assumptions entirely.' },
      {
        text: 'When transmitted signature bytes are the binding constraint (TLS chains, IoT firmware, constrained radios) and you can ship a constant-time implementation.',
        correct: true
      },
      { text: 'When you need hash-only security assumptions.' }
    ],
    explanation:
      'Falcon’s edge is size. If implementation simplicity matters more, ML-DSA wins. If you need hash-only assumptions, SLH-DSA wins. Pick by your binding constraint.'
  },
  q5: {
    id: 'q5',
    prompt: 'What is the main reason Falcon’s Gaussian sampler must run in constant time?',
    options: [
      {
        text: 'Variable timing leaks information about the sampled value, which an attacker can integrate over many signatures to recover bits of the secret key.',
        correct: true
      },
      { text: 'Variable timing makes the signature larger.' },
      { text: 'Constant-time code runs faster on average.' },
      { text: 'Constant-time code is required by JavaScript engines.' }
    ],
    explanation:
      'Espitau, Fouque, Gérard, Rossi (2017) demonstrated practical key recovery on BLISS via timing of the Gaussian sampler. Falcon faces an analogous risk — see Falcon spec §3.8.'
  }
};

function renderQuiz(q: Quiz): string {
  const opts = q.options
    .map(
      (o, i) => `
      <button class="quiz-option" type="button" data-quiz="${q.id}" data-correct="${o.correct ? 'true' : 'false'}" data-idx="${i}">
        ${escapeHtml(o.text)}
      </button>
    `
    )
    .join('');
  return `
    <div class="quiz" data-quiz-id="${q.id}" aria-label="Comprehension check">
      <div class="quiz-prompt"><strong>Check your understanding:</strong> ${escapeHtml(q.prompt)}</div>
      <div class="quiz-options">${opts}</div>
      <div class="quiz-feedback" data-quiz-feedback="${q.id}"></div>
    </div>
  `;
}

export function renderApp(root: HTMLElement): void {
  const theme = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
  const set = currentSet();

  root.innerHTML = `
    <div class="page" aria-label="Falcon Seal page wrapper">
      <header class="hero" aria-label="Header">
        <button
          id="theme-toggle"
          class="theme-toggle"
          type="button"
          aria-label="${theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}"
          aria-pressed="${theme === 'dark' ? 'true' : 'false'}"
        >${theme === 'dark' ? '🌙' : '☀️'}</button>
        <p class="chip category">Post-Quantum Signatures</p>
        <h1>Falcon Seal</h1>
        <p class="subtitle">
          Compact lattice signatures over NTRU lattices, with honest implementation caveats.
        </p>
        <div class="chip-row" aria-label="Primitive chips">
          <span class="chip">Falcon-512</span>
          <span class="chip">Falcon-1024</span>
          <span class="chip">NTRU Lattice</span>
          <span class="chip">Fast Fourier Sampling</span>
        </div>
        <fieldset class="paramset" aria-label="Falcon parameter set selector">
          <legend>Parameter set</legend>
          <label class="paramset-opt">
            <input type="radio" name="paramset" value="Falcon-512" ${state.parameterSetName === 'Falcon-512' ? 'checked' : ''} />
            <span>Falcon-512 <small>(NIST L1, n=512, sig 666 B)</small></span>
          </label>
          <label class="paramset-opt">
            <input type="radio" name="paramset" value="Falcon-1024" ${state.parameterSetName === 'Falcon-1024' ? 'checked' : ''} />
            <span>Falcon-1024 <small>(NIST L5, n=1024, sig 1280 B)</small></span>
          </label>
        </fieldset>
        <div class="hero-actions" aria-label="Header actions">
          <a class="badge" href="https://github.com/systemslibrarian/crypto-lab-falcon-seal" target="_blank" rel="noreferrer" aria-label="Open GitHub repository">GitHub</a>
        </div>
      </header>

      <section class="why" aria-label="Why this matters section">
        <h2>Why this matters</h2>
        <p>
          Falcon produces the smallest signatures among current NIST PQ signature standards, which helps keep certificate chains and IoT updates compact.
        </p>
      </section>

      <section class="panel" aria-labelledby="p1-title">
        <h2 id="p1-title">Panel 1 — NTRU Lattice Primer</h2>
        <p>
          Falcon works in polynomial rings of the form <strong>Z[x]/(x<sup>n</sup>&nbsp;+&nbsp;1)</strong>, where n = 512 or 1024. The underlying hard problem is finding short vectors in high-dimensional lattices (SVP/CVP).
        </p>
        <p>
          <strong>Lattice basis and short vectors:</strong> an NTRU lattice encodes a secret short polynomial pair (f, g) such that <code>h = g · f⁻¹ mod (q, x<sup>n</sup>+1)</code>. The public key h looks random, but the short basis is a trapdoor that enables efficient signing.
        </p>
        <p>
          <strong>Why NTRU lattices produce compact signatures:</strong> ML-DSA (Dilithium) works over <em>module</em> lattices and uses rejection sampling that inflates signatures. Falcon instead uses <em>NTRU</em> lattices with a trapdoor sampler (Fast Fourier Sampling, Ducas &amp; Prest 2016) that directly produces short signature vectors — no inflation step. Result: Falcon-512 ≈ 666 B vs ML-DSA-44 ≈ 2 420 B at comparable security.
        </p>
        <p>
          Standard parameter sets: <strong>Falcon-512</strong> (NIST Level 1, n=512, sig ≈ 666 B) and <strong>Falcon-1024</strong> (NIST Level 5, n=1024, sig ≈ 1280 B). The modulus q = 12289 in both cases.
        </p>
        <div id="lattice-viz" class="viz" aria-label="Lattice visualization">
          ${latticeSvg()}
        </div>
        ${renderQuiz(quizzes.q1)}
      </section>

      <section class="panel" aria-labelledby="p2-title">
        <h2 id="p2-title">Panel 2 — Falcon Key Generation</h2>
        <p class="warning" role="note" aria-label="Disclosure note">
          <strong>Illustrative — not production Falcon.</strong> This demo computes a <em>real</em> NTRU public key <code>h = g · f⁻¹ mod (q, x<sup>n</sup>+1)</code> via negacyclic NTT, but the signing flow uses an educational Gaussian sampler in place of Falcon's constant-time Fast Fourier Sampling.
        </p>
        <p><strong>Private key:</strong> short polynomial pair (f, g) with coefficients in {−1, 0, +1}, forming a short basis of the NTRU lattice.</p>
        <p><strong>Public key:</strong> h = g · f⁻¹ mod q in the ring R<sub>q</sub> = Z<sub>q</sub>[x]/(x<sup>n</sup>+1). Computed here via NTT-based polynomial inversion (q = 12289 is NTT-friendly: q−1 = 12288 is divisible by 2n for both n=512 and n=1024).</p>
        <p><strong>Trapdoor:</strong> the short basis enables Gram-Schmidt orthogonalization, which is essential for the Fast Fourier Sampling used during signing.</p>

        <div class="key-size-table" aria-label="Key and signature size comparison">
          <table>
            <caption>Key and signature sizes (published values)</caption>
            <thead>
              <tr><th>Parameter set</th><th>Public key (B)</th><th>Private key (B)</th><th>Signature (B)</th></tr>
            </thead>
            <tbody>
              <tr><th scope="row">Falcon-512</th><td>897</td><td>1 281</td><td>666</td></tr>
              <tr><th scope="row">Falcon-1024</th><td>1 793</td><td>2 305</td><td>1 280</td></tr>
              <tr><th scope="row">ML-DSA-44</th><td>1 312</td><td>2 560</td><td>2 420</td></tr>
              <tr><th scope="row">SLH-DSA-128s</th><td>32</td><td>64</td><td>7 856</td></tr>
            </tbody>
          </table>
        </div>

        <div class="actions" aria-label="Key generation controls">
          <button id="keygen-btn" class="btn" type="button" aria-label="Generate ${set.name} keypair">Generate ${set.name} keypair</button>
          <span class="status-chip" aria-label="NIST standard status">NIST PQC Standard (Alternate to ML-DSA)</span>
        </div>
        <div id="key-info" class="output" aria-live="polite" aria-label="Generated key information"></div>
        ${renderQuiz(quizzes.q2)}
      </section>

      <section class="panel" aria-labelledby="p3-title">
        <h2 id="p3-title">Panel 3 — Sign and Verify</h2>
        <form id="sign-form" class="form" aria-label="Sign and verify form">
          <label for="message-input">Message</label>
          <textarea id="message-input" rows="5" required aria-label="Message to sign">${escapeHtml(state.message)}</textarea>
          <div class="actions" aria-label="Signing actions">
            <button id="sign-btn" class="btn" type="submit" aria-label="Sign message with illustrative Falcon flow">Sign</button>
            <button id="verify-btn" class="btn alt" type="button" aria-label="Verify current signature">Verify</button>
            <button id="tamper-btn" class="btn alt" type="button" aria-label="Tamper message and verify failure">Tamper test</button>
            <button id="copy-btn" class="btn alt" type="button" aria-label="Copy signature as JSON">Copy as JSON</button>
            <span class="status-chip recommended" aria-label="Recommendation status">RECOMMENDED (size-constrained environments)</span>
          </div>
        </form>
        <p>
          <strong>Gaussian sampling process:</strong> the signer hashes the message with a fresh nonce, derives a sparse challenge polynomial c, then samples a short signature vector s such that h·s ≈ c in the NTRU ring. The verifier (1) re-derives c from message+nonce+h, (2) recomputes u = h·s − c and checks its digest matches, and (3) <em>checks ‖s‖² is below the rejection bound</em>. Both checks must pass.
        </p>
        <p class="warning" role="note" aria-label="Implementation warning">
          <strong>Implementation warning:</strong> the Gaussian sampler <em>must</em> be constant-time in production — see Panel 5 for an interactive demonstration of why.
        </p>
        <div id="sign-info" class="output mono" aria-live="polite" aria-label="Signature details"></div>
        <div id="attempts-info" class="output" aria-live="polite" aria-label="Rejection sampling attempts"></div>
        <div id="challenge-info" class="output" aria-label="Hash to challenge polynomial"></div>
        <div id="verify-info" class="output" aria-live="assertive" aria-label="Verification result"></div>
        ${renderQuiz(quizzes.q3)}
      </section>

      <section class="panel" aria-labelledby="p4-title">
        <h2 id="p4-title">Panel 4 — Falcon vs ML-DSA vs SLH-DSA</h2>
        <p class="small-note">
          Size fields use published NIST submission parameter values. Timing columns are indicative reference-software measurements and hardware-dependent.
        </p>
        <div class="chip-row" aria-label="Algorithm status chips">
          <span class="status-chip" aria-label="Falcon status">Falcon — smallest signatures, highest implementation care</span>
          <span class="status-chip" aria-label="ML-DSA status">ML-DSA — balanced performance and simpler implementation</span>
          <span class="status-chip" aria-label="SLH-DSA status">SLH-DSA — conservative hash-based, no lattice assumptions</span>
        </div>

        <h3>Your message vs each scheme's signature</h3>
        <p class="small-note">Edit the message above in Panel 3 to see how the ratio shifts. Short messages amplify Falcon's advantage; long messages make all signatures look small.</p>
        <div id="vsize-block" class="vsize-block" aria-label="Message vs signature size strips">${renderVisceralSize()}</div>

        <div class="table-wrap" aria-label="Security and performance comparison table">
          <table>
            <caption>NIST Level 1 style sets</caption>
            <thead>
              <tr>
                <th>Set</th>
                <th>PK (B)</th>
                <th>Sig (B)</th>
                <th>Keygen (ms)</th>
                <th>Sign (ms)</th>
                <th>Verify (ms)</th>
                <th>Assumption</th>
                <th>Complexity</th>
              </tr>
            </thead>
            <tbody>${tableRows(comparisonRowsLevel1)}</tbody>
          </table>
        </div>
        <div class="table-wrap" aria-label="Level 5 comparison table">
          <table>
            <caption>NIST Level 5 style sets</caption>
            <thead>
              <tr>
                <th>Set</th>
                <th>PK (B)</th>
                <th>Sig (B)</th>
                <th>Keygen (ms)</th>
                <th>Sign (ms)</th>
                <th>Verify (ms)</th>
                <th>Assumption</th>
                <th>Complexity</th>
              </tr>
            </thead>
            <tbody>${tableRows(comparisonRowsLevel5)}</tbody>
          </table>
        </div>
        <div class="bars" aria-label="Signature size visual comparison">
          ${renderComparisonBars()}
        </div>
        <p class="warning">
          <strong>Security assumption contrast:</strong> Falcon relies on the NTRU lattice hardness (SIS-type problems in the NTRU ring). ML-DSA relies on module lattice hardness (Module-LWE / Module-SIS). SLH-DSA relies only on hash function security — no lattice assumptions at all.
        </p>
        <p class="warning">
          <strong>Implementation complexity:</strong> Falcon is the hardest of the three to implement correctly. Its Gaussian sampler is subtle, requires constant-time execution, and has known side-channel pitfalls. ML-DSA's uniform rejection sampling is simpler. SLH-DSA is conceptually involved (hypertree) but has no sampler timing issues.
        </p>
        ${renderQuiz(quizzes.q4)}
      </section>

      <section class="panel" aria-labelledby="p5-title">
        <h2 id="p5-title">Panel 5 — Side-Channels, Use Cases, and Warnings</h2>

        <h3>Side-channel timing lab</h3>
        <p>
          Falcon's Gaussian sampler is the single component where most real-world attacks land. A non-constant-time sampler leaks the magnitude of each sampled coefficient through timing; aggregated over many signatures, this recovers bits of the secret key.
        </p>
        <fieldset class="sampler-mode" aria-label="Sampler mode toggle">
          <legend>Simulated sampler</legend>
          <label class="paramset-opt">
            <input type="radio" name="sampler-mode" value="constant-time" ${state.samplerMode === 'constant-time' ? 'checked' : ''} />
            <span>Constant-time (Falcon §3.8 compliant)</span>
          </label>
          <label class="paramset-opt">
            <input type="radio" name="sampler-mode" value="leaky" ${state.samplerMode === 'leaky' ? 'checked' : ''} />
            <span>Leaky (time ∝ |sample|)</span>
          </label>
        </fieldset>
        <div class="actions">
          <button id="sample-btn" class="btn alt" type="button" aria-label="Run 512 simulated samples and chart their timings">Run 512 samples</button>
        </div>
        <div id="timing-viz" class="timing-viz" aria-live="polite" aria-label="Timing histogram">
          ${renderTimingHistogram([])}
        </div>
        <p class="warning" role="note">
          <strong>Reference:</strong> Espitau, Fouque, Gérard &amp; Rossi (2017), "Side-Channel Attacks on BLISS Lattice-Based Signatures" — practical key recovery via Gaussian-sampler timing. Falcon spec §3.8 mandates constant-time sampling for production implementations.
        </p>

        <h3>When to choose each algorithm</h3>
        <ul aria-label="Use case list">
          <li><strong>Choose Falcon</strong> when bandwidth dominates: TLS certificate chains, constrained IoT links, blockchain transaction signatures, or any signature-heavy protocol where size matters.</li>
          <li><strong>Choose ML-DSA (Dilithium)</strong> when implementation simplicity, broad library support, and a simpler security proof are more important than raw signature size.</li>
          <li><strong>Choose SLH-DSA (SPHINCS+)</strong> for the most conservative security posture: hash-only assumptions, no lattice hardness dependency, and stateless operation.</li>
        </ul>

        <h3>Real-world deployments and standards</h3>
        <p>
          Falcon is under active consideration by ETSI for post-quantum TLS and certificate profiles. IoT standards bodies (IETF, GlobalPlatform) have noted Falcon's compact signatures as advantageous for constrained device firmware signing and secure boot chains.
        </p>

        <div class="links" aria-label="Related demos">
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-dilithium-seal (ML-DSA comparison)">crypto-lab-dilithium-seal</a>
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-sphincs-ledger (SLH-DSA comparison)">crypto-lab-sphincs-ledger</a>
          <a class="badge" href="https://github.com/systemslibrarian/crypto-lab-kyber-vault" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-kyber-vault">crypto-lab-kyber-vault</a>
          <a class="badge" href="https://github.com/systemslibrarian/crypto-compare" target="_blank" rel="noreferrer" aria-label="Open crypto-compare signatures category">crypto-compare — Signatures</a>
        </div>
        ${renderQuiz(quizzes.q5)}
      </section>

      <section class="panel" aria-labelledby="refs-title">
        <h2 id="refs-title">References and Notes</h2>
        <ul>
          ${references.map((r) => `<li>${r}</li>`).join('')}
        </ul>
      </section>

      <footer class="footer" aria-label="Footer quote">
        <div class="links" aria-label="Related demos">
          Related demos:
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noreferrer">crypto-lab-dilithium-seal</a>
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" target="_blank" rel="noreferrer">crypto-lab-sphincs-ledger</a>
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-hawk/" target="_blank" rel="noreferrer">crypto-lab-hawk</a>
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-dilithium-reject/" target="_blank" rel="noreferrer">crypto-lab-dilithium-reject</a>
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-multivariate/" target="_blank" rel="noreferrer">crypto-lab-multivariate</a>
        </div>
        So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31
      </footer>
    </div>
  `;

  bindEvents(root);
}

function setStatus(id: string, message: string, tone: 'ok' | 'warn' | 'bad' = 'ok'): void {
  const el = document.getElementById(id);
  if (!el) return;
  const prefix = tone === 'ok' ? '✅ ' : tone === 'warn' ? '⚠️ ' : '❌ ';
  el.textContent = prefix + message;
  el.classList.remove('ok', 'warn', 'bad');
  el.classList.add(tone);
}

function updateLatticeViz(): void {
  const host = document.getElementById('lattice-viz');
  if (host) host.innerHTML = latticeSvg();
}

function updateVisceralSize(): void {
  const host = document.getElementById('vsize-block');
  if (host) host.innerHTML = renderVisceralSize();
}

function updateAttempts(): void {
  const host = document.getElementById('attempts-info');
  if (host) host.innerHTML = renderAttempts();
}

function updateChallenge(): void {
  const host = document.getElementById('challenge-info');
  if (host) host.innerHTML = renderChallengeStrip();
}

function updateVerify(): void {
  const host = document.getElementById('verify-info');
  if (host) {
    host.innerHTML = renderVerify();
    host.classList.remove('ok', 'warn', 'bad');
    if (state.verifyResult) host.classList.add(state.verifyResult.overall ? 'ok' : 'bad');
  }
}

function bindEvents(root: HTMLElement): void {
  const keygenBtn = root.querySelector<HTMLButtonElement>('#keygen-btn');
  const signForm = root.querySelector<HTMLFormElement>('#sign-form');
  const verifyBtn = root.querySelector<HTMLButtonElement>('#verify-btn');
  const tamperBtn = root.querySelector<HTMLButtonElement>('#tamper-btn');
  const copyBtn = root.querySelector<HTMLButtonElement>('#copy-btn');
  const msgInput = root.querySelector<HTMLTextAreaElement>('#message-input');
  const sampleBtn = root.querySelector<HTMLButtonElement>('#sample-btn');

  root.querySelectorAll<HTMLInputElement>('input[name="paramset"]').forEach((input) => {
    input.addEventListener('change', () => {
      const next = input.value as FalconParameterSetName;
      if (next === state.parameterSetName) return;
      state.parameterSetName = next;
      state.keyPair = null;
      state.signResult = null;
      state.verifyResult = null;
      state.signedMessage = '';
      renderApp(root);
    });
  });

  root.querySelectorAll<HTMLInputElement>('input[name="sampler-mode"]').forEach((input) => {
    input.addEventListener('change', () => {
      state.samplerMode = input.value as SamplerMode;
    });
  });

  msgInput?.addEventListener('input', () => {
    state.message = msgInput.value;
    updateVisceralSize();
  });

  keygenBtn?.addEventListener('click', async () => {
    keygenBtn.disabled = true;
    setStatus('key-info', `Generating ${state.parameterSetName} keypair (real NTRU inversion via NTT)…`);
    try {
      const t0 = performance.now();
      state.keyPair = await generateFalconKeyPair(currentSet());
      const ms = (performance.now() - t0).toFixed(1);
      const regenNote =
        state.keyPair.privateKey.regenerationsForInvertibility > 0
          ? ` Regenerated f ${state.keyPair.privateKey.regenerationsForInvertibility}× until invertible in R_q.`
          : ' f was invertible on first try.';
      setStatus(
        'key-info',
        `${state.parameterSetName} keypair ready in ${ms} ms. Public key h: ${state.keyPair.publicKey.encodedSizeBytes} B · private (f, g): ${state.keyPair.privateKey.encodedSizeBytes} B.${regenNote} h was computed as g · f⁻¹ mod (q=${state.keyPair.publicKey.q}, x^${state.keyPair.publicKey.n}+1).`,
        'ok'
      );
      state.signResult = null;
      state.verifyResult = null;
      updateLatticeViz();
      updateAttempts();
      updateChallenge();
      updateVerify();
    } finally {
      keygenBtn.disabled = false;
    }
  });

  signForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!state.keyPair) {
      setStatus('verify-info', 'Generate a keypair first.', 'warn');
      return;
    }
    const message = msgInput?.value ?? '';
    if (!message.trim()) {
      setStatus('verify-info', 'Message cannot be empty.', 'bad');
      return;
    }
    const signBtn = root.querySelector<HTMLButtonElement>('#sign-btn');
    if (signBtn) signBtn.disabled = true;
    state.signedMessage = message;
    state.message = message;
    setStatus('sign-info', `Signing with illustrative ${state.parameterSetName} flow…`);
    try {
      const result = await signFalconIllustrative(message, state.keyPair);
      state.signResult = result;
      state.verifyResult = null;
      setStatus(
        'sign-info',
        `${result.signature.parameterSetName} · published sig size: ${result.signature.publishedSizeBytes} B (simulated payload ${result.signature.simulatedPayloadBytes} B). Final ‖s‖² = ${result.finalSquaredNorm} (bound ${result.rejectionBound}). ${result.attempts.length} attempt(s). ${summarizeSignature(result.signature)}`,
        'ok'
      );
      updateAttempts();
      updateChallenge();
      updateLatticeViz();
      updateVerify();
    } finally {
      if (signBtn) signBtn.disabled = false;
    }
  });

  verifyBtn?.addEventListener('click', async () => {
    if (!state.keyPair || !state.signResult) {
      setStatus('verify-info', 'Generate a keypair and sign before verifying.', 'warn');
      return;
    }
    const message = msgInput?.value ?? '';
    state.verifyResult = await verifyFalconIllustrative(message, state.signResult.signature, state.keyPair.publicKey);
    updateVerify();
  });

  tamperBtn?.addEventListener('click', async () => {
    if (!state.keyPair || !state.signResult) {
      setStatus('verify-info', 'Sign a message first to run the tamper test.', 'warn');
      return;
    }
    const tampered = `${state.signedMessage} [tampered]`;
    state.verifyResult = await verifyFalconIllustrative(tampered, state.signResult.signature, state.keyPair.publicKey);
    updateVerify();
  });

  copyBtn?.addEventListener('click', async () => {
    if (!state.signResult) {
      setStatus('verify-info', 'Sign a message first, then copy.', 'warn');
      return;
    }
    const json = signatureToJson(
      state.signResult.signature,
      state.signedMessage,
      state.signResult.rejectionBound,
      state.signResult.finalSquaredNorm
    );
    try {
      await navigator.clipboard.writeText(json);
      copyBtn.textContent = 'Copied ✓';
      setTimeout(() => {
        copyBtn.textContent = 'Copy as JSON';
      }, 1500);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = json;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
      } finally {
        document.body.removeChild(ta);
      }
      copyBtn.textContent = 'Copied ✓';
      setTimeout(() => {
        copyBtn.textContent = 'Copy as JSON';
      }, 1500);
    }
  });

  sampleBtn?.addEventListener('click', () => {
    const samples = simulateSamplerTimings(512, state.samplerMode);
    const host = document.getElementById('timing-viz');
    if (host) host.innerHTML = renderTimingHistogram(samples);
  });

  root.querySelectorAll<HTMLButtonElement>('.quiz-option').forEach((btn) => {
    btn.addEventListener('click', () => {
      const quizId = btn.dataset.quiz;
      if (!quizId) return;
      const quiz = quizzes[quizId];
      if (!quiz) return;
      const correct = btn.dataset.correct === 'true';
      const container = root.querySelector<HTMLElement>(`.quiz[data-quiz-id="${quizId}"]`);
      const feedback = root.querySelector<HTMLElement>(`[data-quiz-feedback="${quizId}"]`);
      container?.querySelectorAll<HTMLButtonElement>('.quiz-option').forEach((b) => {
        b.disabled = true;
        if (b.dataset.correct === 'true') b.classList.add('quiz-correct');
        else if (b === btn) b.classList.add('quiz-wrong');
      });
      if (feedback) {
        feedback.innerHTML = `<strong>${correct ? '✅ Correct.' : '❌ Not quite.'}</strong> ${escapeHtml(quiz.explanation)}`;
        feedback.classList.add(correct ? 'ok' : 'bad');
      }
    });
  });
}
