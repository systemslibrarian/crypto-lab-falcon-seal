import { createAttackState, runAttackRound, type AttackState } from './attack';
import { BAD_BASIS_2D, GOOD_BASIS_2D, babaiRound, closestLatticePoint, distance, type Vec2 } from './babai';
import { comparisonRowsLevel1, comparisonRowsLevel5, references, type SignatureRow } from './compare';
import {
  PARAMETER_SETS,
  flipSignatureCoefficient,
  forgeRandomSignature,
  forgeShortSignature,
  generateFalconKeyPair,
  parseSignatureJson,
  publicKeyFingerprint,
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
  buildLatticePoints,
  projectSignatureVector,
  simulateSamplerTimings,
  type SamplerMode,
  type TimingSample
} from './ntru';
import { loadQuizState, resetQuizState, saveQuizAnswer } from './quiz-state';
import { runRealFalcon } from './real-falcon';
import { startTour } from './tour';

type UIState = {
  parameterSetName: FalconParameterSetName;
  keyPair: FalconKeyPair | null;
  signResult: SignResult | null;
  verifyResult: VerifyResult | null;
  signedMessage: string;
  message: string;
  samplerMode: SamplerMode;
  latticeBasisMode: 'private' | 'public';
  latticeTarget: Vec2 | null;
  samplerHasRun: boolean;
  attackState: AttackState | null;
  attackRunning: boolean;
};

const DEFAULT_MESSAGE = 'Falcon keeps signatures compact for bandwidth-constrained links.';

// Share links carry the message in the hash (#m=<base64url>) so a teacher can
// hand students a pre-loaded exercise. Read once at startup; a bad hash just
// falls back to the default.
function initialMessage(): string {
  try {
    const m = new URLSearchParams(window.location.hash.slice(1)).get('m');
    if (!m) return DEFAULT_MESSAGE;
    const bytes = Uint8Array.from(atob(m.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
    const text = new TextDecoder().decode(bytes).slice(0, 2000);
    return text || DEFAULT_MESSAGE;
  } catch {
    return DEFAULT_MESSAGE;
  }
}

function encodeShareMessage(message: string): string {
  const bytes = new TextEncoder().encode(message);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const state: UIState = {
  parameterSetName: 'Falcon-512',
  keyPair: null,
  signResult: null,
  verifyResult: null,
  signedMessage: '',
  message: initialMessage(),
  samplerMode: 'constant-time',
  latticeBasisMode: 'private',
  latticeTarget: null,
  samplerHasRun: false,
  attackState: null,
  attackRunning: false
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
        <td>${r.nistCategory}</td>
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
  const isPrivate = state.latticeBasisMode === 'private';
  const basis = isPrivate ? GOOD_BASIS_2D : BAD_BASIS_2D;
  const points = buildLatticePoints(GOOD_BASIS_2D); // same lattice under either basis
  const circles = points
    .map((p) => {
      const cx = 150 + p.x;
      const cy = 150 - p.y;
      const cls = p.short ? 'lattice-point short' : 'lattice-point';
      return `<circle class="${cls}" cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="3" />`;
    })
    .join('');

  const lineClass = isPrivate ? 'basis-line private' : 'basis-line public';
  const basisLineA = `<line x1="150" y1="150" x2="${150 + basis.ax}" y2="${150 - basis.ay}" class="${lineClass}" />`;
  const basisLineB = `<line x1="150" y1="150" x2="${150 + basis.bx}" y2="${150 - basis.by}" class="${lineClass}" />`;

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

  let babaiOverlay = '';
  let verdict = '';
  if (state.latticeTarget) {
    const t = state.latticeTarget;
    const snapped = babaiRound(basis, t).point;
    const truest = closestLatticePoint(GOOD_BASIS_2D, t);
    const errDist = distance(snapped, t);
    const bestDist = distance(truest, t);
    // 0.5 = tie tolerance: with the near-orthogonal private basis the only
    // "misses" are sub-pixel ties between equidistant lattice points.
    const found = Math.abs(errDist - bestDist) < 0.5;
    const tx = 150 + t.x;
    const ty = 150 - t.y;
    const sx = 150 + snapped.x;
    const sy = 150 - snapped.y;
    babaiOverlay = `
      <circle cx="${150 + truest.x}" cy="${150 - truest.y}" r="8" class="true-closest" />
      <line x1="${tx}" y1="${ty}" x2="${sx}" y2="${sy}" class="babai-error ${found ? 'hit' : 'miss'}" />
      <circle cx="${sx}" cy="${sy}" r="5" class="babai-snap ${found ? 'hit' : 'miss'}" />
      <path d="M ${tx - 6} ${ty - 6} L ${tx + 6} ${ty + 6} M ${tx - 6} ${ty + 6} L ${tx + 6} ${ty - 6}" class="target-x" />
    `;
    verdict = found
      ? ` <strong>✅ Babai rounding with the ${isPrivate ? 'private short' : 'public long'} basis found the closest lattice point</strong> (error ${errDist.toFixed(1)}).`
      : ` <strong>❌ Babai rounding with the ${isPrivate ? 'private short' : 'public long'} basis missed</strong> — it landed ${errDist.toFixed(1)} away, but the true closest point (dashed ring) is only ${bestDist.toFixed(1)} away.`;
  }

  const caption = state.latticeTarget
    ? `Both bases generate the <em>same</em> lattice — only their shape differs.${verdict} In Falcon this happens in dimension ${currentSet().params.n * 2}, where no one can brute-force the answer.`
    : `Click or drag anywhere on the grid to place a target ✕ (arrow keys work too), then switch bases. The ${isPrivate ? 'short, near-orthogonal <strong>private</strong> basis' : 'long, skewed <strong>public</strong> basis'} is drawn from the origin. Signing = finding the lattice point nearest a hash target; the short basis is what makes that easy.`;

  return `
    <svg
      id="lattice-svg"
      class="lattice interactive"
      viewBox="0 0 300 300"
      role="img"
      tabindex="0"
      aria-label="Interactive two-dimensional lattice: click or drag to place a target, or use the arrow keys to nudge it, and compare Babai rounding under the private and public bases"
    >
      <rect x="0" y="0" width="300" height="300" class="lattice-bg"></rect>
      ${basisLineA}
      ${basisLineB}
      <circle cx="150" cy="150" r="6" class="origin" />
      ${circles}
      ${sigOverlay}
      ${babaiOverlay}
    </svg>
    <p class="small-note" aria-live="polite" aria-label="Lattice visualization legend">${caption}</p>
  `;
}

function latticeControls(): string {
  return `
    <fieldset class="sampler-mode" aria-label="Lattice basis selector">
      <legend>Decode the target with…</legend>
      <label class="paramset-opt">
        <input type="radio" name="lattice-basis" value="private" ${state.latticeBasisMode === 'private' ? 'checked' : ''} />
        <span>Private short basis <small>(the trapdoor — what the signer holds)</small></span>
      </label>
      <label class="paramset-opt">
        <input type="radio" name="lattice-basis" value="public" ${state.latticeBasisMode === 'public' ? 'checked' : ''} />
        <span>Public long basis <small>(same lattice — what an attacker has)</small></span>
      </label>
    </fieldset>
    <div class="actions" aria-label="Lattice playground actions">
      <button id="lattice-random-btn" class="btn alt" type="button" aria-label="Place a random target on the lattice">Place random target</button>
      <button id="lattice-clear-btn" class="btn alt" type="button" aria-label="Clear the lattice target">Clear target</button>
    </div>
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
      ? `Wide spread (${min}–${max} ns, modelled — see the warning above). Timing correlates with |sample| by construction, standing in for a real sampler that short-circuits early. Against such a sampler an attacker reading these timings can recover bits of the secret distribution: the Espitau et al. 2017 attack vector.`
      : `Tight cluster (${min}–${max} ns, modelled — see the warning above). Time is made independent of the sampled value, standing in for a fixed table walk. This is what Falcon §3.8 requires.`;
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
  const set = PARAMETER_SETS[result.signature.parameterSetName];
  return `
    <div class="attempts-block" aria-label="Rejection sampling attempts">
      <div class="attempts-header">Rejection-sampling loop · bound ‖s‖² ≤ ${bound} <span class="fidelity-tag">Demo constant</span></div>
      <ol class="attempts">${rows}</ol>
      <p class="small-note">
        ${bound} is this demo's own bound, tuned so the loop above runs a legible 1–3 times against this build's σ = 1.2 sampler.
        ${set.name}'s real bound is ⌊β²⌋ = ${set.publishedRejectionBoundSqNorm.toLocaleString()} — around
        ${Math.round(set.publishedRejectionBoundSqNorm / bound).toLocaleString()}× larger, because it applies to the pair (s₁, s₂) across 2n
        coefficients sampled at σ ≈ 165.7, not to n coefficients at σ = 1.2. Do not read the number on the left as a Falcon parameter.
      </p>
    </div>
  `;
}

function renderVerifyBlock(v: VerifyResult, note?: string): string {
  const normIcon = v.normCheckOk ? '✅' : '❌';
  const hashIcon = v.recomputeCheckOk ? '✅' : '❌';
  const overall = v.overall
    ? '<span class="badge ok-badge">Verified</span>'
    : '<span class="badge bad-badge">Rejected</span>';
  return `
    <div class="verify-block" aria-label="Verification result">
      <div class="verify-row"><span>${normIcon}</span><span><strong>Norm check:</strong> ‖s‖² = ${v.observedSquaredNorm} ≤ ${v.rejectionBound} (demo constant, not Falcon's β²)? ${v.normCheckOk ? 'yes' : 'no'}</span></div>
      <div class="verify-row"><span>${hashIcon}</span><span><strong>Recompute check:</strong> hash(h·s − c) matches stored digest? ${v.recomputeCheckOk ? 'yes' : 'no'}</span></div>
      <div class="verify-row">${overall}</div>
      ${note ? `<p class="small-note">${note}</p>` : ''}
    </div>
  `;
}

function renderVerify(): string {
  return state.verifyResult ? renderVerifyBlock(state.verifyResult) : '';
}

function renderAttack(): string {
  const attack = state.attackState;
  if (!attack || attack.rounds.length === 0) {
    return '<p class="small-note">The attacker sees only timings — never the sampled values. Run the attack against each sampler mode and compare.</p>';
  }
  const last = attack.rounds[attack.rounds.length - 1];
  const pct = Math.round(last.leakFraction * 100);
  const leaky = attack.mode === 'leaky';
  const sigma = last.recoveredSigma;
  const sparkline = attack.rounds
    .map((r) => {
      const h = Math.max(2, r.leakFraction * 100);
      return `<div class="attack-spark-col" style="height:${h.toFixed(1)}%" title="${r.signaturesObserved} signatures: r²=${(r.leakFraction * 100).toFixed(1)}%"></div>`;
    })
    .join('');
  const verdict = attack.done
    ? leaky
      ? `<strong>Attack succeeded — against the model.</strong> Timing explains ${pct}% of the variance in |sample| (r = ${last.correlation.toFixed(3)}), and the timing strata alone recover the sampler's σ ≈ ${sigma?.toFixed(2) ?? '—'} (true σ = 1.20). Remember what that means here: the timings were computed as <code>820 + (|sample| + 1) × 70 + jitter</code>, so the correlation is recovering a formula this page wrote a moment ago, not a physical leak. The real result it stands in for: Espitau et al. (CCS 2017) turned exactly this class of sampler leakage into full BLISS key recovery — <em>a single</em> execution of strongSwan's signing routine sufficed via branch tracing, as did one electromagnetic trace on an 8-bit microcontroller. The purely statistical form shown here is slower but still cheap: roughly 450 signatures with a perfect cache channel, under 3 500 in practice (Groot Bruinderink et al., CHES 2016).`
      : `<strong>Attack failed.</strong> After ${last.signaturesObserved} signatures, correlation r = ${last.correlation.toFixed(3)} — statistically nothing${sigma === null ? ', and the timings form a single stratum, so no magnitudes can be read out' : ''}. Constant-time sampling starves the attacker of signal, which is why Falcon §3.8 mandates it.`
    : `Observing… ${last.signaturesObserved} signatures (${last.samplesObserved.toLocaleString()} sampler timings) so far. Correlation r = ${last.correlation.toFixed(3)}.`;
  return `
    <div class="attack-block">
      <div class="attack-meter-row">
        <span class="attack-meter-label">Secret-distribution leakage (r²)</span>
        <div class="attack-meter" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}" aria-label="Fraction of sample magnitude variance recovered from timing alone">
          <div class="attack-meter-fill ${leaky ? 'miss' : 'hit'}" style="width:${pct}%"></div>
        </div>
        <span class="attack-meter-pct mono">${pct}%</span>
      </div>
      <div class="attack-spark" aria-label="Leakage versus number of observed signatures">${sparkline}</div>
      <p class="small-note">${verdict}</p>
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
      'The private key is the short basis (f, g), extended by keygen to the full basis (f, g, F, G). Without it, sampling a short vector that also solves the challenge equation s₁ + s₂·h = c is infeasible — that asymmetry is what makes signing hard for everyone except the key holder. Note the qualifier: sampling a short vector on its own is easy. This demo does not implement the trapdoor at all — its signing path never reads (f, g) — which is why the “Forge like a pro” button in Panel 3 succeeds.'
  },
  q3: {
    id: 'q3',
    prompt:
      'The “Forge like a pro” button in the Forgery playground above produces a short s with no private key, and this demo’s verifier accepts it. What does that show about a norm check?',
    options: [
      { text: 'Nothing — real Falcon has no norm check either.' },
      {
        text: 'A norm bound is an unforgeability witness only when the short vector must also solve a fixed equation the challenge pins down. Real Falcon demands s₁ + s₂·h = c and then asks for a short solution; this demo never ties s to c, so shortness on its own is free.',
        correct: true
      },
      { text: 'The forger must have recovered the private key (f, g) from the public key h.' },
      { text: 'The demo’s Gaussian sampler is miscalibrated and produces vectors that are too long.' }
    ],
    explanation:
      'Sampling a short Gaussian vector is easy — anyone can do it, which is what the forge button does. What is hard is sampling a short vector that also satisfies s₁ + s₂·h = c for a challenge you do not control, and only the trapdoor basis makes that possible. This build never enforces that equation during signing, so its norm check is a shortness test rather than an unforgeability witness. An earlier version of this quiz marked “only a holder of the short basis can produce a short s” as the right answer, which the forge button on this very panel disproves.'
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
      'Espitau, Fouque, Gérard, Tibouchi (2017) demonstrated practical key recovery on BLISS via timing of the Gaussian sampler. Falcon faces an analogous risk — see Falcon spec §3.8.'
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
      <div class="hero" aria-label="Header">
        <button
          id="theme-toggle"
          class="theme-toggle"
          type="button"
          aria-label="${theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}"
          aria-pressed="${theme === 'dark' ? 'true' : 'false'}"
        >${theme === 'dark' ? '🌙' : '☀️'}</button>
        <header class="cl-hero">
          <div class="cl-hero-main">
            <h1 class="cl-hero-title">Falcon Seal</h1>
            <p class="cl-hero-sub">FN-DSA · FIPS 206 (in development) · NTRU-lattice signatures</p>
            <p class="cl-hero-desc">
              Explore the NTRU short-basis trapdoor: sample a short signature vector for a hashed challenge, verify by norm bound and public recomputation, and watch a timing attack leak a non-constant-time Gaussian sampler.
            </p>
          </div>
          <aside class="cl-hero-why" aria-label="Why it matters">
            <span class="cl-hero-why-label">WHY IT MATTERS</span>
            <p class="cl-hero-why-text">
              Falcon produces the most compact signatures of the algorithms NIST selected for post-quantum signatures, so it fits where certificates and firmware updates are tight — but it is not a published standard yet: FIPS 206 (FN-DSA) is still in development, while ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are final. And Falcon's Gaussian sampler must run in constant time — a leaky one hands attackers the private key.
            </p>
          </aside>
        </header>
        <p class="chip category">Post-Quantum Signatures</p>
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
          <button id="tour-btn" class="btn" type="button" aria-label="Start the guided tour">▶ Walk me through it</button>
          <a class="badge" href="https://github.com/systemslibrarian/crypto-lab-falcon-seal" target="_blank" rel="noreferrer" aria-label="Open GitHub repository">GitHub</a>
          <span id="quiz-score" class="chip" aria-live="polite" aria-label="Quiz score"></span>
        </div>
        <p class="small-note">
          Naming note: NIST will standardize this design as <strong>FN-DSA</strong> (FFT-over-NTRU-lattice Digital Signature Algorithm) in <strong>FIPS 206 (in development)</strong> — the same dual naming ML-DSA/Dilithium and SLH-DSA/SPHINCS+ went through. FIPS 206 has not been drafted yet, so FN-DSA is a selected-and-named algorithm rather than a published standard.
        </p>
      </div>

      <section class="panel" id="panel-1" aria-labelledby="p1-title">
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
        <h3>Try the trapdoor yourself</h3>
        <p>
          Signing is a <em>closest-vector</em> task: hash the message to a target point, then find the lattice point nearest it. Place a target below and decode it with each basis. The private basis (short, near-orthogonal) rounds to the right answer; the public basis (long, skewed — <em>the same lattice</em>) misses for about half of all targets. That asymmetry is the entire trapdoor.
        </p>
        <div id="lattice-controls" aria-label="Lattice playground controls">
          ${latticeControls()}
        </div>
        <div id="lattice-viz" class="viz" aria-label="Lattice visualization">
          ${latticeSvg()}
        </div>
        ${renderQuiz(quizzes.q1)}
      </section>

      <section class="panel" id="panel-2" aria-labelledby="p2-title">
        <h2 id="p2-title">Panel 2 — Falcon Key Generation</h2>
        <p class="warning" role="note" aria-label="Disclosure note">
          <strong>Illustrative — not production Falcon.</strong> This demo computes a <em>real</em> NTRU public key <code>h = g · f⁻¹ mod (q, x<sup>n</sup>+1)</code> via negacyclic NTT. The signing flow, however, does not merely swap in an educational sampler — it does not use the trapdoor at all. Keygen stops at (f, g, h) and never solves the NTRU equation f·G − g·F = q, so the completing pair (F, G) does not exist in this build, and Panel 3's signer never reads (f, g). See the warnings there.
        </p>
        <p><strong>Private key:</strong> short polynomial pair (f, g) with coefficients in {−1, 0, +1}, forming a short basis of the NTRU lattice. Real Falcon extends this to the full basis (f, g, F, G) with an NTRU solve; this build does not, and its (f, g) are ternary rather than sampled at Falcon's σ<sub>f,g</sub>.</p>
        <p><strong>Public key:</strong> h = g · f⁻¹ mod q in the ring R<sub>q</sub> = Z<sub>q</sub>[x]/(x<sup>n</sup>+1). Computed here via NTT-based polynomial inversion (q = 12289 is NTT-friendly: q−1 = 12288 is divisible by 2n for both n=512 and n=1024). This part is real.</p>
        <p><strong>Trapdoor:</strong> in Falcon, the short basis enables Gram-Schmidt orthogonalization (as an LDL tree over the ring, in floating point), which is what makes Fast Fourier Sampling possible during signing. This build has an integer NTT mod q and no float ring arithmetic, so it has none of that machinery — the trapdoor is described on this page but not implemented anywhere in it.</p>

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
          <span class="status-chip" aria-label="NIST standard status">Selected by NIST — FIPS 206 (FN-DSA) in development, alternate to ML-DSA</span>
        </div>
        <div id="key-info" class="output" aria-live="polite" aria-label="Generated key information"></div>
        ${renderQuiz(quizzes.q2)}
      </section>

      <section class="panel" id="panel-3" aria-labelledby="p3-title">
        <h2 id="p3-title">Panel 3 — Sign and Verify</h2>
        <form id="sign-form" class="form" aria-label="Sign and verify form">
          <label for="message-input">Message</label>
          <textarea id="message-input" rows="5" required aria-label="Message to sign">${escapeHtml(state.message)}</textarea>
          <div class="actions" aria-label="Signing actions">
            <button id="sign-btn" class="btn" type="submit" aria-label="Sign message with illustrative Falcon flow">Sign</button>
            <button id="verify-btn" class="btn alt" type="button" aria-label="Verify current signature">Verify</button>
            <button id="tamper-btn" class="btn alt" type="button" aria-label="Tamper message and verify failure">Tamper test</button>
            <button id="copy-btn" class="btn alt" type="button" aria-label="Copy signature as JSON">Copy as JSON</button>
            <button id="share-btn" class="btn alt" type="button" aria-label="Copy a shareable link that preloads this message">Copy share link</button>
            <span class="status-chip recommended" aria-label="Recommendation status">RECOMMENDED (size-constrained environments)</span>
          </div>
        </form>
        <p>
          <strong>In real Falcon:</strong> the signer hashes the message with a fresh nonce, derives a sparse challenge polynomial c, and then uses the trapdoor basis (f, g, F, G) to sample a <em>short</em> pair (s₁, s₂) that satisfies the fixed equation s₁ + s₂·h = c. The challenge dictates what s must satisfy; finding a short solution to it without the trapdoor is the hard lattice problem.
        </p>
        <p class="warning" role="note" aria-label="Signing fidelity warning">
          <strong>In this demo, signing does not do that.</strong> <code>signFalconIllustrative</code> samples s from a centred Gaussian and loops only until ‖s‖² falls under the bound — c is not an input to the sampler, and the private key (f, g) is never read. The message is bound afterwards, by publishing the digest of u = h·s − c. So the two verifier checks below are real and both genuinely fail on tampering, but they do <em>not</em> establish that a private key was involved. The <strong>Forge like a pro</strong> button in the Forgery playground proves it. This is not fixable by editing the sampler: this build's keygen produces only (f, g, h) and never solves the NTRU equation f·G − g·F = q, so there is no full basis (F, G) to sample against and no fast-Fourier sampler over it.
        </p>
        <p>
          <strong>What the verifier actually does here:</strong> (1) re-derive c from message + nonce + h, (2) recompute u = h·s − c and check its digest matches the one in the signature, and (3) <em>check ‖s‖² is below the rejection bound</em>. Both checks must pass, and both catch tampering — but step 3 is checked against a freely-chosen s rather than against a solution to a pinned equation, which is exactly the gap the forge button walks through.
        </p>
        <p class="warning" role="note" aria-label="Implementation warning">
          <strong>Implementation warning:</strong> the Gaussian sampler <em>must</em> be constant-time in production — see Panel 5 for an interactive demonstration of why.
        </p>
        <div id="sign-info" class="output mono" aria-live="polite" aria-label="Signature details"></div>
        <div id="attempts-info" class="output" aria-label="Rejection sampling attempts"></div>
        <div id="challenge-info" class="output" aria-label="Hash to challenge polynomial"></div>
        <div id="verify-info" class="output" aria-live="assertive" aria-label="Verification result"></div>

        <h3>Forgery playground</h3>
        <p>
          In real Falcon, a signature must be a <strong>short</strong> vector that <strong>satisfies the verification equation</strong> s₁ + s₂·h = c — and finding a short solution without the trapdoor is the hard lattice problem. Probe both requirements, and then find this demo's own weak spot:
        </p>
        <div class="actions" aria-label="Forgery actions">
          <button id="forge-btn" class="btn alt" type="button" aria-label="Attempt a forgery with a random signature vector">Try to forge (random s)</button>
          <button id="flip-btn" class="btn alt" type="button" aria-label="Flip one coefficient of the current signature and re-verify">Flip one coefficient of s</button>
          <button id="forge-pro-btn" class="btn alt" type="button" aria-label="Forge with a short Gaussian vector and expose the toy scheme's weakness">Forge like a pro (short s)</button>
        </div>
        <div id="forge-info" class="output" aria-live="polite" aria-label="Forgery attempt result"></div>

        <h3>Verify a pasted signature</h3>
        <details class="paste-details">
          <summary>Paste a signature JSON from “Copy as JSON” (yours, or someone else’s)</summary>
          <p class="small-note">
            The export embeds the message, nonce, full vector s, and the signer's public key h — everything a verifier needs. Trade exports with a classmate, or edit a byte of the JSON in transit and watch verification catch it.
          </p>
          <textarea id="paste-input" rows="6" aria-label="Signature JSON to verify" placeholder='{"scheme":"Falcon-512", ...}'></textarea>
          <div class="actions">
            <button id="paste-verify-btn" class="btn alt" type="button" aria-label="Verify the pasted signature JSON">Verify pasted signature</button>
          </div>
          <div id="paste-info" class="output" aria-live="polite" aria-label="Pasted signature verification result"></div>
        </details>
        ${renderQuiz(quizzes.q3)}
      </section>

      <section class="panel" id="panel-4" aria-labelledby="p4-title">
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
            <caption>Smallest parameter set of each scheme &mdash; note the NIST categories differ</caption>
            <thead>
              <tr>
                <th>Set</th>
                <th>NIST category</th>
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
          <p class="small-note">These are each scheme's smallest standard parameter set, not a like-for-like security comparison. Falcon-512 and SLH-DSA-128s claim NIST category 1; the smallest ML-DSA set, ML-DSA-44, claims category 2 (FIPS 204). ML-DSA therefore has no category-1 set to put in this row, so it is carrying a slightly higher security target than the other two.</p>
        </div>
        <div class="table-wrap" aria-label="Level 5 comparison table">
          <table>
            <caption>NIST Category 5 sets</caption>
            <thead>
              <tr>
                <th>Set</th>
                <th>NIST category</th>
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

      <section class="panel" id="panel-5" aria-labelledby="p5-title">
        <h2 id="p5-title">Panel 5 — Side-Channels, Use Cases, and Warnings</h2>

        <h3>Side-channel timing lab <span class="fidelity-tag">Model — no clock is read</span></h3>
        <p class="warning" role="note" aria-label="Timing lab fidelity warning">
          <strong>Every nanosecond figure in this lab is computed, not measured.</strong> <code>simulateSamplerTimings</code> assigns each draw
          <code>nanos = 820 + (|sample| + 1) × 70 + jitter</code> in leaky mode and a flat <code>820 + 9 × 70 + jitter</code> in constant-time mode.
          The attack then correlates those numbers against the very magnitudes that produced them, so it is guaranteed to succeed in leaky mode and
          guaranteed to fail in constant-time mode. It reproduces the <em>shape</em> of the real result; it does not independently discover it.
          The reason it is a model rather than a measurement is itself the lesson: browsers deliberately coarsen <code>performance.now()</code> to
          microseconds or worse precisely to make this class of attack unmountable from a web page, so a real 70 ns stratum cannot be observed here
          at all. The published attacks below are real, were run on real implementations, and are cited for what they found — not as a description of
          what this panel just did.
        </p>
        <p>
          With that said: Falcon's Gaussian sampler is the single component where most real-world attacks land. A non-constant-time sampler leaks the magnitude of each sampled coefficient through timing; aggregated over many signatures, this recovers bits of the secret key.
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
        <h3>Now run the attack</h3>
        <p>
          The histogram shows the leak exists. This runs the attacker's side: observe <em>only the timings</em> of many signatures, correlate them against sample magnitude, and read the secret distribution out of the timing strata. Toggle the sampler mode above and run it against both.
        </p>
        <div class="actions">
          <button id="attack-btn" class="btn alt" type="button" aria-label="Simulate a timing attack over 200 observed signatures">Attack: observe 200 signatures</button>
        </div>
        <div id="attack-viz" class="timing-viz" aria-live="polite" aria-label="Timing attack progress">
          ${renderAttack()}
        </div>
        <p class="warning" role="note">
          <strong>References:</strong> Espitau, Fouque, Gérard &amp; Tibouchi, "Side-Channel Attacks on BLISS Lattice-Based Signatures" (ACM CCS 2017, ePrint 2017/505) — full key recovery from a single strongSwan signing execution via branch tracing, and from a single electromagnetic trace on an 8-bit microcontroller. Groot Bruinderink, Hülsing, Lange &amp; Yarom, "Flush, Gauss, and Reload" (CHES 2016, ePrint 2016/300) — the statistical variant modelled here, recovering a BLISS key from about 450 signatures with a perfect side-channel and under 3 500 in practice. Falcon spec §3.8 mandates constant-time sampling for production implementations.
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

      <section class="panel" id="panel-6" aria-labelledby="p6-title">
        <h2 id="p6-title">Panel 6 — Run Real Falcon (WebAssembly)</h2>
        <p>
          Everything above is deliberately illustrative. This panel runs the <strong>reference Falcon-1024 implementation compiled to WebAssembly</strong>
          (<a href="https://github.com/cyph/pqcrypto.js" target="_blank" rel="noreferrer">falcon-crypto / pqcrypto.js</a>) on your machine:
          real key generation, real signing of your Panel 3 message, real verification, real byte counts and timings.
        </p>
        <div class="actions" aria-label="Real Falcon controls">
          <button id="real-falcon-btn" class="btn" type="button" aria-label="Run real Falcon-1024 keygen, sign, and verify in WebAssembly">Run real Falcon-1024 on your message</button>
        </div>
        <div id="real-falcon-info" class="output" aria-live="polite" aria-label="Real Falcon run results"></div>
        <p class="small-note">
          This build exposes Falcon-1024 with the fixed-size <em>padded</em> signature format: 1 header byte + 40-byte salt + padded body = 1,330 B,
          per PQClean's <code>CRYPTO_BYTES</code>. The number you will see reported above is <strong>1,332 B</strong>, because the
          <code>falcon-crypto</code> WebAssembly wrapper prepends a 2-byte length prefix to the PQClean output. The variable-size compressed format
          from the spec averages ≈1,280 B — all three are real numbers describing the same signature at different layers.
        </p>
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
  if (!host) return;
  // Re-rendering replaces the SVG node; restore focus so keyboard nudging
  // (arrow keys) keeps working across updates.
  const hadFocus = document.activeElement?.id === 'lattice-svg';
  host.innerHTML = latticeSvg();
  if (hadFocus) host.querySelector<SVGSVGElement>('#lattice-svg')?.focus();
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

function updateAttack(): void {
  const host = document.getElementById('attack-viz');
  if (host) host.innerHTML = renderAttack();
}

function runHistogram(): void {
  const samples = simulateSamplerTimings(512, state.samplerMode);
  state.samplerHasRun = true;
  const host = document.getElementById('timing-viz');
  if (host) host.innerHTML = renderTimingHistogram(samples);
}

function applyQuizAnswer(root: ParentNode, quiz: Quiz, chosenIdx: number, save: boolean): void {
  const container = root.querySelector<HTMLElement>(`.quiz[data-quiz-id="${quiz.id}"]`);
  if (!container) return;
  let correct = false;
  container.querySelectorAll<HTMLButtonElement>('.quiz-option').forEach((b) => {
    b.disabled = true;
    if (b.dataset.correct === 'true') b.classList.add('quiz-correct');
    if (Number(b.dataset.idx) === chosenIdx) {
      if (b.dataset.correct === 'true') correct = true;
      else b.classList.add('quiz-wrong');
    }
  });
  const feedback = container.querySelector<HTMLElement>(`[data-quiz-feedback="${quiz.id}"]`);
  if (feedback) {
    feedback.innerHTML = `<strong>${correct ? '✅ Correct.' : '❌ Not quite.'}</strong> ${escapeHtml(quiz.explanation)}`;
    feedback.classList.remove('ok', 'bad');
    feedback.classList.add(correct ? 'ok' : 'bad');
  }
  if (save) saveQuizAnswer(quiz.id, { chosenIdx, correct });
  updateQuizScore();
}

function resetQuizDom(root: ParentNode): void {
  root.querySelectorAll<HTMLElement>('.quiz').forEach((container) => {
    container.querySelectorAll<HTMLButtonElement>('.quiz-option').forEach((b) => {
      b.disabled = false;
      b.classList.remove('quiz-correct', 'quiz-wrong');
    });
    const feedback = container.querySelector<HTMLElement>('.quiz-feedback');
    if (feedback) {
      feedback.innerHTML = '';
      feedback.classList.remove('ok', 'bad');
    }
  });
}

function updateQuizScore(): void {
  const host = document.getElementById('quiz-score');
  if (!host) return;
  const stored = loadQuizState();
  const ids = Object.keys(quizzes);
  const answered = ids.filter((id) => stored[id]);
  if (answered.length === 0) {
    host.innerHTML = `Quiz: 0/${ids.length} answered`;
    return;
  }
  const correct = answered.filter((id) => stored[id].correct).length;
  const firstWrong = ids.find((id) => stored[id] && !stored[id].correct);
  const perfect = correct === ids.length;
  host.innerHTML =
    `Quiz score: ${correct}/${ids.length}${perfect ? ' 🎉' : ''}` +
    (firstWrong ? ` · <button type="button" class="quiz-link" data-quiz-review="${firstWrong}">review</button>` : '') +
    ` · <button type="button" class="quiz-link" data-quiz-reset="true" aria-label="Reset quiz progress">reset</button>`;
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
      state.attackState = null;
      updateAttack();
      if (state.samplerHasRun) runHistogram();
    });
  });

  root.querySelectorAll<HTMLInputElement>('input[name="lattice-basis"]').forEach((input) => {
    input.addEventListener('change', () => {
      state.latticeBasisMode = input.value as 'private' | 'public';
      updateLatticeViz();
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
      // Report the spec figures as spec figures and the in-browser objects as
      // what they are. encodedSizeBytes is a published constant copied from the
      // parameter set, not a measurement of the keypair just generated — these
      // are Int16Array coefficient vectors, 2 bytes per coefficient, with none
      // of Falcon's key compression applied. Same pattern the sign handler uses
      // for "published sig size … (simulated payload …)".
      const measuredPubBytes = state.keyPair.publicKey.h.length * 2;
      const measuredPrivBytes = (state.keyPair.privateKey.f.length + state.keyPair.privateKey.g.length) * 2;
      setStatus(
        'key-info',
        `${state.parameterSetName} keypair ready in ${ms} ms. Published key sizes: public h ${state.keyPair.publicKey.encodedSizeBytes} B · private (f, g) ${state.keyPair.privateKey.encodedSizeBytes} B — those are the Falcon spec figures, not measurements of this object. What this build actually holds in memory is uncompressed Int16 coefficient vectors: h ${measuredPubBytes} B · (f, g) ${measuredPrivBytes} B.${regenNote} h was computed as g · f⁻¹ mod (q=${state.keyPair.publicKey.q}, x^${state.keyPair.publicKey.n}+1).`,
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
        `${result.signature.parameterSetName} · published sig size: ${result.signature.publishedSizeBytes} B (simulated payload ${result.signature.simulatedPayloadBytes} B). Final ‖s‖² = ${result.finalSquaredNorm} (demo bound ${result.rejectionBound}). ${result.attempts.length} attempt(s). ${summarizeSignature(result.signature)}`,
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

  const copyText = async (text: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
      } finally {
        document.body.removeChild(ta);
      }
    }
  };
  const flashLabel = (btn: HTMLButtonElement, done: string, restore: string): void => {
    btn.textContent = done;
    setTimeout(() => {
      btn.textContent = restore;
    }, 1500);
  };

  copyBtn?.addEventListener('click', async () => {
    if (!state.signResult) {
      setStatus('verify-info', 'Sign a message first, then copy.', 'warn');
      return;
    }
    const json = signatureToJson(
      state.signResult.signature,
      state.signedMessage,
      state.signResult.rejectionBound,
      state.signResult.finalSquaredNorm,
      state.keyPair?.publicKey
    );
    await copyText(json);
    flashLabel(copyBtn, 'Copied ✓', 'Copy as JSON');
  });

  const shareBtn = root.querySelector<HTMLButtonElement>('#share-btn');
  shareBtn?.addEventListener('click', async () => {
    const message = msgInput?.value ?? state.message;
    const url = `${window.location.origin}${window.location.pathname}#m=${encodeShareMessage(message)}`;
    await copyText(url);
    flashLabel(shareBtn, 'Link copied ✓', 'Copy share link');
  });

  sampleBtn?.addEventListener('click', () => {
    runHistogram();
  });

  // Lattice playground: click or drag to place the target, arrow keys to nudge it.
  const latticeViz = root.querySelector<HTMLElement>('#lattice-viz');
  const clampTarget = (x: number, y: number) => ({
    x: Math.max(-140, Math.min(140, Math.round(x))),
    y: Math.max(-140, Math.min(140, Math.round(y)))
  });
  const pointToLattice = (event: PointerEvent | MouseEvent) => {
    const svg = latticeViz?.querySelector('svg.lattice');
    if (!svg) return null;
    const rect = svg.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return null;
    const x = ((event.clientX - rect.left) / rect.width) * 300 - 150;
    const y = 150 - ((event.clientY - rect.top) / rect.height) * 300;
    return clampTarget(x, y);
  };
  let latticeDragging = false;
  latticeViz?.addEventListener('pointerdown', (event) => {
    if (!(event.target as Element).closest('svg.lattice')) return;
    const p = pointToLattice(event);
    if (!p) return;
    latticeDragging = true;
    state.latticeTarget = p;
    updateLatticeViz();
  });
  latticeViz?.addEventListener('pointermove', (event) => {
    if (!latticeDragging) return;
    const p = pointToLattice(event);
    if (!p) return;
    state.latticeTarget = p;
    updateLatticeViz();
  });
  for (const type of ['pointerup', 'pointercancel', 'pointerleave'] as const) {
    latticeViz?.addEventListener(type, () => {
      latticeDragging = false;
    });
  }
  latticeViz?.addEventListener('keydown', (event) => {
    const deltas: Record<string, [number, number]> = {
      ArrowLeft: [-4, 0],
      ArrowRight: [4, 0],
      ArrowUp: [0, 4],
      ArrowDown: [0, -4]
    };
    const delta = deltas[event.key];
    if (!delta) return;
    event.preventDefault();
    const current = state.latticeTarget ?? { x: 0, y: 0 };
    state.latticeTarget = clampTarget(current.x + delta[0], current.y + delta[1]);
    updateLatticeViz();
  });

  root.querySelector<HTMLButtonElement>('#lattice-random-btn')?.addEventListener('click', () => {
    const rand = new Int8Array(2);
    crypto.getRandomValues(rand);
    state.latticeTarget = {
      x: Math.round((rand[0] / 128) * 110),
      y: Math.round((rand[1] / 128) * 110)
    };
    updateLatticeViz();
  });

  root.querySelector<HTMLButtonElement>('#lattice-clear-btn')?.addEventListener('click', () => {
    state.latticeTarget = null;
    updateLatticeViz();
  });

  // Timing attack simulation.
  const attackBtn = root.querySelector<HTMLButtonElement>('#attack-btn');
  attackBtn?.addEventListener('click', () => {
    if (state.attackRunning) return;
    state.attackRunning = true;
    state.attackState = createAttackState(state.samplerMode);
    attackBtn.disabled = true;
    const totalRounds = 20;
    const step = () => {
      const attack = state.attackState;
      if (!attack) {
        state.attackRunning = false;
        attackBtn.disabled = false;
        return;
      }
      runAttackRound(attack, 10, 128);
      if (attack.rounds.length >= totalRounds) {
        attack.done = true;
        state.attackRunning = false;
        attackBtn.disabled = false;
      }
      updateAttack();
      if (!attack.done) setTimeout(step, 90);
    };
    step();
  });

  // Forgery playground.
  const forgeBtn = root.querySelector<HTMLButtonElement>('#forge-btn');
  forgeBtn?.addEventListener('click', async () => {
    if (!state.keyPair) {
      setStatus('forge-info', 'Generate a keypair first — the forger needs a public key to attack.', 'warn');
      return;
    }
    const message = msgInput?.value ?? state.message;
    forgeBtn.disabled = true;
    try {
      const forged = await forgeRandomSignature(message, state.keyPair.publicKey);
      const v = await verifyFalconIllustrative(message, forged.signature, state.keyPair.publicKey);
      const host = document.getElementById('forge-info');
      if (host) {
        host.classList.remove('ok', 'warn', 'bad');
        host.classList.add(v.overall ? 'ok' : 'bad');
        const factor = (v.observedSquaredNorm / v.rejectionBound).toFixed(1);
        host.innerHTML = renderVerifyBlock(
          v,
          `The forger picked a random s and computed the digest of h·s − c honestly — so the recompute check passes. But ‖s‖² = ${v.observedSquaredNorm} is ${factor}× over the demo bound ${v.rejectionBound}: rejected. That only shows a <em>careless</em> forger fails. Now try “Forge like a pro”, where the forger samples s the same way the signer does — because in this build the signer has no advantage over them.`
        );
      }
    } finally {
      forgeBtn.disabled = false;
    }
  });

  const forgeProBtn = root.querySelector<HTMLButtonElement>('#forge-pro-btn');
  forgeProBtn?.addEventListener('click', async () => {
    if (!state.keyPair) {
      setStatus('forge-info', 'Generate a keypair first — the forger needs a public key to attack.', 'warn');
      return;
    }
    const message = msgInput?.value ?? state.message;
    forgeProBtn.disabled = true;
    try {
      const forged = await forgeShortSignature(message, state.keyPair.publicKey);
      const v = await verifyFalconIllustrative(message, forged.signature, state.keyPair.publicKey);
      const host = document.getElementById('forge-info');
      if (host) {
        host.classList.remove('ok', 'warn', 'bad');
        host.classList.add('warn');
        host.innerHTML = renderVerifyBlock(
          v,
          v.overall
            ? `😱 <strong>It verified — and no private key was used.</strong> You found this demo's weak spot, and it is worse than "the forger got lucky": <code>forgeShortSignature</code> and <code>signFalconIllustrative</code> run the <em>same</em> sampling loop, because the signer never reads (f, g) either. The digest of h·s − c is stored <em>inside the signature</em>, so anyone who samples a short Gaussian s and computes that digest honestly passes both checks. The signer has no advantage over you. <strong>Real Falcon is immune:</strong> its verifier recomputes the challenge c and checks the fixed equation s₁ + s₂·h = c — the challenge dictates what s must satisfy, and finding a <em>short</em> solution to that equation without the trapdoor basis (f, g) is the SIS-style lattice problem believed hard even for quantum computers. This gap is exactly the distance between a teaching flow and FIPS 206.`
            : 'The sampler happened to exceed the norm bound this time — try again.'
        );
      }
    } finally {
      forgeProBtn.disabled = false;
    }
  });

  const flipBtn = root.querySelector<HTMLButtonElement>('#flip-btn');
  flipBtn?.addEventListener('click', async () => {
    if (!state.keyPair || !state.signResult) {
      setStatus('forge-info', 'Sign a message first, then flip a coefficient of the real signature.', 'warn');
      return;
    }
    const { signature, index } = flipSignatureCoefficient(state.signResult.signature);
    const v = await verifyFalconIllustrative(state.signedMessage, signature, state.keyPair.publicKey);
    const host = document.getElementById('forge-info');
    if (host) {
      host.classList.remove('ok', 'warn', 'bad');
      host.classList.add(v.overall ? 'ok' : 'bad');
      host.innerHTML = renderVerifyBlock(
        v,
        `Coefficient s[${index}] was nudged by ±1. The norm barely moved (${v.observedSquaredNorm} vs demo bound ${v.rejectionBound}), but h·s − c changed, so the digest no longer matches. A signature commits to the <em>exact</em> vector — shortness alone is not enough to survive tampering. Note it is also not enough to establish authorship: see “Forge like a pro”.`
      );
    }
  });

  // Paste-to-verify.
  const pasteInput = root.querySelector<HTMLTextAreaElement>('#paste-input');
  root.querySelector<HTMLButtonElement>('#paste-verify-btn')?.addEventListener('click', async () => {
    const raw = pasteInput?.value.trim() ?? '';
    if (!raw) {
      setStatus('paste-info', 'Paste a signature JSON first (use “Copy as JSON” after signing).', 'warn');
      return;
    }
    try {
      const bundle = parseSignatureJson(raw);
      const v = await verifyFalconIllustrative(bundle.message, bundle.signature, bundle.publicKey);
      const fingerprint = await publicKeyFingerprint(bundle.publicKey);
      const host = document.getElementById('paste-info');
      if (host) {
        host.classList.remove('ok', 'warn', 'bad');
        host.classList.add(v.overall ? 'ok' : 'bad');
        const preview = bundle.message.length > 80 ? `${bundle.message.slice(0, 80)}…` : bundle.message;
        host.innerHTML = renderVerifyBlock(
          v,
          `Verified against the public key embedded in the JSON — signer key fingerprint <code class="mono">${fingerprint}</code> · message: “${escapeHtml(preview)}”. ${v.overall ? 'This message was signed by the holder of that key and has not been altered.' : 'Either the message, the vector s, or the key was altered after signing.'}`
        );
      }
    } catch (err) {
      setStatus('paste-info', err instanceof Error ? err.message : 'Could not parse the signature JSON.', 'bad');
    }
  });

  // Real Falcon (WASM).
  const realBtn = root.querySelector<HTMLButtonElement>('#real-falcon-btn');
  realBtn?.addEventListener('click', async () => {
    realBtn.disabled = true;
    setStatus('real-falcon-info', 'Loading the Falcon-1024 WebAssembly module and generating a real keypair (this is the slow, real thing)…');
    try {
      const run = await runRealFalcon(state.message || 'Falcon');
      const host = document.getElementById('real-falcon-info');
      if (host) {
        const healthy = run.verified && !run.tamperedVerified;
        host.classList.remove('ok', 'warn', 'bad');
        host.classList.add(healthy ? 'ok' : 'bad');
        const illustrativeBytes = state.signResult?.signature.simulatedPayloadBytes;
        host.innerHTML = `
          <div class="table-wrap">
            <table>
              <caption>Real Falcon-1024 (reference implementation, WASM) — measured on your machine just now</caption>
              <thead><tr><th>Step</th><th>Result</th><th>Time</th></tr></thead>
              <tbody>
                <tr><th scope="row">Key generation</th><td>public key ${run.publicKeyBytes} B · private key ${run.privateKeyBytes} B</td><td>${run.keygenMs.toFixed(1)} ms</td></tr>
                <tr><th scope="row">Sign your message</th><td>signature ${run.signatureBytes} B · <code class="mono">${run.signatureHexPreview}…</code></td><td>${run.signMs.toFixed(1)} ms</td></tr>
                <tr><th scope="row">Verify</th><td>${run.verified ? '✅ valid' : '❌ INVALID'}</td><td>${run.verifyMs.toFixed(1)} ms</td></tr>
                <tr><th scope="row">Verify tampered message</th><td>${run.tamperedVerified ? '❌ ACCEPTED (bad!)' : '✅ rejected, as it must be'}</td><td>—</td></tr>
              </tbody>
            </table>
          </div>
          <p class="small-note">
            Published Falcon-1024 sizes: public key 1,793 B · signature ≈1,280 B compressed. This build uses the fixed 1,330-byte padded format, and the
            ${run.signatureBytes} B measured above is that plus the 2-byte length prefix the <code>falcon-crypto</code> WASM wrapper adds.
            ${illustrativeBytes ? `Compare the illustrative flow's simulated payload above: ${illustrativeBytes} B — same order of magnitude, none of the constant-time engineering.` : 'Sign a message in Panel 3 to compare against the illustrative flow.'}
          </p>
        `;
      }
    } catch (err) {
      setStatus(
        'real-falcon-info',
        `Could not run the WASM build (${err instanceof Error ? err.message : 'unknown error'}). This can happen offline or in browsers without WebAssembly support.`,
        'warn'
      );
    } finally {
      realBtn.disabled = false;
    }
  });

  // Guided tour.
  root.querySelector<HTMLButtonElement>('#tour-btn')?.addEventListener('click', () => {
    const setLatticeMode = (mode: 'private' | 'public') => {
      state.latticeBasisMode = mode;
      root.querySelectorAll<HTMLInputElement>('input[name="lattice-basis"]').forEach((i) => {
        i.checked = i.value === mode;
      });
      updateLatticeViz();
    };
    startTour([
      {
        target: '#panel-1',
        title: 'The trapdoor is a short basis',
        body: 'A lattice is every whole-number combination of two basis vectors. Signing means finding the lattice point closest to a hash target — easy with a short, near-orthogonal basis. We just placed a target for you: the private-basis rounding lands on the closest point.',
        action: () => {
          setLatticeMode('private');
          root.querySelector<HTMLButtonElement>('#lattice-random-btn')?.click();
        }
      },
      {
        target: '#panel-1',
        title: 'Same lattice, useless basis',
        body: 'Now decode the same target with the public basis — long, skewed vectors that generate the exact same lattice. Babai rounding usually misses. In dimension 1024 this gap becomes cryptographic hardness.',
        action: () => setLatticeMode('public')
      },
      {
        target: '#panel-2',
        title: 'Key generation — for real',
        body: 'We just generated a keypair: short secret polynomials (f, g) and the public key h = g·f⁻¹ mod (q, xⁿ+1), computed with a real number-theoretic transform. h looks random; (f, g) is the short basis you just used.',
        action: () => root.querySelector<HTMLButtonElement>('#keygen-btn')?.click()
      },
      {
        target: '#panel-3',
        title: 'Sign: hash, then sample short (but not for c)',
        body: 'The message is hashed with a fresh nonce into a sparse challenge polynomial c. Real Falcon would now use the trapdoor basis to sample a short s solving s₁ + s₂·h = c. This demo does not: it samples s from a centred Gaussian, ignores c while doing so, never touches the private key, and binds the message afterwards by publishing the digest of u = h·s − c. Watch the loop below — it is a genuine rejection loop, but it rejects on length alone.',
        action: () => root.querySelector<HTMLFormElement>('#sign-form')?.requestSubmit()
      },
      {
        target: '#panel-3',
        title: 'Verify: two checks, both required',
        body: 'The verifier recomputes the challenge from the message and checks (1) the digest of h·s − c matches and (2) ‖s‖² is under the bound. In real Falcon the norm check is the unforgeability witness, because there it applies to a solution of the pinned equation s₁ + s₂·h = c. Here it applies to a freely-chosen s, so it proves shortness and nothing more — two steps from now you will forge a signature that passes both.',
        action: () => root.querySelector<HTMLButtonElement>('#verify-btn')?.click()
      },
      {
        target: '#panel-3',
        title: 'Tamper detection',
        body: 'We just verified the same signature against a tampered message. The recomputed challenge changes, the digest no longer matches, and verification fails — authenticity and integrity in one primitive.',
        action: () => root.querySelector<HTMLButtonElement>('#tamper-btn')?.click()
      },
      {
        target: '#panel-3',
        title: 'Why forgery fails (and where this demo cheats)',
        body: 'A forger just tried: they picked a random s and computed the hash digest honestly. The recompute check passed — and the norm check failed by an order of magnitude. In real Falcon, shortness is the thing only the trapdoor buys you. After the tour, press “Forge like a pro” to find the one attack this toy scheme cannot stop — and read why the real verification equation can.',
        action: () => root.querySelector<HTMLButtonElement>('#forge-btn')?.click()
      },
      {
        target: '#panel-5',
        title: 'Where real implementations get broken',
        body: 'Falcon’s Gaussian sampler must be constant-time. This histogram shows per-sample timings — try both sampler modes. The leaky one’s timing strata spell out the secret distribution.',
        action: () => root.querySelector<HTMLButtonElement>('#sample-btn')?.click()
      },
      {
        target: '#panel-5',
        title: 'Run the actual attack',
        body: 'This plays the attacker: observe only timings across 200 signatures and correlate. Against the leaky sampler the leakage meter climbs; against the constant-time sampler it flatlines. Both timings are computed from a formula rather than clocked — browsers coarsen performance.now() too far to measure 70 ns strata — so this shows the shape of the result, not a rediscovery of it. Espitau et al. (2017) did it to BLISS for real, on real hardware.',
        action: () => root.querySelector<HTMLButtonElement>('#attack-btn')?.click()
      },
      {
        target: '#panel-6',
        title: 'And this is the real thing',
        body: 'Everything so far was illustrative. This panel runs the reference Falcon-1024 compiled to WebAssembly — real keys, real 1.3 kB signatures, real timings, on your machine. That’s the whole demo. Explore, and try the quizzes!',
        action: () => root.querySelector<HTMLButtonElement>('#real-falcon-btn')?.click()
      }
    ]);
  });

  // Quiz answering, restore, and score.
  root.querySelectorAll<HTMLButtonElement>('.quiz-option').forEach((btn) => {
    btn.addEventListener('click', () => {
      const quizId = btn.dataset.quiz;
      if (!quizId) return;
      const quiz = quizzes[quizId];
      if (!quiz) return;
      applyQuizAnswer(root, quiz, Number(btn.dataset.idx), true);
    });
  });

  const stored = loadQuizState();
  for (const [quizId, record] of Object.entries(stored)) {
    const quiz = quizzes[quizId];
    if (quiz) applyQuizAnswer(root, quiz, record.chosenIdx, false);
  }
  updateQuizScore();

  document.getElementById('quiz-score')?.addEventListener('click', (event) => {
    const target = event.target as HTMLElement;
    const reviewId = target.dataset.quizReview;
    if (reviewId) {
      const quizEl = root.querySelector<HTMLElement>(`.quiz[data-quiz-id="${reviewId}"]`);
      quizEl?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
      return;
    }
    if (target.dataset.quizReset) {
      resetQuizState();
      resetQuizDom(root);
      updateQuizScore();
    }
  });
}
