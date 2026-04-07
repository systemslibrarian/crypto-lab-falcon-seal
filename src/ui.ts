import { comparisonRowsLevel1, comparisonRowsLevel5, references, type SignatureRow } from './compare';
import {
  generateFalcon512KeyPair,
  signFalcon512Illustrative,
  summarizeSignature,
  verifyFalcon512Illustrative,
  type FalconKeyPair,
  type FalconSignature
} from './falcon';
import { buildLatticePoints } from './ntru';

type UIState = {
  keyPair: FalconKeyPair | null;
  signature: FalconSignature | null;
  signedMessage: string;
  theme: 'light' | 'dark';
};

const state: UIState = {
  keyPair: null,
  signature: null,
  signedMessage: '',
  theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light'
};

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

function latticeSvg(): string {
  const points = buildLatticePoints();
  const circles = points
    .map((p) => {
      const cx = 150 + p.x;
      const cy = 150 - p.y;
      const cls = p.short ? 'lattice-point short' : 'lattice-point';
      return `<circle class="${cls}" cx="${cx}" cy="${cy}" r="3" />`;
    })
    .join('');

  return `
    <svg
      class="lattice"
      viewBox="0 0 300 300"
      role="img"
      aria-label="Two-dimensional lattice visualization showing basis vectors and short vectors"
    >
      <rect x="0" y="0" width="300" height="300" class="lattice-bg"></rect>
      <line x1="150" y1="150" x2="240" y2="130" class="basis-line" />
      <line x1="150" y1="150" x2="188" y2="74" class="basis-line" />
      <circle cx="150" cy="150" r="6" class="origin" />
      ${circles}
      <circle cx="188" cy="74" r="7" class="target" />
      <text x="194" y="66" class="svg-label">short vector target</text>
    </svg>
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

export function renderApp(root: HTMLElement): void {
  root.innerHTML = `
    <div class="page" aria-label="Falcon Seal page wrapper">
      <header class="hero" aria-label="Header">
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
        <div class="hero-actions" aria-label="Header actions">
          <button id="theme-toggle" class="btn" type="button" aria-label="Toggle dark or light mode" aria-pressed="${state.theme === 'dark'}">Toggle theme</button>
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
          Falcon works in polynomial rings of the form <strong>Z[x]/(x<sup>n</sup> + 1)</strong>, where n = 512 or 1024. The underlying hard problem is finding short vectors in high-dimensional lattices (SVP/CVP).
        </p>
        <p>
          <strong>Lattice basis and short vectors:</strong> an NTRU lattice encodes a secret short polynomial pair (f, g) such that h = g/f mod q. The public key h looks random, but the short basis is a trapdoor that enables efficient signing.
        </p>
        <p>
          <strong>Why NTRU lattices produce compact signatures:</strong> ML-DSA (Dilithium) works over <em>module</em> lattices and uses rejection sampling that inflates signatures. Falcon instead uses <em>NTRU</em> lattices with a trapdoor sampler (Fast Fourier Sampling, Ducas &amp; Prest 2016) that directly produces short signature vectors — no inflation step. The result: Falcon-512 signatures are ~666 bytes vs ML-DSA-44's ~2420 bytes — roughly 3–4× smaller at comparable security.
        </p>
        <p>
          Standard parameter sets: <strong>Falcon-512</strong> (NIST Level 1, n=512, sig ≈ 666 B) and <strong>Falcon-1024</strong> (NIST Level 5, n=1024, sig ≈ 1280 B). The modulus q = 12289 in both cases.
        </p>
        <p>
          Bridge: Falcon uses this structure to produce the smallest signatures of any NIST PQC standard — critical for bandwidth-constrained environments like TLS certificate chains and IoT firmware updates.
        </p>
        <div class="viz" aria-label="Lattice visualization container">
          ${latticeSvg()}
          <p class="small-note" aria-label="Lattice visualization legend">Green dots: lattice points. Orange dots: short vectors near the origin (easier targets). Red dot: shortest-vector target. Lines: basis vectors.</p>
        </div>
      </section>

      <section class="panel" aria-labelledby="p2-title">
        <h2 id="p2-title">Panel 2 — Falcon Key Generation</h2>
        <p class="warning" role="note" aria-label="Disclosure note">
          <strong>Illustrative — not production Falcon.</strong> This demo uses real ring arithmetic but does not implement full constant-time trapdoor sampling from the Falcon reference implementation.
        </p>
        <p><strong>Private key:</strong> short polynomial pair (f, g) forming a short basis of the NTRU lattice.</p>
        <p><strong>Public key:</strong> h = g·f<sup>−1</sup> mod q — a compact NTRU public key (educational coefficient-wise approximation here).</p>
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
          <button id="keygen-btn" class="btn" type="button" aria-label="Generate Falcon-512 keypair">Generate Falcon-512 keypair</button>
          <span class="status-chip" aria-label="NIST standard status">NIST PQC Standard (Alternate to ML-DSA)</span>
        </div>
        <div id="key-info" class="output" aria-live="polite" aria-label="Generated key information"></div>
      </section>

      <section class="panel" aria-labelledby="p3-title">
        <h2 id="p3-title">Panel 3 — Sign and Verify</h2>
        <form id="sign-form" class="form" aria-label="Sign and verify form">
          <label for="message-input">Message</label>
          <textarea id="message-input" rows="5" required aria-label="Message to sign">Falcon keeps signatures compact for bandwidth-constrained links.</textarea>
          <div class="actions" aria-label="Signing actions">
            <button id="sign-btn" class="btn" type="submit" aria-label="Sign message with Falcon-512 illustrative flow">Sign</button>
            <button id="verify-btn" class="btn alt" type="button" aria-label="Verify current signature">Verify</button>
            <button id="tamper-btn" class="btn alt" type="button" aria-label="Tamper message and verify failure">Tamper test</button>
            <span class="status-chip recommended" aria-label="Recommendation status">RECOMMENDED (size-constrained environments)</span>
          </div>
        </form>
        <p>
          <strong>Gaussian sampling process:</strong> the signer hashes the message with a fresh nonce, derives a challenge polynomial c, then uses Fast Fourier Sampling to find a short signature vector s such that h·s ≈ c in the NTRU ring. Rejection sampling discards candidates whose squared norm exceeds a bound — this is Falcon's "hash-then-sign" paradigm.
        </p>
        <p class="warning" role="note" aria-label="Implementation warning">
          <strong>Implementation warning:</strong> the Gaussian sampler <em>must</em> be constant-time in production. Non-constant-time sampling leaks secret key information through timing side-channels (see Espitau et al., "Side-Channel Attacks on BLISS Lattice-Based Signatures," 2017, and related Falcon analysis by Fouque et al.).
        </p>
        <p>
          <strong>RNG requirement:</strong> Falcon requires a high-quality random number generator for nonce generation and Gaussian sampling. Weak or predictable RNG compromises signature security by making the sampled vectors predictable.
        </p>
        <div id="sign-info" class="output mono" aria-live="polite" aria-label="Signature details"></div>
        <div id="verify-info" class="output" aria-live="assertive" aria-label="Verification result"></div>
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
      </section>

      <section class="panel" aria-labelledby="p5-title">
        <h2 id="p5-title">Panel 5 — Use Cases and Implementation Warnings</h2>

        <h3>When to choose each algorithm</h3>
        <ul aria-label="Use case list">
          <li><strong>Choose Falcon</strong> when bandwidth dominates: TLS certificate chains, constrained IoT links, blockchain transaction signatures, or any signature-heavy protocol where size matters.</li>
          <li><strong>Choose ML-DSA (Dilithium)</strong> when implementation simplicity, broad library support, and a simpler security proof are more important than raw signature size.</li>
          <li><strong>Choose SLH-DSA (SPHINCS+)</strong> for the most conservative security posture: hash-only assumptions, no lattice hardness dependency, and stateless operation.</li>
        </ul>

        <h3>Implementation warnings</h3>
        <p class="warning" role="note" aria-label="Gaussian sampler timing warning">
          <strong>Timing side-channels:</strong> Falcon's discrete Gaussian sampler has known timing side-channel risks. Espitau, Fouque, Gérard &amp; Rossi (2017) demonstrated practical key recovery via timing analysis against BLISS (a related lattice signature scheme). Falcon's sampler faces analogous risks. <em>Production implementations must use constant-time Gaussian sampling</em> — see the Falcon specification §3.8 and NIST's implementation guidance.
        </p>

        <h3>Real-world deployments and standards</h3>
        <p>
          Falcon is under active consideration by ETSI for post-quantum TLS and certificate profiles. IoT standards bodies (IETF, GlobalPlatform) have noted Falcon's compact signatures as advantageous for constrained device firmware signing and secure boot chains.
        </p>

        <h3>Why this matters in 2026+</h3>
        <p>
          PQ TLS deployment is no longer theoretical. Certificate chain sizes directly affect handshake latency and bandwidth costs. Falcon enables post-quantum TLS without the bandwidth explosion that ML-DSA or SLH-DSA signatures would cause — a critical advantage for mobile networks, CDN edge nodes, and embedded systems.
        </p>

        <div class="links" aria-label="Related demos">
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-dilithium-seal (ML-DSA comparison)">crypto-lab-dilithium-seal</a>
          <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-sphincs-ledger (SLH-DSA comparison)">crypto-lab-sphincs-ledger</a>
          <a class="badge" href="https://github.com/systemslibrarian/crypto-lab-kyber-vault" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-kyber-vault">crypto-lab-kyber-vault</a>
          <a class="badge" href="https://github.com/systemslibrarian/crypto-compare" target="_blank" rel="noreferrer" aria-label="Open crypto-compare signatures category">crypto-compare — Signatures</a>
        </div>
      </section>

      <section class="panel" aria-labelledby="refs-title">
        <h2 id="refs-title">References and Notes</h2>
        <ul>
          ${references.map((r) => `<li>${r}</li>`).join('')}
        </ul>
      </section>

      <footer class="footer" aria-label="Footer quote">
        So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31
      </footer>
    </div>
  `;

  bindEvents(root);
}

function setStatus(id: string, message: string, tone: 'ok' | 'warn' | 'bad' = 'ok'): void {
  const el = document.getElementById(id);
  if (!el) return;
  const prefix = tone === 'ok' ? '\u2705 ' : tone === 'warn' ? '\u26a0\ufe0f ' : '\u274c ';
  el.textContent = prefix + message;
  el.classList.remove('ok', 'warn', 'bad');
  el.classList.add(tone);
}

function bindEvents(root: HTMLElement): void {
  const themeToggle = root.querySelector<HTMLButtonElement>('#theme-toggle');
  const keygenBtn = root.querySelector<HTMLButtonElement>('#keygen-btn');
  const signForm = root.querySelector<HTMLFormElement>('#sign-form');
  const verifyBtn = root.querySelector<HTMLButtonElement>('#verify-btn');
  const tamperBtn = root.querySelector<HTMLButtonElement>('#tamper-btn');
  const msgInput = root.querySelector<HTMLTextAreaElement>('#message-input');

  themeToggle?.addEventListener('click', () => {
    state.theme = state.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = state.theme;
    themeToggle.setAttribute('aria-pressed', state.theme === 'dark' ? 'true' : 'false');
  });

  keygenBtn?.addEventListener('click', async () => {
    keygenBtn.disabled = true;
    setStatus('key-info', 'Generating Falcon-512 keypair...');
    try {
      state.keyPair = await generateFalcon512KeyPair();
      setStatus(
        'key-info',
        `Public key: ${state.keyPair.publicKey.encodedSizeBytes} B | Private key: ${state.keyPair.privateKey.encodedSizeBytes} B | Falcon-1024 sig: 1280 B | ML-DSA-44 sig: 2420 B | SLH-DSA-128s sig: 7856 B`,
        'ok'
      );
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
    setStatus('sign-info', 'Signing with illustrative Falcon-512 flow...');
    try {
      const result = await signFalcon512Illustrative(message, state.keyPair);
      state.signature = result.signature;
      setStatus(
        'sign-info',
        `Published Falcon-512 signature size: ${result.signature.publishedSizeBytes} B (~666 B). Simulated payload: ${result.signature.simulatedPayloadBytes} B. Rejection attempts: ${result.stats.attempts}. Squared norm: ${result.stats.squaredNorm}. ${summarizeSignature(result.signature)}`,
        'ok'
      );
      setStatus('verify-info', 'Signature generated. Run verify.', 'ok');
    } finally {
      if (signBtn) signBtn.disabled = false;
    }
  });

  verifyBtn?.addEventListener('click', async () => {
    if (!state.keyPair || !state.signature) {
      setStatus('verify-info', 'Generate keypair and sign before verify.', 'warn');
      return;
    }
    const message = msgInput?.value ?? '';
    const valid = await verifyFalcon512Illustrative(message, state.signature, state.keyPair.publicKey);
    if (valid) {
      setStatus('verify-info', 'Verification passed. Signature matches this message.', 'ok');
      return;
    }
    setStatus('verify-info', 'Verification failed. Message or signature was altered.', 'bad');
  });

  tamperBtn?.addEventListener('click', async () => {
    if (!state.keyPair || !state.signature) {
      setStatus('verify-info', 'Sign a message first to run tamper test.', 'warn');
      return;
    }
    const tampered = `${state.signedMessage} [tampered]`;
    const valid = await verifyFalcon512Illustrative(tampered, state.signature, state.keyPair.publicKey);
    if (valid) {
      setStatus('verify-info', 'Tamper test unexpectedly passed. (This should not happen.)', 'bad');
      return;
    }
    setStatus('verify-info', 'Tamper test failed verification as expected.', 'ok');
  });
}
