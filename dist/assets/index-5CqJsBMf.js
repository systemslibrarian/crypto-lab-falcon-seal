(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const s of document.querySelectorAll('link[rel="modulepreload"]'))n(s);new MutationObserver(s=>{for(const i of s)if(i.type==="childList")for(const r of i.addedNodes)r.tagName==="LINK"&&r.rel==="modulepreload"&&n(r)}).observe(document,{childList:!0,subtree:!0});function a(s){const i={};return s.integrity&&(i.integrity=s.integrity),s.referrerPolicy&&(i.referrerPolicy=s.referrerPolicy),s.crossOrigin==="use-credentials"?i.credentials="include":s.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function n(s){if(s.ep)return;s.ep=!0;const i=a(s);fetch(s.href,i)}})();const F=[{parameterSet:"Falcon-512",publicKeyBytes:897,signatureBytes:666,keygenTimeMs:8.1,signTimeMs:5.5,verifyTimeMs:.9,securityAssumption:"NTRU lattice (SIS/R-SIS style hardness in NTRU setting)",implementationComplexity:"High (FFT + Gaussian sampler)",status:"Recommended for size-constrained deployments"},{parameterSet:"ML-DSA-44",publicKeyBytes:1312,signatureBytes:2420,keygenTimeMs:.8,signTimeMs:1.4,verifyTimeMs:.6,securityAssumption:"Module lattice (Module-SIS / Module-LWE)",implementationComplexity:"Medium",status:"NIST primary lattice standard"},{parameterSet:"SLH-DSA-128s",publicKeyBytes:32,signatureBytes:7856,keygenTimeMs:.2,signTimeMs:45,verifyTimeMs:9.8,securityAssumption:"Hash-based (stateless hypertree)",implementationComplexity:"Medium-High",status:"Conservative, large signatures"}],L=[{parameterSet:"Falcon-1024",publicKeyBytes:1793,signatureBytes:1280,keygenTimeMs:31,signTimeMs:21,verifyTimeMs:1.8,securityAssumption:"NTRU lattice",implementationComplexity:"High (sampler subtlety)",status:"Compact at NIST Level 5"},{parameterSet:"ML-DSA-87",publicKeyBytes:2592,signatureBytes:4627,keygenTimeMs:2,signTimeMs:3.5,verifyTimeMs:1.2,securityAssumption:"Module lattice (Module-SIS / Module-LWE)",implementationComplexity:"Medium",status:"Broader implementation footprint"},{parameterSet:"SLH-DSA-256s",publicKeyBytes:64,signatureBytes:29792,keygenTimeMs:.3,signTimeMs:145,verifyTimeMs:31,securityAssumption:"Hash-based (stateless hypertree)",implementationComplexity:"Medium-High",status:"Very large signatures"}],R=["Falcon specification v1.2: Fouque, Kirchner, Tibouchi, Wallet, et al.","Ducas & Prest (2016): Fast Fourier Sampling over q-ary lattices.","NIST FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 related PQ signature context.","Timing numbers are indicative reference-software style measurements and hardware-dependent."],x={n:512,q:12289};function H(t,e){const a=t%e;return a<0?a+e:a}function B(t,e){const a=H(t,e);return a>e/2?a-e:a}function T(t){const e=new Int16Array(t),a=new Uint8Array(t);crypto.getRandomValues(a);for(let n=0;n<t;n+=1){const s=a[n]%3;e[n]=s===0?-1:s===1?0:1}return e}function k(t,e=1.2){const a=new Int16Array(t),n=new Uint32Array(t*2);crypto.getRandomValues(n);for(let s=0;s<t;s+=1){const i=Math.max(n[s*2]/4294967295,1e-12),r=n[s*2+1]/4294967295,o=Math.sqrt(-2*Math.log(i))*Math.cos(2*Math.PI*r),u=Math.round(o*e);a[s]=Math.max(-8,Math.min(8,u))}return a}function v(t,e,a){const n=new Int16Array(t.length);for(let s=0;s<t.length;s+=1)n[s]=B(t[s]-e[s],a);return n}function w(t,e,a){const n=t.length,s=new Int32Array(n*2);for(let r=0;r<n;r+=1)for(let o=0;o<n;o+=1)s[r+o]+=t[r]*e[o];const i=new Int16Array(n);for(let r=0;r<n;r+=1){const o=s[r]-s[r+n];i[r]=B(o,a)}return i}function g(t){let e=0;for(let a=0;a<t.length;a+=1)e+=t[a]*t[a];return e}function I(t,e,a=40){const n=new Int16Array(e);let s=0;for(let i=0;i<a;i+=1){const r=t[s%t.length]%e,o=t[(s+1)%t.length]&1?-1:1;n[r]=o,s+=2}return n}function K(){const t=[],e={x:42,y:10},a={x:18,y:36};for(let n=-4;n<=4;n+=1)for(let s=-4;s<=4;s+=1){const i=n*e.x+s*a.x,r=n*e.y+s*a.y,o=Math.sqrt(i*i+r*r);t.push({x:i,y:r,short:o<55})}return t}const C=18e3;function f(t){return[...t].map(e=>e.toString(16).padStart(2,"0")).join("")}function P(t){const e=new Uint8Array(t.length/2);for(let a=0;a<e.length;a+=1)e[a]=Number.parseInt(t.slice(a*2,a*2+2),16);return e}async function y(t){const e=await crypto.subtle.digest("SHA-256",t);return new Uint8Array(e)}function N(...t){const e=t.reduce((s,i)=>s+i.length,0),a=new Uint8Array(e);let n=0;for(const s of t)a.set(s,n),n+=s.length;return a}function b(t){const e=new Uint8Array(t.length*2),a=new DataView(e.buffer);for(let n=0;n<t.length;n+=1)a.setInt16(n*2,t[n],!0);return e}function z(t,e){const a=t.length,n=x.q,s=new Int16Array(a);for(let i=0;i<a;i+=1){const r=t[i]===0?1:t[i];s[i]=(e[i]*4096/r|0)%n}return s}function E(){const t=new Uint8Array(16);return crypto.getRandomValues(t),f(t)}async function U(){const{n:t,q:e}=x,a=T(t),n=T(t),s=z(a,n),i=new Uint8Array(32);return crypto.getRandomValues(i),{publicKey:{h:s,n:t,q:e,encodedSizeBytes:897},privateKey:{f:a,g:n,seedHex:f(i),encodedSizeBytes:1281}}}async function G(t,e){const n=new TextEncoder().encode(t),s=E(),i=P(s),r=b(e.publicKey.h),o=N(n,i,r),u=await y(o),d=I(u,e.publicKey.n);let m=0,p=k(e.publicKey.n),h=v(w(e.publicKey.h,p,e.publicKey.q),d,e.publicKey.q),S=g(p)+g(h);for(;S>C&&m<64;)p=k(e.publicKey.n),h=v(w(e.publicKey.h,p,e.publicKey.q),d,e.publicKey.q),S=g(p)+g(h),m+=1;const q=f(await y(b(h))),$=16+p.length*2+32;return{signature:{mode:"Illustrative - not production Falcon",n:e.publicKey.n,nonceHex:s,s:p,uDigestHex:q,publishedSizeBytes:666,simulatedPayloadBytes:$},stats:{attempts:m+1,squaredNorm:S}}}async function M(t,e,a){const s=new TextEncoder().encode(t),i=P(e.nonceHex),r=b(a.h),o=N(s,i,r),u=await y(o),d=I(u,a.n),m=v(w(a.h,e.s,a.q),d,a.q);return f(await y(b(m)))===e.uDigestHex}function O(t){const e=Array.from(t.s.slice(0,24)).join(",");return`mode=${t.mode}; nonce=${t.nonceHex}; s[0..23]=${e}; digest=${t.uDigestHex}`}const l={keyPair:null,signature:null,signedMessage:""};function V(t,e){const a=Math.max(4,Math.round(t/e*100));return`<div class="bar-wrap" aria-label="bar for ${t} bytes"><div class="bar" style="width:${a}%"></div><span>${t} B</span></div>`}function A(t){return t.map(e=>`
      <tr>
        <th scope="row">${e.parameterSet}</th>
        <td>${e.publicKeyBytes}</td>
        <td>${e.signatureBytes}</td>
        <td>${e.keygenTimeMs}</td>
        <td>${e.signTimeMs}</td>
        <td>${e.verifyTimeMs}</td>
        <td>${e.securityAssumption}</td>
        <td>${e.implementationComplexity}</td>
      </tr>
    `).join("")}function j(){return`
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
      ${K().map(a=>{const n=150+a.x,s=150-a.y;return`<circle class="${a.short?"lattice-point short":"lattice-point"}" cx="${n}" cy="${s}" r="3" />`}).join("")}
      <circle cx="188" cy="74" r="7" class="target" />
      <text x="194" y="66" class="svg-label">short vector target</text>
    </svg>
  `}function W(){const t=[...F,...L],e=Math.max(...t.map(a=>a.signatureBytes));return t.map(a=>`
      <div class="bar-row" aria-label="Signature size bar for ${a.parameterSet}">
        <div class="bar-title">${a.parameterSet}</div>
        ${V(a.signatureBytes,e)}
      </div>
    `).join("")}function _(t){const e=document.documentElement.dataset.theme==="light"?"light":"dark";t.innerHTML=`
    <div class="page" aria-label="Falcon Seal page wrapper">
      <header class="hero" aria-label="Header">
        <button
          id="theme-toggle"
          class="theme-toggle"
          type="button"
          style="position: absolute; top: 0; right: 0"
          aria-label="${e==="dark"?"Switch to light mode":"Switch to dark mode"}"
          aria-pressed="${e==="dark"?"true":"false"}"
        >${e==="dark"?"🌙":"☀️"}</button>
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
          ${j()}
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
            <tbody>${A(F)}</tbody>
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
            <tbody>${A(L)}</tbody>
          </table>
        </div>
        <div class="bars" aria-label="Signature size visual comparison">
          ${W()}
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
          ${R.map(a=>`<li>${a}</li>`).join("")}
        </ul>
      </section>

      <footer class="footer" aria-label="Footer quote">
        So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31
      </footer>
    </div>
  `,Q(t)}function c(t,e,a="ok"){const n=document.getElementById(t);if(!n)return;const s=a==="ok"?"✅ ":a==="warn"?"⚠️ ":"❌ ";n.textContent=s+e,n.classList.remove("ok","warn","bad"),n.classList.add(a)}function Q(t){const e=t.querySelector("#keygen-btn"),a=t.querySelector("#sign-form"),n=t.querySelector("#verify-btn"),s=t.querySelector("#tamper-btn"),i=t.querySelector("#message-input");e==null||e.addEventListener("click",async()=>{e.disabled=!0,c("key-info","Generating Falcon-512 keypair...");try{l.keyPair=await U(),c("key-info",`Public key: ${l.keyPair.publicKey.encodedSizeBytes} B | Private key: ${l.keyPair.privateKey.encodedSizeBytes} B | Falcon-1024 sig: 1280 B | ML-DSA-44 sig: 2420 B | SLH-DSA-128s sig: 7856 B`,"ok")}finally{e.disabled=!1}}),a==null||a.addEventListener("submit",async r=>{if(r.preventDefault(),!l.keyPair){c("verify-info","Generate a keypair first.","warn");return}const o=(i==null?void 0:i.value)??"";if(!o.trim()){c("verify-info","Message cannot be empty.","bad");return}const u=t.querySelector("#sign-btn");u&&(u.disabled=!0),l.signedMessage=o,c("sign-info","Signing with illustrative Falcon-512 flow...");try{const d=await G(o,l.keyPair);l.signature=d.signature,c("sign-info",`Published Falcon-512 signature size: ${d.signature.publishedSizeBytes} B (~666 B). Simulated payload: ${d.signature.simulatedPayloadBytes} B. Rejection attempts: ${d.stats.attempts}. Squared norm: ${d.stats.squaredNorm}. ${O(d.signature)}`,"ok"),c("verify-info","Signature generated. Run verify.","ok")}finally{u&&(u.disabled=!1)}}),n==null||n.addEventListener("click",async()=>{if(!l.keyPair||!l.signature){c("verify-info","Generate keypair and sign before verify.","warn");return}const r=(i==null?void 0:i.value)??"";if(await M(r,l.signature,l.keyPair.publicKey)){c("verify-info","Verification passed. Signature matches this message.","ok");return}c("verify-info","Verification failed. Message or signature was altered.","bad")}),s==null||s.addEventListener("click",async()=>{if(!l.keyPair||!l.signature){c("verify-info","Sign a message first to run tamper test.","warn");return}const r=`${l.signedMessage} [tampered]`;if(await M(r,l.signature,l.keyPair.publicKey)){c("verify-info","Tamper test unexpectedly passed. (This should not happen.)","bad");return}c("verify-info","Tamper test failed verification as expected.","ok")})}function J(){const t=document.documentElement,e=document.querySelector("#theme-toggle");if(!e)return;const a=s=>{e.textContent=s==="dark"?"🌙":"☀️",e.setAttribute("aria-label",s==="dark"?"Switch to light mode":"Switch to dark mode"),e.setAttribute("aria-pressed",s==="dark"?"true":"false")};let n=t.getAttribute("data-theme")==="light"?"light":"dark";t.setAttribute("data-theme",n),a(n),e.addEventListener("click",()=>{n=n==="dark"?"light":"dark",t.setAttribute("data-theme",n),localStorage.setItem("theme",n),a(n)})}const D=document.querySelector("#app");if(!D)throw new Error("App root not found");_(D);J();
