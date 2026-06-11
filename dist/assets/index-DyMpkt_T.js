(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const a of document.querySelectorAll('link[rel="modulepreload"]'))n(a);new MutationObserver(a=>{for(const i of a)if(i.type==="childList")for(const o of i.addedNodes)o.tagName==="LINK"&&o.rel==="modulepreload"&&n(o)}).observe(document,{childList:!0,subtree:!0});function s(a){const i={};return a.integrity&&(i.integrity=a.integrity),a.referrerPolicy&&(i.referrerPolicy=a.referrerPolicy),a.crossOrigin==="use-credentials"?i.credentials="include":a.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function n(a){if(a.ep)return;a.ep=!0;const i=s(a);fetch(a.href,i)}})();const W=[{parameterSet:"Falcon-512",publicKeyBytes:897,signatureBytes:666,keygenTimeMs:8.1,signTimeMs:5.5,verifyTimeMs:.9,securityAssumption:"NTRU lattice (SIS/R-SIS style hardness in NTRU setting)",implementationComplexity:"High (FFT + Gaussian sampler)",status:"Recommended for size-constrained deployments"},{parameterSet:"ML-DSA-44",publicKeyBytes:1312,signatureBytes:2420,keygenTimeMs:.8,signTimeMs:1.4,verifyTimeMs:.6,securityAssumption:"Module lattice (Module-SIS / Module-LWE)",implementationComplexity:"Medium",status:"NIST primary lattice standard"},{parameterSet:"SLH-DSA-128s",publicKeyBytes:32,signatureBytes:7856,keygenTimeMs:.2,signTimeMs:45,verifyTimeMs:9.8,securityAssumption:"Hash-based (stateless hypertree)",implementationComplexity:"Medium-High",status:"Conservative, large signatures"}],_=[{parameterSet:"Falcon-1024",publicKeyBytes:1793,signatureBytes:1280,keygenTimeMs:31,signTimeMs:21,verifyTimeMs:1.8,securityAssumption:"NTRU lattice",implementationComplexity:"High (sampler subtlety)",status:"Compact at NIST Level 5"},{parameterSet:"ML-DSA-87",publicKeyBytes:2592,signatureBytes:4627,keygenTimeMs:2,signTimeMs:3.5,verifyTimeMs:1.2,securityAssumption:"Module lattice (Module-SIS / Module-LWE)",implementationComplexity:"Medium",status:"Broader implementation footprint"},{parameterSet:"SLH-DSA-256s",publicKeyBytes:64,signatureBytes:29792,keygenTimeMs:.3,signTimeMs:145,verifyTimeMs:31,securityAssumption:"Hash-based (stateless hypertree)",implementationComplexity:"Medium-High",status:"Very large signatures"}],ue=["Falcon specification v1.2: Fouque, Kirchner, Tibouchi, Wallet, et al.","Ducas & Prest (2016): Fast Fourier Sampling over q-ary lattices.","NIST FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 related PQ signature context.","Timing numbers are indicative reference-software style measurements and hardware-dependent."],pe={n:512,q:12289},me={n:1024,q:12289};function he(e,t){const s=e%t;return s<0?s+t:s}function ge(e,t){const s=he(e,t);return s>t/2?s-t:s}function T(e){const t=new Int16Array(e),s=new Uint8Array(e*2);crypto.getRandomValues(s);let n=0;for(let a=0;a<e;){n>=s.length&&(crypto.getRandomValues(s),n=0);const i=s[n++];if(i<255){const o=i%3;t[a]=o===0?-1:o===1?0:1,a+=1}}return t}function E(e,t=1.2){const s=new Int16Array(e),n=new Uint32Array(e*2);crypto.getRandomValues(n);for(let a=0;a<e;a+=1){const i=Math.max(n[a*2]/4294967295,1e-12),o=n[a*2+1]/4294967295,d=Math.sqrt(-2*Math.log(i))*Math.cos(2*Math.PI*o),l=Math.round(d*t);s[a]=Math.max(-8,Math.min(8,l))}return s}function J(e,t,s){const n=new Int16Array(e.length);for(let a=0;a<e.length;a+=1)n[a]=ge(e[a]-t[a],s);return n}function P(e){let t=0;for(let s=0;s<e.length;s+=1)t+=e[s]*e[s];return t}function Q(e,t,s=40){const n=new Int16Array(t);let a=0,i=0;for(;i<s;){if(a+1>=e.length)throw new Error(`Not enough hash bytes to reach weight ${s}. Added ${i} so far.`);const o=e[a],d=e[a+1];a+=2;const l=o<<8|d,r=l%t,u=l&32768?-1:1;n[r]===0&&(n[r]=u,i+=1)}return n}function ye(e,t,s=1.2){const n=[],l=new Uint32Array(e*2);crypto.getRandomValues(l);for(let r=0;r<e;r+=1){const u=Math.max(l[r*2]/4294967295,1e-12),m=l[r*2+1]/4294967295,p=Math.sqrt(-2*Math.log(u))*Math.cos(2*Math.PI*m),h=Math.max(-8,Math.min(8,Math.round(p*s))),g=Math.abs(h),b=(Math.random()-.5)*22,y=t==="constant-time"?820+9*70+b:820+(g+1)*70+b;n.push({value:h,nanos:Math.max(0,Math.round(y))})}return n}const w={ax:42,ay:10,bx:18,by:36};function be(e=w){const t=[];for(let s=-4;s<=4;s+=1)for(let n=-4;n<=4;n+=1){const a=s*e.ax+n*e.bx,i=s*e.ay+n*e.by,o=Math.sqrt(a*a+i*i);t.push({x:a,y:i,short:o<55})}return t}function fe(e,t){const n=Math.max(0,e.length-32);let a=0,i=0,o=0,d=0;for(let r=0;r<32;r+=1)a+=e[r],i+=t[r],o+=e[n+r],d+=t[n+r];const l=5;return{ax:a*l,ay:i*l,bx:o*l,by:d*l}}function ve(e){const s=Math.max(0,e.length-32);let n=0,a=0;for(let i=0;i<32;i+=1)n+=e[i],a+=e[s+i];return{x:n*5,y:a*5}}const Se=12289;function F(e,t,s){let n=1,a=(e%s+s)%s,i=t;for(;i>0;)i&1&&(n=n*a%s),a=a*a%s,i=Math.floor(i/2);return n}function A(e,t){return F(e,t-2,t)}function we(e,t){for(let s=2;s<t;s+=1){const n=F(s,(t-1)/(2*e),t);if(F(n,e,t)===t-1)return n}throw new Error(`No primitive 2n-th root of unity found for n=${e}, q=${t}`)}const j=new Map;function I(e){const t=j.get(e);if(t)return t;const s=Math.log2(e),n=Math.round(s);if(Math.abs(s-n)>1e-9)throw new Error(`NTT requires n a power of two, got ${e}`);const a=Se,i=we(e,a),o=A(i,a),d=A(e,a),l=new Int32Array(e),r=new Int32Array(e);let u=1,m=1;for(let h=0;h<e;h+=1)l[h]=u,r[h]=m,u=u*i%a,m=m*o%a;const p={n:e,q:a,bits:n,psi:i,psiInv:o,nInv:d,psiPow:l,psiInvPow:r};return j.set(e,p),p}function ke(e,t){let s=0,n=e;for(let a=0;a<t;a+=1)s=s<<1|n&1,n>>>=1;return s}function Y(e,t,s,n){const a=e.length;for(let i=0;i<a;i+=1){const o=ke(i,n);if(i<o){const d=e[i];e[i]=e[o],e[o]=d}}for(let i=2;i<=a;i<<=1){const o=i>>>1,d=F(t,a/i,s);for(let l=0;l<a;l+=i){let r=1;for(let u=0;u<o;u+=1){const m=e[l+u],p=e[l+u+o]*r%s,h=m+p;e[l+u]=h>=s?h-s:h;const g=m-p;e[l+u+o]=g<0?g+s:g,r=r*d%s}}}}function $e(e,t){const s=new Int32Array(e.length);for(let n=0;n<e.length;n+=1){let a=e[n]%t;a<0&&(a+=t),s[n]=a}return s}function R(e,t){const s=$e(e,t.q);for(let a=0;a<t.n;a+=1)s[a]=s[a]*t.psiPow[a]%t.q;const n=t.psi*t.psi%t.q;return Y(s,n,t.q,t.bits),s}function Z(e,t){const s=new Int32Array(e),n=t.psi*t.psi%t.q,a=A(n,t.q);Y(s,a,t.q,t.bits);for(let i=0;i<t.n;i+=1){let o=s[i]*t.nInv%t.q;o=o*t.psiInvPow[i]%t.q,s[i]=o}return s}function X(e,t){const s=new Int16Array(e.length),n=t>>>1;for(let a=0;a<e.length;a+=1)s[a]=e[a]>n?e[a]-t:e[a];return s}function z(e,t,s){const n=R(e,s),a=R(t,s);for(let o=0;o<s.n;o+=1)n[o]=n[o]*a[o]%s.q;const i=Z(n,s);return X(i,s.q)}function D(e,t){const s=R(e,t);for(let a=0;a<t.n;a+=1){if(s[a]===0)return null;s[a]=A(s[a],t.q)}const n=Z(s,t);return X(n,t.q)}const Me={name:"Falcon-512",params:pe,publishedPublicKeyBytes:897,publishedPrivateKeyBytes:1281,publishedSignatureBytes:666,rejectionBoundSqNorm:800},xe={name:"Falcon-1024",params:me,publishedPublicKeyBytes:1793,publishedPrivateKeyBytes:2305,publishedSignatureBytes:1280,rejectionBoundSqNorm:1580},ee={"Falcon-512":Me,"Falcon-1024":xe};function M(e){return[...e].map(t=>t.toString(16).padStart(2,"0")).join("")}function te(e){const t=new Uint8Array(e.length/2);for(let s=0;s<t.length;s+=1)t[s]=Number.parseInt(e.slice(s*2,s*2+2),16);return t}async function q(e){const t=await crypto.subtle.digest("SHA-256",e);return new Uint8Array(t)}async function se(e,t){const s=new Uint8Array(t);let n=0,a=0;for(;n<t;){const i=C(e,new Uint8Array([a])),o=new Uint8Array(await crypto.subtle.digest("SHA-256",i)),d=Math.min(o.length,t-n);s.set(o.slice(0,d),n),n+=d,a+=1}return s}function C(...e){const t=e.reduce((a,i)=>a+i.length,0),s=new Uint8Array(t);let n=0;for(const a of e)s.set(a,n),n+=a.length;return s}function L(e){const t=new Uint8Array(e.length*2),s=new DataView(t.buffer);for(let n=0;n<e.length;n+=1)s.setInt16(n*2,e[n],!0);return t}function Te(){const e=new Uint8Array(16);return crypto.getRandomValues(e),M(e)}async function Be(e){const{n:t,q:s}=e.params,n=I(t);let a=T(t),i=T(t),o=D(a,n),d=0;for(;o===null;)if(d+=1,a=T(t),i=T(t),o=D(a,n),d>64)throw new Error("Failed to find invertible f after 64 attempts");const l=z(i,o,n),r=new Uint8Array(32);return crypto.getRandomValues(r),{parameterSet:e,publicKey:{h:l,n:t,q:s,encodedSizeBytes:e.publishedPublicKeyBytes},privateKey:{f:a,g:i,seedHex:M(r),encodedSizeBytes:e.publishedPrivateKeyBytes,regenerationsForInvertibility:d}}}async function Fe(e,t){const s=t.parameterSet,{n,q:a}=s.params,i=I(n),d=new TextEncoder().encode(e),l=Te(),r=te(l),u=L(t.publicKey.h),m=C(d,r,u),p=await q(m),h=await se(p,256),g=Q(h,n),b=[];let y=E(n),f=P(y),S=1;for(b.push({attempt:S,squaredNorm:f,accepted:f<=s.rejectionBoundSqNorm});f>s.rejectionBoundSqNorm&&S<32;)y=E(n),f=P(y),S+=1,b.push({attempt:S,squaredNorm:f,accepted:f<=s.rejectionBoundSqNorm});const H=z(t.publicKey.h,y,i),x=J(H,g,a),ce=M(await q(L(x))),de=16+y.length*2+32;return{signature:{mode:"Illustrative - not production Falcon",parameterSetName:s.name,n,nonceHex:l,s:y,digestHex:ce,challengePoly:g,hashHex:M(p),publishedSizeBytes:s.publishedSignatureBytes,simulatedPayloadBytes:de},attempts:b,rejectionBound:s.rejectionBoundSqNorm,finalSquaredNorm:f}}async function K(e,t,s){const n=ee[t.parameterSetName],{n:a,q:i}=n.params,o=I(a),d=P(t.s),l=d<=n.rejectionBoundSqNorm,u=new TextEncoder().encode(e),m=te(t.nonceHex),p=L(s.h),h=C(u,m,p),g=await q(h),b=await se(g,256),y=Q(b,a),f=z(s.h,t.s,o),S=J(f,y,i),x=M(await q(L(S)))===t.digestHex;return{normCheckOk:l,recomputeCheckOk:x,overall:l&&x,observedSquaredNorm:d,rejectionBound:n.rejectionBoundSqNorm}}function Ae(e){const t=Array.from(e.s.slice(0,16)).join(",");return`${e.parameterSetName} · nonce=${e.nonceHex.slice(0,16)}… · s[0..15]=[${t}] · digest=${e.digestHex.slice(0,32)}…`}function qe(e,t,s,n){return JSON.stringify({scheme:e.parameterSetName,mode:e.mode,message:t,nonceHex:e.nonceHex,hashHex:e.hashHex,digestHex:e.digestHex,sPreview:Array.from(e.s.slice(0,32)),sLength:e.s.length,observedSquaredNorm:n,rejectionBound:s,publishedSizeBytes:e.publishedSizeBytes,simulatedPayloadBytes:e.simulatedPayloadBytes},null,2)}const c={parameterSetName:"Falcon-512",keyPair:null,signResult:null,verifyResult:null,signedMessage:"",message:"Falcon keeps signatures compact for bandwidth-constrained links.",samplerMode:"constant-time"};function ae(){return ee[c.parameterSetName]}function Le(e,t){const s=Math.max(4,Math.round(e/t*100));return`<div class="bar-wrap" aria-label="bar for ${e} bytes"><div class="bar" style="width:${s}%"></div><span>${e} B</span></div>`}function U(e){return e.map(t=>`
      <tr>
        <th scope="row">${t.parameterSet}</th>
        <td>${t.publicKeyBytes}</td>
        <td>${t.signatureBytes}</td>
        <td>${t.keygenTimeMs}</td>
        <td>${t.signTimeMs}</td>
        <td>${t.verifyTimeMs}</td>
        <td>${t.securityAssumption}</td>
        <td>${t.implementationComplexity}</td>
      </tr>
    `).join("")}function N(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;")}function ne(){const e=c.keyPair,t=e?fe(e.privateKey.f,e.privateKey.g):w,s={ax:Math.max(-120,Math.min(120,t.ax||w.ax)),ay:Math.max(-120,Math.min(120,t.ay||w.ay)),bx:Math.max(-120,Math.min(120,t.bx||w.bx)),by:Math.max(-120,Math.min(120,t.by||w.by))},a=be(s).map(p=>{const h=150+p.x,g=150-p.y;return`<circle class="${p.short?"lattice-point short":"lattice-point"}" cx="${h.toFixed(1)}" cy="${g.toFixed(1)}" r="3" />`}).join(""),i=`<line x1="150" y1="150" x2="${150+s.ax}" y2="${150-s.ay}" class="basis-line${e?" private":""}" />`,o=`<line x1="150" y1="150" x2="${150+s.bx}" y2="${150-s.by}" class="basis-line${e?" private":""}" />`;let d="";if(c.signResult){const p=ve(c.signResult.signature.s),h=Math.max(-130,Math.min(130,p.x)),g=Math.max(-130,Math.min(130,p.y));d=`
      <line x1="150" y1="150" x2="${150+h}" y2="${150-g}" class="sig-vector" />
      <circle cx="${150+h}" cy="${150-g}" r="6" class="sig-point" />
      <text x="${150+h+8}" y="${150-g-6}" class="svg-label">s (projected)</text>
    `}const l=188,r=74,u=e?"":`<circle cx="${l}" cy="${r}" r="7" class="target" /><text x="${l+6}" y="${r-8}" class="svg-label">short-vector target</text>`,m=e?c.signResult?"Green basis lines: projection of your private short basis (f, g). Orange dot: signature vector s (projected).":"Green basis lines: projection of your private short basis (f, g) — the trapdoor. Generate a signature to see where s lands.":"Green dots: lattice points. Orange dots: short vectors near the origin. Red dot: shortest-vector target. Lines: a generic short basis.";return`
    <svg
      class="lattice"
      viewBox="0 0 300 300"
      role="img"
      aria-label="Two-dimensional lattice visualization"
    >
      <rect x="0" y="0" width="300" height="300" class="lattice-bg"></rect>
      ${i}
      ${o}
      <circle cx="150" cy="150" r="6" class="origin" />
      ${a}
      ${u}
      ${d}
    </svg>
    <p class="small-note" aria-label="Lattice visualization legend">${m}</p>
  `}function Ne(){const e=[...W,..._],t=Math.max(...e.map(s=>s.signatureBytes));return e.map(s=>`
      <div class="bar-row" aria-label="Signature size bar for ${s.parameterSet}">
        <div class="bar-title">${s.parameterSet}</div>
        ${Le(s.signatureBytes,t)}
      </div>
    `).join("")}function ie(){const t=new TextEncoder().encode(c.message||"").length,s=[{label:"Falcon-512",sigBytes:666},{label:"Falcon-1024",sigBytes:1280},{label:"ML-DSA-44",sigBytes:2420},{label:"ML-DSA-87",sigBytes:4627},{label:"SLH-DSA-128s",sigBytes:7856}],n=s[s.length-1].sigBytes+t;return s.map(a=>{const i=Math.max(.4,t/n*100),o=a.sigBytes/n*100,d=t===0?"∞":(a.sigBytes/Math.max(1,t)).toFixed(1);return`
        <div class="vsize-row" aria-label="Size comparison for ${a.label}">
          <div class="vsize-title">${a.label} <span class="vsize-ratio">sig is ${d}× your message</span></div>
          <div class="vsize-strip">
            <div class="vsize-msg" style="width:${i}%" title="${t} B message"></div>
            <div class="vsize-sig" style="width:${o}%" title="${a.sigBytes} B signature"></div>
            <span class="vsize-label">${t} B msg · ${a.sigBytes} B sig</span>
          </div>
        </div>
      `}).join("")}function oe(e){if(e.length===0)return'<p class="small-note">Run the sampler to see a timing histogram.</p>';const t=Math.min(...e.map(r=>r.nanos)),s=Math.max(...e.map(r=>r.nanos)),n=24,a=Math.max(1,s-t),i=new Array(n).fill(0);for(const r of e){const u=Math.min(n-1,Math.floor((r.nanos-t)/a*n));i[u]+=1}const o=Math.max(...i,1),d=i.map((r,u)=>{const m=r/o*100,p=Math.round(t+a*u/n),h=Math.round(t+a*(u+1)/n);return`<div class="histo-col" style="height:${m.toFixed(1)}%" title="${p}–${h} ns · ${r} samples" aria-label="${p} to ${h} nanoseconds: ${r} samples"></div>`}).join(""),l=c.samplerMode==="leaky"?`Wide spread (${t}–${s} ns). Timing correlates with |sample| — an attacker reading these timings can recover bits of the secret distribution. This is the Espitau et al. 2017 attack vector.`:`Tight cluster (${t}–${s} ns). Time is independent of the sampled value. This is what Falcon §3.8 requires.`;return`
    <div class="histo" aria-label="Per-sample timing histogram">${d}</div>
    <p class="small-note">${l}</p>
  `}function Pe(){var i;const e=(i=c.signResult)==null?void 0:i.signature;if(!e)return"";const t=96,s=Math.ceil(e.n/t),n=[];for(let o=0;o<t;o+=1){const d=o*s,l=Math.min(e.n,d+s);let r=0,u=0;for(let p=d;p<l;p+=1)e.challengePoly[p]>0?r+=1:e.challengePoly[p]<0&&(u+=1);const m=r>0&&u>0?"mixed":r>0?"pos":u>0?"neg":"zero";n.push(`<div class="c-cell ${m}" title="indices ${d}–${l-1}: +${r} / −${u}"></div>`)}return`
    <div class="hash-challenge" aria-label="Hash to challenge polynomial">
      <div class="hash-row"><span class="label">SHA-256(message ‖ nonce ‖ h):</span> <code class="mono">${`${e.hashHex.slice(0,24)}…${e.hashHex.slice(-24)}`}</code></div>
      <div class="label">Challenge polynomial c (n=${e.n}, weight=40, ±1 sparse):</div>
      <div class="c-strip" role="img" aria-label="Sparse challenge polynomial coefficients">${n.join("")}</div>
      <div class="c-legend"><span class="swatch pos"></span>+1 &nbsp; <span class="swatch neg"></span>−1 &nbsp; <span class="swatch zero"></span>0</div>
    </div>
  `}function Re(){const e=c.signResult;if(!e)return"";const t=e.rejectionBound,s=e.attempts.map((n,a)=>{const i=Math.min(140,Math.round(n.squaredNorm/t*100)),o=n.accepted?"attempt-row ok":"attempt-row bad",d=n.accepted?"accepted ✅":"rejected ❌";return`
        <li class="${o}" style="animation-delay:${a*160}ms">
          <span class="attempt-n">try ${n.attempt}</span>
          <div class="attempt-bar"><div class="attempt-fill" style="width:${i}%"></div><div class="attempt-bound" title="rejection bound"></div></div>
          <span class="attempt-norm mono">‖s‖² = ${n.squaredNorm} / ${t}</span>
          <span class="attempt-verdict">${d}</span>
        </li>
      `}).join("");return`
    <div class="attempts-block" aria-label="Rejection sampling attempts">
      <div class="attempts-header">Rejection-sampling loop · bound ‖s‖² ≤ ${t}</div>
      <ol class="attempts">${s}</ol>
    </div>
  `}function Ie(){const e=c.verifyResult;if(!e)return"";const t=e.normCheckOk?"✅":"❌",s=e.recomputeCheckOk?"✅":"❌",n=e.overall?'<span class="badge ok-badge">Verified</span>':'<span class="badge bad-badge">Rejected</span>';return`
    <div class="verify-block" aria-label="Verification result">
      <div class="verify-row"><span>${t}</span><span><strong>Norm check:</strong> ‖s‖² = ${e.observedSquaredNorm} ≤ ${e.rejectionBound}? ${e.normCheckOk?"yes":"no"}</span></div>
      <div class="verify-row"><span>${s}</span><span><strong>Recompute check:</strong> hash(h·s − c) matches stored digest? ${e.recomputeCheckOk?"yes":"no"}</span></div>
      <div class="verify-row">${n}</div>
    </div>
  `}const k={q1:{id:"q1",prompt:"Why are Falcon signatures smaller than ML-DSA signatures at the same security level?",options:[{text:"Falcon uses elliptic curves instead of lattices."},{text:"Falcon samples short vectors directly via Fast Fourier Sampling over an NTRU lattice, with no rejection-sampling inflation step.",correct:!0},{text:"Falcon stores signatures using a more efficient text encoding."},{text:"Falcon truncates signatures to fit a fixed budget."}],explanation:"ML-DSA (Dilithium) uses module lattices and rejection sampling that produces noticeably larger vectors. Falcon’s NTRU trapdoor plus FFT sampling lets it output a short signature vector directly."},q2:{id:"q2",prompt:'In Falcon, what plays the role of the "trapdoor" during signing?',options:[{text:"The public modulus q."},{text:"The short polynomial pair (f, g) — a short basis of the NTRU lattice that enables Gaussian sampling.",correct:!0},{text:"The signature nonce."},{text:"The hash function used to bind the message."}],explanation:"The private key is the short basis (f, g). Without it, sampling within the rejection bound is infeasible — this asymmetry is what makes signing hard for everyone except the key holder."},q3:{id:"q3",prompt:"Why does Falcon’s verifier check the squared norm of the signature s?",options:[{text:"To save bandwidth."},{text:"Because only a holder of the short basis can produce s with ‖s‖² below the bound; the norm check is the actual unforgeability witness.",correct:!0},{text:"To detect replay attacks."},{text:"To compress the signature for transmission."}],explanation:"A random forger can construct an s that hashes consistently with the public equation, but cannot make it short. The norm bound is what closes the loop."},q4:{id:"q4",prompt:"When does Falcon clearly beat ML-DSA in practice?",options:[{text:"When you want the simplest possible implementation."},{text:"When you must avoid lattice assumptions entirely."},{text:"When transmitted signature bytes are the binding constraint (TLS chains, IoT firmware, constrained radios) and you can ship a constant-time implementation.",correct:!0},{text:"When you need hash-only security assumptions."}],explanation:"Falcon’s edge is size. If implementation simplicity matters more, ML-DSA wins. If you need hash-only assumptions, SLH-DSA wins. Pick by your binding constraint."},q5:{id:"q5",prompt:"What is the main reason Falcon’s Gaussian sampler must run in constant time?",options:[{text:"Variable timing leaks information about the sampled value, which an attacker can integrate over many signatures to recover bits of the secret key.",correct:!0},{text:"Variable timing makes the signature larger."},{text:"Constant-time code runs faster on average."},{text:"Constant-time code is required by JavaScript engines."}],explanation:"Espitau, Fouque, Gérard, Rossi (2017) demonstrated practical key recovery on BLISS via timing of the Gaussian sampler. Falcon faces an analogous risk — see Falcon spec §3.8."}};function $(e){const t=e.options.map((s,n)=>`
      <button class="quiz-option" type="button" data-quiz="${e.id}" data-correct="${s.correct?"true":"false"}" data-idx="${n}">
        ${N(s.text)}
      </button>
    `).join("");return`
    <div class="quiz" data-quiz-id="${e.id}" aria-label="Comprehension check">
      <div class="quiz-prompt"><strong>Check your understanding:</strong> ${N(e.prompt)}</div>
      <div class="quiz-options">${t}</div>
      <div class="quiz-feedback" data-quiz-feedback="${e.id}"></div>
    </div>
  `}function re(e){const t=document.documentElement.dataset.theme==="light"?"light":"dark",s=ae();e.innerHTML=`
    <div class="page" aria-label="Falcon Seal page wrapper">
      <header class="hero" aria-label="Header">
        <button
          id="theme-toggle"
          class="theme-toggle"
          type="button"
          aria-label="${t==="dark"?"Switch to light mode":"Switch to dark mode"}"
          aria-pressed="${t==="dark"?"true":"false"}"
        >${t==="dark"?"🌙":"☀️"}</button>
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
            <input type="radio" name="paramset" value="Falcon-512" ${c.parameterSetName==="Falcon-512"?"checked":""} />
            <span>Falcon-512 <small>(NIST L1, n=512, sig 666 B)</small></span>
          </label>
          <label class="paramset-opt">
            <input type="radio" name="paramset" value="Falcon-1024" ${c.parameterSetName==="Falcon-1024"?"checked":""} />
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
          ${ne()}
        </div>
        ${$(k.q1)}
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
          <button id="keygen-btn" class="btn" type="button" aria-label="Generate ${s.name} keypair">Generate ${s.name} keypair</button>
          <span class="status-chip" aria-label="NIST standard status">NIST PQC Standard (Alternate to ML-DSA)</span>
        </div>
        <div id="key-info" class="output" aria-live="polite" aria-label="Generated key information"></div>
        ${$(k.q2)}
      </section>

      <section class="panel" aria-labelledby="p3-title">
        <h2 id="p3-title">Panel 3 — Sign and Verify</h2>
        <form id="sign-form" class="form" aria-label="Sign and verify form">
          <label for="message-input">Message</label>
          <textarea id="message-input" rows="5" required aria-label="Message to sign">${N(c.message)}</textarea>
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
        ${$(k.q3)}
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
        <div id="vsize-block" class="vsize-block" aria-label="Message vs signature size strips">${ie()}</div>

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
            <tbody>${U(W)}</tbody>
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
            <tbody>${U(_)}</tbody>
          </table>
        </div>
        <div class="bars" aria-label="Signature size visual comparison">
          ${Ne()}
        </div>
        <p class="warning">
          <strong>Security assumption contrast:</strong> Falcon relies on the NTRU lattice hardness (SIS-type problems in the NTRU ring). ML-DSA relies on module lattice hardness (Module-LWE / Module-SIS). SLH-DSA relies only on hash function security — no lattice assumptions at all.
        </p>
        <p class="warning">
          <strong>Implementation complexity:</strong> Falcon is the hardest of the three to implement correctly. Its Gaussian sampler is subtle, requires constant-time execution, and has known side-channel pitfalls. ML-DSA's uniform rejection sampling is simpler. SLH-DSA is conceptually involved (hypertree) but has no sampler timing issues.
        </p>
        ${$(k.q4)}
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
            <input type="radio" name="sampler-mode" value="constant-time" ${c.samplerMode==="constant-time"?"checked":""} />
            <span>Constant-time (Falcon §3.8 compliant)</span>
          </label>
          <label class="paramset-opt">
            <input type="radio" name="sampler-mode" value="leaky" ${c.samplerMode==="leaky"?"checked":""} />
            <span>Leaky (time ∝ |sample|)</span>
          </label>
        </fieldset>
        <div class="actions">
          <button id="sample-btn" class="btn alt" type="button" aria-label="Run 512 simulated samples and chart their timings">Run 512 samples</button>
        </div>
        <div id="timing-viz" class="timing-viz" aria-live="polite" aria-label="Timing histogram">
          ${oe([])}
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
        ${$(k.q5)}
      </section>

      <section class="panel" aria-labelledby="refs-title">
        <h2 id="refs-title">References and Notes</h2>
        <ul>
          ${ue.map(n=>`<li>${n}</li>`).join("")}
        </ul>
      </section>

      <footer class="footer" aria-label="Footer quote">
        So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31
      </footer>
    </div>
  `,Ce(e)}function v(e,t,s="ok"){const n=document.getElementById(e);if(!n)return;const a=s==="ok"?"✅ ":s==="warn"?"⚠️ ":"❌ ";n.textContent=a+t,n.classList.remove("ok","warn","bad"),n.classList.add(s)}function O(){const e=document.getElementById("lattice-viz");e&&(e.innerHTML=ne())}function ze(){const e=document.getElementById("vsize-block");e&&(e.innerHTML=ie())}function G(){const e=document.getElementById("attempts-info");e&&(e.innerHTML=Re())}function V(){const e=document.getElementById("challenge-info");e&&(e.innerHTML=Pe())}function B(){const e=document.getElementById("verify-info");e&&(e.innerHTML=Ie(),e.classList.remove("ok","warn","bad"),c.verifyResult&&e.classList.add(c.verifyResult.overall?"ok":"bad"))}function Ce(e){const t=e.querySelector("#keygen-btn"),s=e.querySelector("#sign-form"),n=e.querySelector("#verify-btn"),a=e.querySelector("#tamper-btn"),i=e.querySelector("#copy-btn"),o=e.querySelector("#message-input"),d=e.querySelector("#sample-btn");e.querySelectorAll('input[name="paramset"]').forEach(l=>{l.addEventListener("change",()=>{const r=l.value;r!==c.parameterSetName&&(c.parameterSetName=r,c.keyPair=null,c.signResult=null,c.verifyResult=null,c.signedMessage="",re(e))})}),e.querySelectorAll('input[name="sampler-mode"]').forEach(l=>{l.addEventListener("change",()=>{c.samplerMode=l.value})}),o==null||o.addEventListener("input",()=>{c.message=o.value,ze()}),t==null||t.addEventListener("click",async()=>{t.disabled=!0,v("key-info",`Generating ${c.parameterSetName} keypair (real NTRU inversion via NTT)…`);try{const l=performance.now();c.keyPair=await Be(ae());const r=(performance.now()-l).toFixed(1),u=c.keyPair.privateKey.regenerationsForInvertibility>0?` Regenerated f ${c.keyPair.privateKey.regenerationsForInvertibility}× until invertible in R_q.`:" f was invertible on first try.";v("key-info",`${c.parameterSetName} keypair ready in ${r} ms. Public key h: ${c.keyPair.publicKey.encodedSizeBytes} B · private (f, g): ${c.keyPair.privateKey.encodedSizeBytes} B.${u} h was computed as g · f⁻¹ mod (q=${c.keyPair.publicKey.q}, x^${c.keyPair.publicKey.n}+1).`,"ok"),c.signResult=null,c.verifyResult=null,O(),G(),V(),B()}finally{t.disabled=!1}}),s==null||s.addEventListener("submit",async l=>{if(l.preventDefault(),!c.keyPair){v("verify-info","Generate a keypair first.","warn");return}const r=(o==null?void 0:o.value)??"";if(!r.trim()){v("verify-info","Message cannot be empty.","bad");return}const u=e.querySelector("#sign-btn");u&&(u.disabled=!0),c.signedMessage=r,c.message=r,v("sign-info",`Signing with illustrative ${c.parameterSetName} flow…`);try{const m=await Fe(r,c.keyPair);c.signResult=m,c.verifyResult=null,v("sign-info",`${m.signature.parameterSetName} · published sig size: ${m.signature.publishedSizeBytes} B (simulated payload ${m.signature.simulatedPayloadBytes} B). Final ‖s‖² = ${m.finalSquaredNorm} (bound ${m.rejectionBound}). ${m.attempts.length} attempt(s). ${Ae(m.signature)}`,"ok"),G(),V(),O(),B()}finally{u&&(u.disabled=!1)}}),n==null||n.addEventListener("click",async()=>{if(!c.keyPair||!c.signResult){v("verify-info","Generate a keypair and sign before verifying.","warn");return}const l=(o==null?void 0:o.value)??"";c.verifyResult=await K(l,c.signResult.signature,c.keyPair.publicKey),B()}),a==null||a.addEventListener("click",async()=>{if(!c.keyPair||!c.signResult){v("verify-info","Sign a message first to run the tamper test.","warn");return}const l=`${c.signedMessage} [tampered]`;c.verifyResult=await K(l,c.signResult.signature,c.keyPair.publicKey),B()}),i==null||i.addEventListener("click",async()=>{if(!c.signResult){v("verify-info","Sign a message first, then copy.","warn");return}const l=qe(c.signResult.signature,c.signedMessage,c.signResult.rejectionBound,c.signResult.finalSquaredNorm);try{await navigator.clipboard.writeText(l),i.textContent="Copied ✓",setTimeout(()=>{i.textContent="Copy as JSON"},1500)}catch{const r=document.createElement("textarea");r.value=l,document.body.appendChild(r),r.select();try{document.execCommand("copy")}finally{document.body.removeChild(r)}i.textContent="Copied ✓",setTimeout(()=>{i.textContent="Copy as JSON"},1500)}}),d==null||d.addEventListener("click",()=>{const l=ye(512,c.samplerMode),r=document.getElementById("timing-viz");r&&(r.innerHTML=oe(l))}),e.querySelectorAll(".quiz-option").forEach(l=>{l.addEventListener("click",()=>{const r=l.dataset.quiz;if(!r)return;const u=k[r];if(!u)return;const m=l.dataset.correct==="true",p=e.querySelector(`.quiz[data-quiz-id="${r}"]`),h=e.querySelector(`[data-quiz-feedback="${r}"]`);p==null||p.querySelectorAll(".quiz-option").forEach(g=>{g.disabled=!0,g.dataset.correct==="true"?g.classList.add("quiz-correct"):g===l&&g.classList.add("quiz-wrong")}),h&&(h.innerHTML=`<strong>${m?"✅ Correct.":"❌ Not quite."}</strong> ${N(u.explanation)}`,h.classList.add(m?"ok":"bad"))})})}function He(){const e=document.documentElement,t=document.querySelector("#theme-toggle");if(!t)return;const s=a=>{t.textContent=a==="dark"?"🌙":"☀️",t.setAttribute("aria-label",a==="dark"?"Switch to light mode":"Switch to dark mode"),t.setAttribute("aria-pressed",a==="dark"?"true":"false")};let n=e.getAttribute("data-theme")==="light"?"light":"dark";e.setAttribute("data-theme",n),s(n),t.addEventListener("click",()=>{n=n==="dark"?"light":"dark",e.setAttribute("data-theme",n),localStorage.setItem("theme",n),s(n)})}const le=document.querySelector("#app");if(!le)throw new Error("App root not found");re(le);He();
