// Standalone correctness check for the NTT module. Run with: node scripts/verify-ntt.mjs
// Mirrors src/ntt.ts so we can test in pure Node without a TS toolchain.

const Q = 12289;

function powMod(base, exp, mod) {
  let r = 1n;
  let b = ((BigInt(base) % BigInt(mod)) + BigInt(mod)) % BigInt(mod);
  let e = BigInt(exp);
  const m = BigInt(mod);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return Number(r);
}

function modInv(a, mod) {
  return powMod(a, mod - 2, mod);
}

function findPsi(n, q) {
  for (let g = 2; g < q; g += 1) {
    const psi = powMod(g, (q - 1) / (2 * n), q);
    if (powMod(psi, n, q) === q - 1) return psi;
  }
  throw new Error('no psi');
}

function getCtx(n) {
  const q = Q;
  const psi = findPsi(n, q);
  const psiInv = modInv(psi, q);
  const nInv = modInv(n, q);
  const psiPow = new Int32Array(n);
  const psiInvPow = new Int32Array(n);
  let p = 1, pi = 1;
  for (let i = 0; i < n; i++) {
    psiPow[i] = p; psiInvPow[i] = pi;
    p = (p * psi) % q; pi = (pi * psiInv) % q;
  }
  return { n, q, bits: Math.round(Math.log2(n)), psi, psiInv, nInv, psiPow, psiInvPow };
}

function bitReverse(x, bits) {
  let r = 0, v = x;
  for (let i = 0; i < bits; i++) { r = (r << 1) | (v & 1); v >>>= 1; }
  return r;
}

function nttCore(a, omega, q, bits) {
  const n = a.length;
  for (let i = 0; i < n; i++) {
    const j = bitReverse(i, bits);
    if (i < j) { const t = a[i]; a[i] = a[j]; a[j] = t; }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const half = len >>> 1;
    const wlen = powMod(omega, n / len, q);
    for (let i = 0; i < n; i += len) {
      let w = 1;
      for (let j = 0; j < half; j++) {
        const u = a[i + j];
        const v = (a[i + j + half] * w) % q;
        const sum = u + v;
        a[i + j] = sum >= q ? sum - q : sum;
        const sub = u - v;
        a[i + j + half] = sub < 0 ? sub + q : sub;
        w = (w * wlen) % q;
      }
    }
  }
}

function forward(a, ctx) {
  const out = new Int32Array(ctx.n);
  for (let i = 0; i < ctx.n; i++) {
    let v = a[i] % ctx.q; if (v < 0) v += ctx.q;
    out[i] = (v * ctx.psiPow[i]) % ctx.q;
  }
  const omega = (ctx.psi * ctx.psi) % ctx.q;
  nttCore(out, omega, ctx.q, ctx.bits);
  return out;
}

function inverse(aHat, ctx) {
  const out = new Int32Array(aHat);
  const omega = (ctx.psi * ctx.psi) % ctx.q;
  const omegaInv = modInv(omega, ctx.q);
  nttCore(out, omegaInv, ctx.q, ctx.bits);
  for (let i = 0; i < ctx.n; i++) {
    let v = (out[i] * ctx.nInv) % ctx.q;
    v = (v * ctx.psiInvPow[i]) % ctx.q;
    out[i] = v;
  }
  return out;
}

function toCentered(arr, q) {
  const half = q >> 1;
  const out = new Int16Array(arr.length);
  for (let i = 0; i < arr.length; i++) out[i] = arr[i] > half ? arr[i] - q : arr[i];
  return out;
}

function polyMulNtt(a, b, ctx) {
  const ah = forward(a, ctx);
  const bh = forward(b, ctx);
  for (let i = 0; i < ctx.n; i++) ah[i] = (ah[i] * bh[i]) % ctx.q;
  return toCentered(inverse(ah, ctx), ctx.q);
}

function polyInvNtt(a, ctx) {
  const ah = forward(a, ctx);
  for (let i = 0; i < ctx.n; i++) {
    if (ah[i] === 0) return null;
    ah[i] = modInv(ah[i], ctx.q);
  }
  return toCentered(inverse(ah, ctx), ctx.q);
}

// Schoolbook negacyclic multiplication for cross-check.
function schoolbook(a, b, q) {
  const n = a.length;
  const tmp = new Int32Array(2 * n);
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) tmp[i + j] += a[i] * b[j];
  const out = new Int16Array(n);
  const half = q >> 1;
  for (let k = 0; k < n; k++) {
    let v = (tmp[k] - tmp[k + n]) % q;
    if (v < 0) v += q;
    out[k] = v > half ? v - q : v;
  }
  return out;
}

function arraysEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function randSmall(n) {
  const out = new Int16Array(n);
  for (let i = 0; i < n; i++) out[i] = (Math.random() * 3 | 0) - 1;
  return out;
}

// Tests
let failed = 0;
for (const n of [512, 1024]) {
  const ctx = getCtx(n);
  // 1. Round-trip
  const a = randSmall(n);
  const rt = toCentered(inverse(forward(a, ctx), ctx), ctx.q);
  if (!arraysEq(a, rt)) { console.error(`n=${n} round-trip FAIL`); failed++; }
  else console.log(`n=${n} round-trip ok`);

  // 2. NTT mul vs schoolbook
  const b = randSmall(n);
  const cNtt = polyMulNtt(a, b, ctx);
  const cSchool = schoolbook(a, b, ctx.q);
  if (!arraysEq(cNtt, cSchool)) { console.error(`n=${n} mul mismatch`); failed++; }
  else console.log(`n=${n} mul matches schoolbook`);

  // 3. Inverse: f * f^-1 == 1
  let f, fInv = null;
  while (fInv === null) { f = randSmall(n); fInv = polyInvNtt(f, ctx); }
  const prod = polyMulNtt(f, fInv, ctx);
  const expected = new Int16Array(n); expected[0] = 1;
  if (!arraysEq(prod, expected)) { console.error(`n=${n} inversion FAIL`); failed++; }
  else console.log(`n=${n} f · f⁻¹ = 1 ok`);

  // 4. h = g * f^-1 satisfies h * f = g
  const g = randSmall(n);
  const h = polyMulNtt(g, fInv, ctx);
  const back = polyMulNtt(h, f, ctx);
  if (!arraysEq(back, g)) { console.error(`n=${n} h·f != g FAIL`); failed++; }
  else console.log(`n=${n} h·f = g ok`);
}

if (failed > 0) {
  console.error(`\n${failed} test(s) FAILED`);
  process.exit(1);
}
console.log('\nAll NTT correctness tests passed.');
