// Negacyclic NTT over Z_q[x] / (x^n + 1) for q = 12289, n ∈ {512, 1024}.
// q - 1 = 12288 = 2^12 · 3, so 2n divides q-1 for both n=512 (2n=1024) and n=1024 (2n=2048).
// Used for real NTRU public-key derivation h = g · f⁻¹ mod (q, x^n + 1) and fast poly multiplication.

export const Q = 12289;

export function powMod(base: number, exp: number, mod: number): number {
  let r = 1;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0) {
    if (e & 1) r = (r * b) % mod;
    b = (b * b) % mod;
    e = Math.floor(e / 2);
  }
  return r;
}

export function modInv(a: number, mod: number): number {
  return powMod(a, mod - 2, mod);
}

// Finds a primitive 2n-th root of unity ψ in Z_q*: ψ^(2n) = 1 and ψ^n = -1 mod q.
function findPsi(n: number, q: number): number {
  for (let g = 2; g < q; g += 1) {
    const psi = powMod(g, (q - 1) / (2 * n), q);
    if (powMod(psi, n, q) === q - 1) return psi;
  }
  throw new Error(`No primitive 2n-th root of unity found for n=${n}, q=${q}`);
}

export type NttContext = {
  n: number;
  q: number;
  bits: number;
  psi: number;
  psiInv: number;
  nInv: number;
  psiPow: Int32Array;
  psiInvPow: Int32Array;
};

const contextCache = new Map<number, NttContext>();

export function getNttContext(n: number): NttContext {
  const cached = contextCache.get(n);
  if (cached) return cached;

  const bitsFloat = Math.log2(n);
  const bits = Math.round(bitsFloat);
  if (Math.abs(bitsFloat - bits) > 1e-9) {
    throw new Error(`NTT requires n a power of two, got ${n}`);
  }

  const q = Q;
  const psi = findPsi(n, q);
  const psiInv = modInv(psi, q);
  const nInv = modInv(n, q);

  const psiPow = new Int32Array(n);
  const psiInvPow = new Int32Array(n);
  let p = 1;
  let pi = 1;
  for (let i = 0; i < n; i += 1) {
    psiPow[i] = p;
    psiInvPow[i] = pi;
    p = (p * psi) % q;
    pi = (pi * psiInv) % q;
  }

  const ctx: NttContext = { n, q, bits, psi, psiInv, nInv, psiPow, psiInvPow };
  contextCache.set(n, ctx);
  return ctx;
}

function bitReverse(x: number, bits: number): number {
  let r = 0;
  let v = x;
  for (let i = 0; i < bits; i += 1) {
    r = (r << 1) | (v & 1);
    v >>>= 1;
  }
  return r;
}

// In-place iterative NTT length n with primitive n-th root omega.
function nttCore(a: Int32Array, omega: number, q: number, bits: number): void {
  const n = a.length;
  for (let i = 0; i < n; i += 1) {
    const j = bitReverse(i, bits);
    if (i < j) {
      const t = a[i];
      a[i] = a[j];
      a[j] = t;
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const half = len >>> 1;
    const wlen = powMod(omega, n / len, q);
    for (let i = 0; i < n; i += len) {
      let w = 1;
      for (let j = 0; j < half; j += 1) {
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

function normalizeInput(a: Int16Array, q: number): Int32Array {
  const out = new Int32Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    let v = a[i] % q;
    if (v < 0) v += q;
    out[i] = v;
  }
  return out;
}

export function forwardNegacyclicNtt(a: Int16Array, ctx: NttContext): Int32Array {
  const out = normalizeInput(a, ctx.q);
  for (let i = 0; i < ctx.n; i += 1) {
    out[i] = (out[i] * ctx.psiPow[i]) % ctx.q;
  }
  const omega = (ctx.psi * ctx.psi) % ctx.q;
  nttCore(out, omega, ctx.q, ctx.bits);
  return out;
}

export function inverseNegacyclicNtt(aHat: Int32Array, ctx: NttContext): Int32Array {
  const out = new Int32Array(aHat);
  const omega = (ctx.psi * ctx.psi) % ctx.q;
  const omegaInv = modInv(omega, ctx.q);
  nttCore(out, omegaInv, ctx.q, ctx.bits);
  for (let i = 0; i < ctx.n; i += 1) {
    let v = (out[i] * ctx.nInv) % ctx.q;
    v = (v * ctx.psiInvPow[i]) % ctx.q;
    out[i] = v;
  }
  return out;
}

function toCentered(coefsModQ: Int32Array, q: number): Int16Array {
  const out = new Int16Array(coefsModQ.length);
  const half = q >>> 1;
  for (let i = 0; i < coefsModQ.length; i += 1) {
    out[i] = coefsModQ[i] > half ? coefsModQ[i] - q : coefsModQ[i];
  }
  return out;
}

export function polyMulNtt(a: Int16Array, b: Int16Array, ctx: NttContext): Int16Array {
  const ah = forwardNegacyclicNtt(a, ctx);
  const bh = forwardNegacyclicNtt(b, ctx);
  for (let i = 0; i < ctx.n; i += 1) {
    ah[i] = (ah[i] * bh[i]) % ctx.q;
  }
  const c = inverseNegacyclicNtt(ah, ctx);
  return toCentered(c, ctx.q);
}

// Real polynomial inversion in Z_q[x] / (x^n + 1). Returns null if a is not invertible
// (i.e., some NTT coefficient is zero — Falcon keygen regenerates f in that case).
export function polyInvNtt(a: Int16Array, ctx: NttContext): Int16Array | null {
  const ah = forwardNegacyclicNtt(a, ctx);
  for (let i = 0; i < ctx.n; i += 1) {
    if (ah[i] === 0) return null;
    ah[i] = modInv(ah[i], ctx.q);
  }
  const inv = inverseNegacyclicNtt(ah, ctx);
  return toCentered(inv, ctx.q);
}
