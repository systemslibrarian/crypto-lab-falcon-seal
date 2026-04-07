export type NtruParams = {
  n: number;
  q: number;
};

export type Poly = Int16Array;

export const FALCON_512_PARAMS: NtruParams = {
  n: 512,
  q: 12289
};

export const FALCON_1024_PARAMS: NtruParams = {
  n: 1024,
  q: 12289
};

export function modQ(value: number, q: number): number {
  const r = value % q;
  return r < 0 ? r + q : r;
}

export function centeredModQ(value: number, q: number): number {
  const r = modQ(value, q);
  return r > q / 2 ? r - q : r;
}

export function randomSmallPoly(n: number): Poly {
  const out = new Int16Array(n);
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  for (let i = 0; i < n; i += 1) {
    const v = bytes[i] % 3;
    out[i] = v === 0 ? -1 : v === 1 ? 0 : 1;
  }
  return out;
}

export function gaussianSamplePoly(n: number, sigma = 1.2): Poly {
  const out = new Int16Array(n);
  const rand = new Uint32Array(n * 2);
  crypto.getRandomValues(rand);
  for (let i = 0; i < n; i += 1) {
    const u1 = Math.max(rand[i * 2] / 0xffffffff, 1e-12);
    const u2 = rand[i * 2 + 1] / 0xffffffff;
    const z0 = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    const sampled = Math.round(z0 * sigma);
    out[i] = Math.max(-8, Math.min(8, sampled));
  }
  return out;
}

export function polyAdd(a: Poly, b: Poly, q: number): Poly {
  const out = new Int16Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = centeredModQ(a[i] + b[i], q);
  }
  return out;
}

export function polySub(a: Poly, b: Poly, q: number): Poly {
  const out = new Int16Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = centeredModQ(a[i] - b[i], q);
  }
  return out;
}

// Negacyclic multiplication in Z_q[x]/(x^n + 1).
export function polyMulNegacyclic(a: Poly, b: Poly, q: number): Poly {
  const n = a.length;
  const temp = new Int32Array(n * 2);
  for (let i = 0; i < n; i += 1) {
    for (let j = 0; j < n; j += 1) {
      temp[i + j] += a[i] * b[j];
    }
  }

  const out = new Int16Array(n);
  for (let k = 0; k < n; k += 1) {
    const folded = temp[k] - temp[k + n];
    out[k] = centeredModQ(folded, q);
  }
  return out;
}

export function normSquared(a: Poly): number {
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) {
    acc += a[i] * a[i];
  }
  return acc;
}

export function challengeFromHash(hashBytes: Uint8Array, n: number, weight = 40): Poly {
  const c = new Int16Array(n);
  let idx = 0;
  for (let i = 0; i < weight; i += 1) {
    const p = hashBytes[idx % hashBytes.length] % n;
    const s = (hashBytes[(idx + 1) % hashBytes.length] & 1) === 0 ? 1 : -1;
    c[p] = s;
    idx += 2;
  }
  return c;
}

export type LatticePoint = {
  x: number;
  y: number;
  short?: boolean;
};

export function buildLatticePoints(): LatticePoint[] {
  const points: LatticePoint[] = [];
  const basisA = { x: 42, y: 10 };
  const basisB = { x: 18, y: 36 };

  for (let i = -4; i <= 4; i += 1) {
    for (let j = -4; j <= 4; j += 1) {
      const x = i * basisA.x + j * basisB.x;
      const y = i * basisA.y + j * basisB.y;
      const radius = Math.sqrt(x * x + y * y);
      points.push({ x, y, short: radius < 55 });
    }
  }

  return points;
}
