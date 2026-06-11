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
  const bytes = new Uint8Array(n * 2);
  crypto.getRandomValues(bytes);
  let idx = 0;
  for (let i = 0; i < n; ) {
    if (idx >= bytes.length) {
      crypto.getRandomValues(bytes);
      idx = 0;
    }
    const b = bytes[idx++];
    if (b < 255) {
      const v = b % 3;
      out[i] = v === 0 ? -1 : v === 1 ? 0 : 1;
      i += 1;
    }
  }
  return out;
}

// Box–Muller Gaussian sampler used for the illustrative signing flow.
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
  let added = 0;
  while (added < weight) {
    if (idx + 1 >= hashBytes.length) {
      throw new Error(`Not enough hash bytes to reach weight ${weight}. Added ${added} so far.`);
    }
    const b0 = hashBytes[idx];
    const b1 = hashBytes[idx + 1];
    idx += 2;

    const val = (b0 << 8) | b1;
    const p = val % n;
    const s = (val & 0x8000) === 0 ? 1 : -1;

    if (c[p] === 0) {
      c[p] = s;
      added += 1;
    }
  }
  return c;
}

// Side-channel teaching aid. Simulates per-sample timing for two sampler regimes:
//   - 'constant-time': time is independent of the sampled value (fixed CDF table walk).
//   - 'leaky': time grows with |sample|, mimicking a non-constant-time CDF sampler
//             that short-circuits early. This is the failure mode Espitau et al. (2017)
//             exploited against BLISS and that Falcon §3.8 warns against.
export type SamplerMode = 'constant-time' | 'leaky';
export type TimingSample = { value: number; nanos: number };

export function simulateSamplerTimings(count: number, mode: SamplerMode, sigma = 1.2): TimingSample[] {
  const out: TimingSample[] = [];
  const baseline = 820;
  const perStep = 70;
  const ctSteps = 9;
  const jitter = 22;
  const rand = new Uint32Array(count * 2);
  crypto.getRandomValues(rand);
  for (let i = 0; i < count; i += 1) {
    const u1 = Math.max(rand[i * 2] / 0xffffffff, 1e-12);
    const u2 = rand[i * 2 + 1] / 0xffffffff;
    const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    const value = Math.max(-8, Math.min(8, Math.round(z * sigma)));
    const mag = Math.abs(value);
    const jitterDelta = (Math.random() - 0.5) * jitter;
    const nanos =
      mode === 'constant-time' ? baseline + ctSteps * perStep + jitterDelta : baseline + (mag + 1) * perStep + jitterDelta;
    out.push({ value, nanos: Math.max(0, Math.round(nanos)) });
  }
  return out;
}

export type LatticePoint = {
  x: number;
  y: number;
  short?: boolean;
};

export type Basis2D = { ax: number; ay: number; bx: number; by: number };

export const DEFAULT_BASIS_2D: Basis2D = { ax: 42, ay: 10, bx: 18, by: 36 };

export function buildLatticePoints(basis: Basis2D = DEFAULT_BASIS_2D): LatticePoint[] {
  const points: LatticePoint[] = [];
  for (let i = -4; i <= 4; i += 1) {
    for (let j = -4; j <= 4; j += 1) {
      const x = i * basis.ax + j * basis.bx;
      const y = i * basis.ay + j * basis.by;
      const radius = Math.sqrt(x * x + y * y);
      points.push({ x, y, short: radius < 55 });
    }
  }
  return points;
}

// Projects the secret polynomial pair (f, g) into a 2D plane by summing two disjoint
// coefficient slices. Educational — not a cryptographically meaningful projection.
export function projectShortBasis(f: Poly, g: Poly): Basis2D {
  const window = 32;
  const tail = Math.max(0, f.length - window);
  let fa = 0;
  let ga = 0;
  let fb = 0;
  let gb = 0;
  for (let i = 0; i < window; i += 1) {
    fa += f[i];
    ga += g[i];
    fb += f[tail + i];
    gb += g[tail + i];
  }
  const scale = 5;
  return { ax: fa * scale, ay: ga * scale, bx: fb * scale, by: gb * scale };
}

export function projectSignatureVector(s: Poly): { x: number; y: number } {
  const window = 32;
  const tail = Math.max(0, s.length - window);
  let x = 0;
  let y = 0;
  for (let i = 0; i < window; i += 1) {
    x += s[i];
    y += s[tail + i];
  }
  return { x: x * 5, y: y * 5 };
}
