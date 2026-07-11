import { describe, expect, it } from 'vitest';
import { forwardNegacyclicNtt, getNttContext, inverseNegacyclicNtt, polyInvNtt, polyMulNtt } from '../src/ntt';
import { centeredModQ, randomSmallPoly } from '../src/ntru';

const Q = 12289;

// O(n²) reference multiplication in Z_q[x]/(x^n + 1): x^n ≡ -1.
function schoolbookNegacyclic(a: Int16Array, b: Int16Array, q: number): Int16Array {
  const n = a.length;
  const acc = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i += 1) {
    if (a[i] === 0) continue;
    for (let j = 0; j < n; j += 1) {
      const k = i + j;
      const term = a[i] * b[j];
      if (k < n) acc[k] += term;
      else acc[k - n] -= term;
    }
  }
  return Int16Array.from(acc, (v) => centeredModQ(v, q));
}

describe('negacyclic NTT (n=512, q=12289)', () => {
  it('inverse NTT undoes forward NTT', () => {
    const ctx = getNttContext(512);
    const a = randomSmallPoly(512);
    const roundtrip = inverseNegacyclicNtt(forwardNegacyclicNtt(a, ctx), ctx);
    for (let i = 0; i < 512; i += 1) {
      expect(centeredModQ(roundtrip[i], Q)).toBe(centeredModQ(a[i], Q));
    }
  });

  it('polyMulNtt matches schoolbook negacyclic multiplication', () => {
    const ctx = getNttContext(512);
    const a = randomSmallPoly(512);
    const b = randomSmallPoly(512);
    const fast = polyMulNtt(a, b, ctx);
    const slow = schoolbookNegacyclic(a, b, Q);
    expect(Array.from(fast)).toEqual(Array.from(slow));
  });

  it('polyInvNtt produces a true inverse: f · f⁻¹ ≡ 1', () => {
    const ctx = getNttContext(512);
    let f = randomSmallPoly(512);
    let fInv = polyInvNtt(f, ctx);
    while (fInv === null) {
      f = randomSmallPoly(512);
      fInv = polyInvNtt(f, ctx);
    }
    const product = polyMulNtt(f, fInv, ctx);
    expect(product[0]).toBe(1);
    for (let i = 1; i < 512; i += 1) expect(product[i]).toBe(0);
  });

  it('supports n=1024 as well', () => {
    const ctx = getNttContext(1024);
    const a = randomSmallPoly(1024);
    const roundtrip = inverseNegacyclicNtt(forwardNegacyclicNtt(a, ctx), ctx);
    for (let i = 0; i < 1024; i += 1) {
      expect(centeredModQ(roundtrip[i], Q)).toBe(centeredModQ(a[i], Q));
    }
  });
});
