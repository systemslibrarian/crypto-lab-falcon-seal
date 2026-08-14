import { describe, expect, it } from 'vitest';
import {
  TOY_BOUND_SQ,
  TOY_N,
  TOY_Q,
  challengeFor,
  damageTrapdoor,
  equationHolds,
  forgeWithoutTrapdoor,
  generateTrapdoorKey,
  negacyclicMul,
  normSq,
  ntruEquationLhs,
  signWithTrapdoor,
  strippedBasis,
  trapdoorBasis,
  verifyTrapdoor
} from '../src/trapdoor';

describe('NTRU equation solving (the trapdoor completion)', () => {
  it('produces (F, G) satisfying f·G − g·F = q exactly, over repeated keygens', () => {
    for (let i = 0; i < 8; i += 1) {
      const key = generateTrapdoorKey();
      const lhs = ntruEquationLhs(key);
      expect(lhs[0]).toBe(BigInt(TOY_Q));
      expect(lhs.slice(1).every((v) => v === 0n)).toBe(true);
      expect(key.equationHolds).toBe(true);
    }
  });

  it('reports the equation as failing when the completion is damaged', () => {
    const key = generateTrapdoorKey();
    const damaged = damageTrapdoor(key, 0, 1n);
    expect(damaged.equationHolds).toBe(false);
    expect(equationHolds(damaged.equationLhs, TOY_Q)).toBe(false);
  });

  it('reduces the completion to the same order of magnitude as (f, g)', () => {
    const key = generateTrapdoorKey();
    // Without size reduction the raw completion is ~q× larger. This asserts the
    // reduction ran, which is what makes round-off produce short signatures.
    expect(key.completionNormSq).toBeLessThan(key.shortBasisNormSq * 40n);
  });

  it('publishes h with g = f·h mod q — the public key is derived, not stored', () => {
    const key = generateTrapdoorKey();
    const fh = negacyclicMul(key.f, key.h.map(BigInt), TOY_N);
    const Q = BigInt(TOY_Q);
    for (let i = 0; i < TOY_N; i += 1) {
      const lhs = ((fh[i] % Q) + Q) % Q;
      const rhs = ((key.g[i] % Q) + Q) % Q;
      expect(lhs).toBe(rhs);
    }
  });
});

describe('signing depends on the private key', () => {
  it('produces a signature the public verifier accepts', async () => {
    const key = generateTrapdoorKey();
    const result = await signWithTrapdoor(key, 'ship it');
    expect(result.signature).not.toBeNull();
    const v = await verifyTrapdoor(key.h, 'ship it', result.signature!);
    expect(v.equationOk).toBe(true);
    expect(v.normOk).toBe(true);
    expect(v.overall).toBe(true);
    expect(v.mismatches).toBe(0);
  });

  it('cannot produce a SHORT signature without (F, G), however many attempts', async () => {
    const key = generateTrapdoorKey();
    const result = await signWithTrapdoor(key, 'ship it', strippedBasis(key));
    expect(result.spansLattice).toBe(false);
    expect(result.basisRows).toBe(TOY_N);
    expect(result.signature).toBeNull();
    expect(result.attempts.length).toBeGreaterThan(1);
    expect(result.attempts.every((a) => !a.accepted)).toBe(true);
    // Not merely over the bound — over it by orders of magnitude, because the
    // missing rows are the ones that could have cancelled those coordinates.
    expect(result.bestNormSq!).toBeGreaterThan(TOY_BOUND_SQ * 100n);
  });

  it('an incomplete rank-n basis lands in the forger’s range, far above the full trapdoor', async () => {
    const key = generateTrapdoorKey();
    const half = await signWithTrapdoor(key, 'ship it', strippedBasis(key));
    const forged = await forgeWithoutTrapdoor(key.h, 'ship it', TOY_N, TOY_Q, 30);
    const full = await signWithTrapdoor(key, 'ship it');
    // Half-key and no-key land within an order of magnitude of each other…
    const ratio = Number(half.bestNormSq!) / Number(forged.bestNormSq);
    expect(ratio).toBeGreaterThan(0.05);
    expect(ratio).toBeLessThan(20);
    // …while the full trapdoor is orders of magnitude below both.
    expect(full.signature!.normSq * 100n).toBeLessThan(half.bestNormSq!);
  });

  it('stops verifying when one coefficient of F is changed — the key is load-bearing', async () => {
    const key = generateTrapdoorKey();
    const damaged = damageTrapdoor(key, 3, 7n);
    const result = await signWithTrapdoor(damaged, 'ship it');
    // The damaged basis still spans a lattice, so signing may or may not clear
    // the norm bound; what must NOT happen is a signature the verifier accepts.
    if (result.signature) {
      const v = await verifyTrapdoor(key.h, 'ship it', result.signature);
      expect(v.overall).toBe(false);
      expect(v.equationOk).toBe(false);
    }
  });

  it('binds the message: the same signature fails on a different message', async () => {
    const key = generateTrapdoorKey();
    const result = await signWithTrapdoor(key, 'transfer 10');
    const v = await verifyTrapdoor(key.h, 'transfer 100', result.signature!);
    expect(v.overall).toBe(false);
    expect(v.equationOk).toBe(false);
  });

  it('binds the nonce: changing it breaks the equation', async () => {
    const key = generateTrapdoorKey();
    const result = await signWithTrapdoor(key, 'ship it');
    const tampered = { ...result.signature!, nonceHex: 'ff'.repeat(16) };
    const v = await verifyTrapdoor(key.h, 'ship it', tampered);
    expect(v.equationOk).toBe(false);
  });

  it('binds the vector: flipping one coefficient of s₁ breaks the equation', async () => {
    const key = generateTrapdoorKey();
    const result = await signWithTrapdoor(key, 'ship it');
    const s1 = [...result.signature!.s1];
    s1[2] += 1n;
    const v = await verifyTrapdoor(key.h, 'ship it', { ...result.signature!, s1 });
    expect(v.equationOk).toBe(false);
  });

  it('records every rejected attempt with its measured norm', async () => {
    const key = generateTrapdoorKey();
    const result = await signWithTrapdoor(key, 'ship it');
    expect(result.attempts.length).toBeGreaterThanOrEqual(1);
    for (const a of result.attempts.slice(0, -1)) {
      expect(a.accepted).toBe(false);
      expect(a.normSq).toBeGreaterThan(TOY_BOUND_SQ);
    }
    const last = result.attempts[result.attempts.length - 1];
    expect(last.accepted).toBe(true);
    expect(last.normSq).toBeLessThanOrEqual(TOY_BOUND_SQ);
    expect(last.normSq).toBe(result.signature!.normSq);
  });
});

describe('forgery without the trapdoor', () => {
  it('satisfies the verification EQUATION every time — anyone can do that', async () => {
    const key = generateTrapdoorKey();
    const forged = await forgeWithoutTrapdoor(key.h, 'pay Eve', TOY_N, TOY_Q, 30);
    const v = await verifyTrapdoor(key.h, 'pay Eve', forged.signature);
    expect(v.equationOk).toBe(true);
    expect(v.mismatches).toBe(0);
  });

  it('fails the norm check by orders of magnitude, so verification rejects it', async () => {
    const key = generateTrapdoorKey();
    const forged = await forgeWithoutTrapdoor(key.h, 'pay Eve', TOY_N, TOY_Q, 30);
    const v = await verifyTrapdoor(key.h, 'pay Eve', forged.signature);
    expect(v.normOk).toBe(false);
    expect(v.overall).toBe(false);
    expect(forged.bestNormSq).toBeGreaterThan(TOY_BOUND_SQ * 100n);
  });

  it('is beaten by the honest signer by a very wide margin', async () => {
    const key = generateTrapdoorKey();
    const honest = await signWithTrapdoor(key, 'pay Eve');
    const forged = await forgeWithoutTrapdoor(key.h, 'pay Eve', TOY_N, TOY_Q, 30);
    expect(forged.bestNormSq / honest.signature!.normSq).toBeGreaterThan(100n);
  });
});

describe('the challenge is a real hash of the message', () => {
  it('changes completely when the message changes by one character', async () => {
    const key = generateTrapdoorKey();
    const nonce = 'ab'.repeat(16);
    const a = await challengeFor('pay 10', nonce, key.h, TOY_N, TOY_Q);
    const b = await challengeFor('pay 11', nonce, key.h, TOY_N, TOY_Q);
    expect(a).not.toEqual(b);
    expect(a.filter((v, i) => v === b[i]).length).toBeLessThan(TOY_N);
  });

  it('is deterministic in (message, nonce, h)', async () => {
    const key = generateTrapdoorKey();
    const nonce = 'ab'.repeat(16);
    expect(await challengeFor('x', nonce, key.h, TOY_N, TOY_Q)).toEqual(
      await challengeFor('x', nonce, key.h, TOY_N, TOY_Q)
    );
  });
});

describe('the basis really is 2n-dimensional', () => {
  it('has 2n rows with the trapdoor and n without', () => {
    const key = generateTrapdoorKey();
    expect(trapdoorBasis(key)).toHaveLength(2 * TOY_N);
    expect(strippedBasis(key)).toHaveLength(TOY_N);
  });

  it('every row is in the lattice: u + v·h ≡ 0 (mod q)', () => {
    const key = generateTrapdoorKey();
    const Q = BigInt(TOY_Q);
    for (const row of trapdoorBasis(key)) {
      const u = row.slice(0, TOY_N);
      const v = row.slice(TOY_N);
      const vh = negacyclicMul(v, key.h.map(BigInt), TOY_N);
      for (let i = 0; i < TOY_N; i += 1) {
        expect((((u[i] + vh[i]) % Q) + Q) % Q).toBe(0n);
      }
    }
  });

  it('the short rows really are short — this is the trapdoor', () => {
    const key = generateTrapdoorKey();
    const rows = trapdoorBasis(key);
    for (const row of rows) {
      // Every basis vector is far below q, which is what round-off needs.
      expect(normSq(row)).toBeLessThan(BigInt(TOY_Q) * BigInt(TOY_Q));
    }
  });
});

describe('the calibrated bound is doing the work the comment claims', () => {
  it('accepts roughly four honest signatures in five, on the first attempt', async () => {
    let accepted = 0;
    let total = 0;
    for (let k = 0; k < 20; k += 1) {
      const key = generateTrapdoorKey();
      const rows = trapdoorBasis(key);
      for (let m = 0; m < 20; m += 1) {
        const r = await signWithTrapdoor(key, `msg ${k}:${m}`, rows);
        total += 1;
        if (r.attempts[0].accepted) accepted += 1;
      }
    }
    const rate = accepted / total;
    // Calibration says 0.804 over 60,000 samples. 400 samples here, so the band
    // is ±5σ. If TOY_BOUND_SQ or the sampler moves, this fails rather than the
    // doc comment quietly becoming fiction.
    expect(rate).toBeGreaterThan(0.65);
    expect(rate).toBeLessThan(0.93);
  });

  it('never accepts a forgery, over many independent keys', async () => {
    for (let k = 0; k < 12; k += 1) {
      const key = generateTrapdoorKey();
      const forged = await forgeWithoutTrapdoor(key.h, `msg ${k}`, TOY_N, TOY_Q, 20);
      const v = await verifyTrapdoor(key.h, `msg ${k}`, forged.signature);
      expect(v.equationOk).toBe(true);
      expect(v.normOk).toBe(false);
    }
  });
});
