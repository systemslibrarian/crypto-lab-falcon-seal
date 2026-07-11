import { describe, expect, it } from 'vitest';
import { BAD_BASIS_2D, GOOD_BASIS_2D, babaiRound, closestLatticePoint, det2, distance } from '../src/babai';

describe('Babai round-off playground', () => {
  it('both bases generate the same lattice (|det| equal, integer coordinates)', () => {
    expect(Math.abs(det2(GOOD_BASIS_2D))).toBe(Math.abs(det2(BAD_BASIS_2D)));
  });

  it('bad-basis Babai points are lattice points of the good basis too', () => {
    for (const t of [{ x: 37, y: -22 }, { x: -81, y: 64 }, { x: 5, y: 99 }]) {
      const p = babaiRound(BAD_BASIS_2D, t).point;
      // p must be expressible as integer combination of the good basis
      const d = det2(GOOD_BASIS_2D);
      const u = (p.x * GOOD_BASIS_2D.by - p.y * GOOD_BASIS_2D.bx) / d;
      const v = (-p.x * GOOD_BASIS_2D.ay + p.y * GOOD_BASIS_2D.ax) / d;
      expect(Math.abs(u - Math.round(u))).toBeLessThan(1e-9);
      expect(Math.abs(v - Math.round(v))).toBeLessThan(1e-9);
    }
  });

  // Round-off is exact CVP only for orthogonal bases, which is why GOOD_BASIS_2D
  // is chosen near-orthogonal (μ ≈ −0.008): its only "misses" are sub-pixel ties
  // between equidistant lattice points, below the UI's 0.5 tie tolerance. The bad
  // basis — the same lattice — misses outright for roughly half of all targets.
  it('good basis decodes every target to the closest point (within tie tolerance); bad basis misses ~half', () => {
    let goodMisses = 0;
    let badMisses = 0;
    let total = 0;
    for (let x = -140; x <= 140; x += 4) {
      for (let y = -140; y <= 140; y += 4) {
        const t = { x: x + 1, y: y + 2 };
        const best = closestLatticePoint(GOOD_BASIS_2D, t);
        const good = babaiRound(GOOD_BASIS_2D, t).point;
        const bad = babaiRound(BAD_BASIS_2D, t).point;
        total += 1;
        if (distance(good, t) - distance(best, t) > 0.5) goodMisses += 1;
        if (distance(bad, t) - distance(best, t) > 0.5) badMisses += 1;
      }
    }
    expect(goodMisses).toBe(0);
    expect(badMisses / total).toBeGreaterThan(0.3);
  });
});
