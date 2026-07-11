// Babai round-off playground math. Demonstrates why a short, near-orthogonal basis
// is a trapdoor: nearest-plane rounding finds the closest lattice point with the
// good (private) basis but usually misses with a long, skewed (public) basis —
// even though both generate the exact same lattice.

import type { Basis2D } from './ntru';

export type Vec2 = { x: number; y: number };

// Short, near-orthogonal "private" basis. Round-off is only exact CVP when the
// basis is orthogonal, so orthogonality here is load-bearing: with μ = ⟨b1,b2⟩/‖b1‖²
// ≈ −0.008, an exhaustive check of every integer target in [-140,140]² shows
// round-off is optimal up to sub-pixel ties (worst excess 0.12), i.e. every
// clickable target decodes to the closest lattice point with this basis.
export const GOOD_BASIS_2D: Basis2D = { ax: 32, ay: 4, bx: -4, by: 30 };

// Same lattice, transformed by the unimodular matrix [[2,1],[1,1]] (det = 1):
//   b1' = 2·b1 + b2, b2' = b1 + b2. Long and ~18° apart — what an attacker
// works with when they only know the lattice, not the short basis. Round-off
// with this basis misses the closest point for ~49% of targets.
export const BAD_BASIS_2D: Basis2D = {
  ax: GOOD_BASIS_2D.ax * 2 + GOOD_BASIS_2D.bx,
  ay: GOOD_BASIS_2D.ay * 2 + GOOD_BASIS_2D.by,
  bx: GOOD_BASIS_2D.ax + GOOD_BASIS_2D.bx,
  by: GOOD_BASIS_2D.ay + GOOD_BASIS_2D.by
};

export function det2(basis: Basis2D): number {
  return basis.ax * basis.by - basis.ay * basis.bx;
}

export function babaiRound(basis: Basis2D, target: Vec2): { coeffs: [number, number]; point: Vec2 } {
  const d = det2(basis);
  // Solve [ax bx; ay by]·[u v]ᵀ = target, then round coefficients to integers.
  const u = (target.x * basis.by - target.y * basis.bx) / d;
  const v = (-target.x * basis.ay + target.y * basis.ax) / d;
  const ru = Math.round(u);
  const rv = Math.round(v);
  return {
    coeffs: [ru, rv],
    point: { x: ru * basis.ax + rv * basis.bx, y: ru * basis.ay + rv * basis.by }
  };
}

export function distance(a: Vec2, b: Vec2): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

// Brute-force true closest lattice point (fine at this scale; the whole point of
// lattice crypto is that this search is infeasible in dimension 512+).
export function closestLatticePoint(basis: Basis2D, target: Vec2, range = 8): Vec2 {
  let best: Vec2 = { x: 0, y: 0 };
  let bestDist = Number.POSITIVE_INFINITY;
  for (let i = -range; i <= range; i += 1) {
    for (let j = -range; j <= range; j += 1) {
      const p = { x: i * basis.ax + j * basis.bx, y: i * basis.ay + j * basis.by };
      const dist = distance(p, target);
      if (dist < bestDist) {
        bestDist = dist;
        best = p;
      }
    }
  }
  return best;
}
