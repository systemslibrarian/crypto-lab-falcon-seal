// Timing-attack teaching aid. Plays the attacker's side of Espitau, Fouque,
// Gérard & Rossi (2017): observe only per-sample timings from many signatures,
// correlate them with the (secret) sampled magnitudes, and watch how much of the
// sampler's output distribution leaks. Against a constant-time sampler the same
// analysis flatlines.

import { simulateSamplerTimings, type SamplerMode, type TimingSample } from './ntru';

export type AttackRound = {
  signaturesObserved: number;
  samplesObserved: number;
  correlation: number; // Pearson r between timing and |sample|
  leakFraction: number; // r² — fraction of magnitude variance explained by timing
  recoveredSigma: number | null; // attacker's σ estimate from timing buckets, if leaking
};

export type AttackState = {
  mode: SamplerMode;
  rounds: AttackRound[];
  samples: TimingSample[];
  done: boolean;
};

export function createAttackState(mode: SamplerMode): AttackState {
  return { mode, rounds: [], samples: [], done: false };
}

function pearson(xs: number[], ys: number[]): number {
  const n = xs.length;
  if (n < 2) return 0;
  let mx = 0;
  let my = 0;
  for (let i = 0; i < n; i += 1) {
    mx += xs[i];
    my += ys[i];
  }
  mx /= n;
  my /= n;
  let sxy = 0;
  let sxx = 0;
  let syy = 0;
  for (let i = 0; i < n; i += 1) {
    const dx = xs[i] - mx;
    const dy = ys[i] - my;
    sxy += dx * dy;
    sxx += dx * dx;
    syy += dy * dy;
  }
  if (sxx === 0 || syy === 0) return 0;
  return sxy / Math.sqrt(sxx * syy);
}

// Attacker-side σ estimate: bucket timings (they only see nanoseconds), map each
// bucket to an inferred magnitude by rank, then compute the standard deviation of
// the inferred magnitudes. Honest in what it uses — timings only, never values.
function estimateSigmaFromTimings(samples: TimingSample[]): number | null {
  if (samples.length < 64) return null;
  const sorted = [...samples.map((s) => s.nanos)].sort((a, b) => a - b);
  // Cluster into timing steps: leaky sampler has ~70 ns strata, jitter ±11 ns.
  const clusters: number[] = [];
  let clusterStart = sorted[0];
  let count = 0;
  const counts: number[] = [];
  for (const t of sorted) {
    if (t - clusterStart > 38) {
      counts.push(count);
      clusters.push(clusterStart);
      clusterStart = t;
      count = 1;
    } else {
      count += 1;
    }
  }
  counts.push(count);
  clusters.push(clusterStart);
  if (clusters.length < 3) return null; // no strata → nothing to read
  // Inferred |value| for cluster k is k (fastest stratum = magnitude 0).
  const total = samples.length;
  let ex2 = 0;
  for (let k = 0; k < counts.length; k += 1) {
    ex2 += (counts[k] / total) * k * k;
  }
  // Half-Gaussian: E[m²] ≈ σ² for the folded magnitude distribution.
  return Math.sqrt(ex2);
}

export function runAttackRound(state: AttackState, signaturesPerRound: number, samplesPerSignature: number): AttackRound {
  const fresh = simulateSamplerTimings(signaturesPerRound * samplesPerSignature, state.mode);
  state.samples.push(...fresh);
  const timings = state.samples.map((s) => s.nanos);
  const magnitudes = state.samples.map((s) => Math.abs(s.value));
  const r = pearson(timings, magnitudes);
  const round: AttackRound = {
    signaturesObserved: (state.rounds.length > 0 ? state.rounds[state.rounds.length - 1].signaturesObserved : 0) + signaturesPerRound,
    samplesObserved: state.samples.length,
    correlation: r,
    leakFraction: r * r,
    recoveredSigma: estimateSigmaFromTimings(state.samples)
  };
  state.rounds.push(round);
  return round;
}
