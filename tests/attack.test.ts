import { describe, expect, it } from 'vitest';
import { createAttackState, runAttackRound } from '../src/attack';

describe('timing-attack simulation', () => {
  it('leaky sampler leaks: strong timing↔magnitude correlation and recovered σ near 1.2', () => {
    const attack = createAttackState('leaky');
    for (let i = 0; i < 10; i += 1) runAttackRound(attack, 10, 128);
    const last = attack.rounds[attack.rounds.length - 1];
    expect(last.correlation).toBeGreaterThan(0.9);
    expect(last.recoveredSigma).not.toBeNull();
    expect(last.recoveredSigma!).toBeGreaterThan(0.8);
    expect(last.recoveredSigma!).toBeLessThan(1.6);
  });

  it('constant-time sampler starves the attacker: near-zero correlation', () => {
    const attack = createAttackState('constant-time');
    for (let i = 0; i < 10; i += 1) runAttackRound(attack, 10, 128);
    const last = attack.rounds[attack.rounds.length - 1];
    expect(Math.abs(last.correlation)).toBeLessThan(0.1);
    expect(last.leakFraction).toBeLessThan(0.01);
  });
});
