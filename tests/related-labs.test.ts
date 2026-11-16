import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

/**
 * Standards reviewed 15 November 2026.
 *
 * HAWK was withdrawn from NIST's additional-signatures process. This lab is
 * about Falcon and only links HAWK as a related demo, but the link used to
 * describe HAWK as Falcon's "conceptual successor" with no status attached —
 * which sends a reader toward a lab that opens by saying the scheme is
 * withdrawn and insecure, with no warning in the sentence that got them there.
 *
 * Citation split, and it matters because the two sources carry different facts:
 *  - NIST's round-3 additional-signatures page states the withdrawal itself
 *    ("The submission team has withdrawn HAWK...") but carries NO date.
 *  - The HAWK team's own site carries the date (timeline entry "HAWK is
 *    withdrawn", 29 July 2026) and the stronger statement, its site banner
 *    "Hawk is insecure and should not be used."
 * So the date must not be attached to the NIST page.
 *
 * No technical detail of the attack belongs in this line; crypto-lab-hawk
 * carries that, with the paper and its authors.
 */
const readme = readFileSync('README.md', 'utf8');

describe('the HAWK related-demo link is historical, not an active-candidate blurb', () => {
  const line = readme
    .split('\n')
    .find((l) => l.startsWith('- [crypto-lab-hawk]'));

  it('still links the HAWK lab', () => {
    expect(line).toBeDefined();
    expect(line).toContain('https://systemslibrarian.github.io/crypto-lab-hawk/');
  });

  it('states the withdrawal and cites NIST for it', () => {
    expect(line).toMatch(/withdrawn/);
    expect(line).toContain(
      'https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures',
    );
  });

  it('takes the date and the "insecure" statement from the HAWK team, not from NIST', () => {
    expect(line).toContain('https://hawk-sign.info/');
    expect(line).toMatch(/29 July 2026/);
    expect(line).toMatch(/is insecure and should not be used/);
    // The NIST page carries no date, so the date must not be presented as NIST's.
    expect(line).not.toMatch(
      /round-3-additional-signatures\)[^[]*29 July 2026/,
    );
  });

  it('does not import the attack internals this lab has not read', () => {
    expect(line).not.toMatch(/SVP|cocycle|Galois|2\^?1\d\d|gates/);
  });
});

it('the dated standards note records the re-check', () => {
  expect(readme).toMatch(/\*\*Standards reviewed 15 November 2026:\*\*/);
  expect(readme).toMatch(/does not transfer to Falcon/);
});
