/* real-falcon.ts had no test file, and it is the module whose entire purpose is
 * to be compared against published figures: "real key sizes, real signature
 * bytes, real timings".
 *
 * WHY THERE IS NO PUBLISHED SIGN-KAT HERE, measured rather than assumed. A NIST
 * Falcon known-answer test cannot be applied through this wrapper:
 *
 *   - Falcon signing is RANDOMIZED. Two signatures over the same message with
 *     the same key differ, so no (message, key) -> signature vector can be
 *     asserted. Confirmed by signing 'abc' twice and comparing.
 *   - The signature ENCODING differs from the reference's compressed format.
 *     This build emits the fixed 1,330-byte padded format plus a 2-byte length
 *     prefix the falcon-crypto wrapper adds, so a reference KAT signature would
 *     be rejected for framing rather than for being wrong -- a format mismatch
 *     reported as a correctness finding, which is the thing this fleet refuses.
 *
 * What IS published and assertable are the Falcon-1024 PARAMETER sizes, which
 * src/falcon.ts already carries as publishedPublicKeyBytes / privateKeyBytes /
 * signatureBytes. Nothing checked that the real WASM agrees with them, which is
 * the lab's central comparison. These tests pin that, and pin the arithmetic
 * the UI shows for the signature-size difference.
 */
import { describe, it, expect } from 'vitest';
import { FALCON_1024 } from '../src/falcon';

type FalconWasm = {
  keyPair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }>;
  signDetached(m: Uint8Array, sk: Uint8Array): Promise<Uint8Array>;
  verifyDetached(s: Uint8Array, m: Uint8Array, pk: Uint8Array): Promise<boolean>;
};

const load = async (): Promise<FalconWasm> => {
  const mod = (await import('falcon-crypto')) as unknown as Record<string, unknown>;
  return (mod.falcon
    ?? (mod.default as Record<string, unknown> | undefined)?.falcon
    ?? mod.default) as FalconWasm;
};

/* The wrapper's own framing, stated in src/ui.ts beside the figure it explains:
   the padded format plus a 2-byte length prefix. */
const PADDED_FORMAT_BYTES = 1330;
const WRAPPER_LENGTH_PREFIX_BYTES = 2;

describe('the real Falcon build against the published Falcon-1024 figures', () => {
  it('its key sizes equal the published parameter sizes', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    expect(kp.publicKey.length).toBe(FALCON_1024.publishedPublicKeyBytes);
    expect(kp.privateKey.length).toBe(FALCON_1024.publishedPrivateKeyBytes);
  }, 60_000);

  it('its signature size is the padded format plus the wrapper prefix, as the page says', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    const sig = await falcon.signDetached(new TextEncoder().encode('abc'), kp.privateKey);
    expect(sig.length).toBe(PADDED_FORMAT_BYTES + WRAPPER_LENGTH_PREFIX_BYTES);
    /* And it is LARGER than the published compressed size, which is the thing
       the page's note exists to explain rather than hide. */
    expect(sig.length).toBeGreaterThan(FALCON_1024.publishedSignatureBytes);
  }, 60_000);

  it('signing is randomized, so no sign-KAT could be pinned', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    const m = new TextEncoder().encode('abc');
    const a = await falcon.signDetached(m, kp.privateKey);
    const b = await falcon.signDetached(m, kp.privateKey);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    /* Both must still verify: randomized, not arbitrary. */
    expect(await falcon.verifyDetached(a, m, kp.publicKey)).toBe(true);
    expect(await falcon.verifyDetached(b, m, kp.publicKey)).toBe(true);
  }, 60_000);
});

describe('the verify contract the demo rests on', () => {
  it('accepts a genuine signature; rejects a wrong key, a wrong message and a flipped body byte', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    const other = await falcon.keyPair();
    const m = new TextEncoder().encode('seal this');
    const sig = await falcon.signDetached(m, kp.privateKey);

    expect(await falcon.verifyDetached(sig, m, kp.publicKey)).toBe(true);
    expect(await falcon.verifyDetached(sig, m, other.publicKey)).toBe(false);
    expect(await falcon.verifyDetached(sig, new TextEncoder().encode('seal that'), kp.publicKey)).toBe(false);

    const body = Uint8Array.from(sig);
    body[600] ^= 0x01; // comfortably inside the signature proper
    expect(await falcon.verifyDetached(body, m, kp.publicKey)).toBe(false);
  }, 60_000);

  /* ASSERTED ON PURPOSE, because it surprised me and it is a property of the
     format rather than a defect.
     This build emits the FIXED 1,330-byte padded format, so the tail is
     padding the verifier does not cover: flipping the final byte leaves the
     signature valid. My first version of the test above flipped exactly that
     byte and read the `true` as a verification failure -- a conclusion about
     the lab drawn from my own choice of byte. The lab's own tamper check does
     the right thing: src/real-falcon.ts:56 alters the MESSAGE, which fails.
     Pinning it here documents where the format's covered region ends, and
     would catch a wrapper change that began trimming or covering the padding. */
  it('the trailing byte is padding, and flipping it does NOT invalidate', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    const m = new TextEncoder().encode('seal this');
    const sig = await falcon.signDetached(m, kp.privateKey);
    const tail = Uint8Array.from(sig);
    tail[tail.length - 1] ^= 0x01;
    expect(await falcon.verifyDetached(tail, m, kp.publicKey)).toBe(true);
  }, 60_000);
});
