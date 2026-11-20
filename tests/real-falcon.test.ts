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
 *   - The signature FRAMING differs from the reference's. This build returns a
 *     fixed 1,332-byte buffer: a 2-byte little-endian length prefix the
 *     falcon-crypto wrapper adds, then PQClean's 1,330-byte CRYPTO_BYTES buffer
 *     holding the variable-length COMPRESSED signature and zero fill. A
 *     reference KAT signature would be rejected for framing rather than for
 *     being wrong -- a format mismatch reported as a correctness finding, which
 *     is the thing this fleet refuses.
 *
 *     1,330 is NOT Falcon's padded format. Falcon-1024's padded signature is a
 *     fixed 1,280 B (specification v1.2, Table 3.3, sbytelen); 1,330 is the
 *     maximum the variable-length compressed encoding can reach, which is what
 *     PQClean sizes its output buffer to. The page used to call 1,330 the
 *     padded format and 1,280 the compressed average, which is backwards, and
 *     this file repeated it.
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
   PQClean's CRYPTO_BYTES buffer plus a 2-byte length prefix. */
const PQCLEAN_CRYPTO_BYTES = 1330;
const WRAPPER_LENGTH_PREFIX_BYTES = 2;
/* Falcon-1024's PADDED signature length, specification v1.2 Table 3.3. This is
   the figure the page quotes as published, and it is NOT what this build emits. */
const SPEC_PADDED_BYTES = 1280;

describe('the real Falcon build against the published Falcon-1024 figures', () => {
  it('its key sizes equal the published parameter sizes', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    expect(kp.publicKey.length).toBe(FALCON_1024.publishedPublicKeyBytes);
    expect(kp.privateKey.length).toBe(FALCON_1024.publishedPrivateKeyBytes);
  }, 60_000);

  it('its signature size is PQClean\'s buffer plus the wrapper prefix, as the page says', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    const sig = await falcon.signDetached(new TextEncoder().encode('abc'), kp.privateKey);
    expect(sig.length).toBe(PQCLEAN_CRYPTO_BYTES + WRAPPER_LENGTH_PREFIX_BYTES);
    /* And it is LARGER than the published padded size, which is the thing
       the page's note exists to explain rather than hide. */
    expect(sig.length).toBeGreaterThan(FALCON_1024.publishedSignatureBytes);
  }, 60_000);

  /* The buffer is not Falcon's padded format, and this pins the two facts that
     prove it: the published padded length is 1,280 B, and what the wrapper hands
     back is a 2-byte little-endian length prefix naming a variable
     compressed signature, with the rest zero fill. If the page ever goes back to
     calling 1,330 "the padded format", these fail. */
  it('what it emits is the variable-length compressed signature, not the 1,280-byte padded format', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    const m = new TextEncoder().encode('abc');

    expect(FALCON_1024.publishedSignatureBytes).toBe(SPEC_PADDED_BYTES);
    expect(PQCLEAN_CRYPTO_BYTES).not.toBe(SPEC_PADDED_BYTES);

    const lengths = new Set<number>();
    for (let i = 0; i < 6; i += 1) {
      const sig = await falcon.signDetached(m, kp.privateKey);
      const declared = sig[0] | (sig[1] << 8); // little-endian length prefix
      /* The prefix delimits the signature; its own last byte may also be zero.
         Compressed signatures may equal or exceed the padded length. Check the
         buffer bound and zero fill, not a bound on the average signature size. */
      expect(declared).toBeGreaterThan(0);
      expect(declared).toBeLessThanOrEqual(PQCLEAN_CRYPTO_BYTES);
      expect(sig.subarray(WRAPPER_LENGTH_PREFIX_BYTES + declared).every((b) => b === 0)).toBe(true);
      lengths.add(declared);
    }
    /* Six signatures over one message and one key did not all come out the same
       length: that is what "variable-length" means, and a padded format could
       not do it. */
    expect(lengths.size).toBeGreaterThan(1);
  }, 120_000);

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
     This build returns a FIXED-SIZE 1,330-byte buffer holding a shorter
     variable-length compressed signature, so the tail is zero fill the verifier
     does not cover: flipping the final byte leaves the signature valid. (Under
     Falcon's real padded format, specification v1.2 section 3.11.3, that byte
     would be covered: all padding bytes must be zero for the signature to be
     valid.) My first version of the test above flipped exactly that
     byte and read the `true` as a verification failure -- a conclusion about
     the lab drawn from my own choice of byte. The lab's own tamper check does
     the right thing: src/real-falcon.ts:56 alters the MESSAGE, which fails.
     Pinning it here documents where the format's covered region ends, and
     would catch a wrapper change that began trimming or covering the padding. */
  it('the trailing byte is unused zero fill, and flipping it does NOT invalidate', async () => {
    const falcon = await load();
    const kp = await falcon.keyPair();
    const m = new TextEncoder().encode('seal this');
    const sig = await falcon.signDetached(m, kp.privateKey);
    const tail = Uint8Array.from(sig);
    tail[tail.length - 1] ^= 0x01;
    expect(await falcon.verifyDetached(tail, m, kp.publicKey)).toBe(true);
  }, 60_000);
});
