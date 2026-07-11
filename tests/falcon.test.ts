import { describe, expect, it } from 'vitest';
import {
  FALCON_512,
  flipSignatureCoefficient,
  forgeRandomSignature,
  forgeShortSignature,
  generateFalconKeyPair,
  parseSignatureJson,
  publicKeyFingerprint,
  signFalconIllustrative,
  signatureToJson,
  verifyFalconIllustrative
} from '../src/falcon';

describe('illustrative Falcon flow', () => {
  it('sign → verify succeeds; tampered message fails the recompute check', async () => {
    const keyPair = await generateFalconKeyPair(FALCON_512);
    const result = await signFalconIllustrative('attack at dawn', keyPair);

    const ok = await verifyFalconIllustrative('attack at dawn', result.signature, keyPair.publicKey);
    expect(ok.normCheckOk).toBe(true);
    expect(ok.recomputeCheckOk).toBe(true);
    expect(ok.overall).toBe(true);

    const tampered = await verifyFalconIllustrative('attack at dusk', result.signature, keyPair.publicKey);
    expect(tampered.recomputeCheckOk).toBe(false);
    expect(tampered.overall).toBe(false);
  });

  it('accepted signature respects the rejection bound', async () => {
    const keyPair = await generateFalconKeyPair(FALCON_512);
    const result = await signFalconIllustrative('bounded', keyPair);
    expect(result.finalSquaredNorm).toBeLessThanOrEqual(result.rejectionBound);
    const lastAttempt = result.attempts[result.attempts.length - 1];
    expect(lastAttempt.accepted).toBe(true);
  });

  it('forgery passes the recompute check but fails the norm check', async () => {
    const keyPair = await generateFalconKeyPair(FALCON_512);
    const forged = await forgeRandomSignature('forged message', keyPair.publicKey);
    const v = await verifyFalconIllustrative('forged message', forged.signature, keyPair.publicKey);
    expect(v.recomputeCheckOk).toBe(true); // the hash equation is trivially satisfiable
    expect(v.normCheckOk).toBe(false); // shortness is what the trapdoor buys
    expect(v.overall).toBe(false);
  });

  // Documents the toy scheme's DELIBERATE weakness (surfaced in the UI as
  // "Forge like a pro"): because the digest is stored inside the signature, a
  // short Gaussian s forged without the private key passes both checks. Real
  // Falcon's verification equation (s1 + s2·h = c) closes this hole. If this
  // test ever fails, the illustrative scheme changed shape — update the
  // forgery-playground copy to match.
  it('short-s forgery SUCCEEDS against the illustrative scheme (known teaching gap)', async () => {
    const keyPair = await generateFalconKeyPair(FALCON_512);
    const forged = await forgeShortSignature('forged with a short vector', keyPair.publicKey);
    const v = await verifyFalconIllustrative('forged with a short vector', forged.signature, keyPair.publicKey);
    expect(v.recomputeCheckOk).toBe(true);
    expect(v.normCheckOk).toBe(true);
    expect(v.overall).toBe(true);
  });

  it('flipping one coefficient breaks the digest recompute check', async () => {
    const keyPair = await generateFalconKeyPair(FALCON_512);
    const result = await signFalconIllustrative('flip me', keyPair);
    const { signature, index } = flipSignatureCoefficient(result.signature);
    expect(index).toBeGreaterThanOrEqual(0);
    expect(index).toBeLessThan(signature.s.length);
    const v = await verifyFalconIllustrative('flip me', signature, keyPair.publicKey);
    expect(v.recomputeCheckOk).toBe(false);
    expect(v.overall).toBe(false);
  });

  it('signature JSON round-trips and verifies against the embedded public key', async () => {
    const keyPair = await generateFalconKeyPair(FALCON_512);
    const result = await signFalconIllustrative('over the wire', keyPair);
    const json = signatureToJson(result.signature, 'over the wire', result.rejectionBound, result.finalSquaredNorm, keyPair.publicKey);

    const bundle = parseSignatureJson(json);
    expect(bundle.message).toBe('over the wire');
    const v = await verifyFalconIllustrative(bundle.message, bundle.signature, bundle.publicKey);
    expect(v.overall).toBe(true);

    const fp = await publicKeyFingerprint(bundle.publicKey);
    expect(fp).toBe(await publicKeyFingerprint(keyPair.publicKey));
  });

  it('tampered JSON (message edited in transit) fails verification', async () => {
    const keyPair = await generateFalconKeyPair(FALCON_512);
    const result = await signFalconIllustrative('pay Alice 10', keyPair);
    const json = signatureToJson(result.signature, 'pay Alice 10', result.rejectionBound, result.finalSquaredNorm, keyPair.publicKey);
    const evil = json.replace('pay Alice 10', 'pay Mallory 99');

    const bundle = parseSignatureJson(evil);
    const v = await verifyFalconIllustrative(bundle.message, bundle.signature, bundle.publicKey);
    expect(v.overall).toBe(false);
  });

  it('parseSignatureJson rejects malformed input with readable errors', () => {
    expect(() => parseSignatureJson('not json')).toThrow(/Not valid JSON/);
    expect(() => parseSignatureJson('{"scheme":"RSA-2048"}')).toThrow(/Unknown scheme/);
    expect(() => parseSignatureJson('{"scheme":"Falcon-512","message":"x","nonceHex":"00"}')).toThrow(/nonceHex/);
  });
});
