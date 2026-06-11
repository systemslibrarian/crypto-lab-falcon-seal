import {
  FALCON_512_PARAMS,
  FALCON_1024_PARAMS,
  challengeFromHash,
  gaussianSamplePoly,
  normSquared,
  polySub,
  randomSmallPoly,
  type NtruParams,
  type Poly
} from './ntru';
import { getNttContext, polyInvNtt, polyMulNtt } from './ntt';

export type FalconParameterSetName = 'Falcon-512' | 'Falcon-1024';

export type FalconParameterSet = {
  name: FalconParameterSetName;
  params: NtruParams;
  publishedPublicKeyBytes: number;
  publishedPrivateKeyBytes: number;
  publishedSignatureBytes: number;
  rejectionBoundSqNorm: number;
};

export const FALCON_512: FalconParameterSet = {
  name: 'Falcon-512',
  params: FALCON_512_PARAMS,
  publishedPublicKeyBytes: 897,
  publishedPrivateKeyBytes: 1281,
  publishedSignatureBytes: 666,
  // Tuned via scripts/verify-bounds.mjs against the clamped σ=1.2 Box–Muller sampler
  // (E[s_i²] ≈ 1.55). ~67% per-attempt acceptance for n=512 → most sigs show 1–3 attempts.
  rejectionBoundSqNorm: 800
};

export const FALCON_1024: FalconParameterSet = {
  name: 'Falcon-1024',
  params: FALCON_1024_PARAMS,
  publishedPublicKeyBytes: 1793,
  publishedPrivateKeyBytes: 2305,
  publishedSignatureBytes: 1280,
  rejectionBoundSqNorm: 1580
};

export const PARAMETER_SETS: Record<FalconParameterSetName, FalconParameterSet> = {
  'Falcon-512': FALCON_512,
  'Falcon-1024': FALCON_1024
};

export type FalconKeyPair = {
  parameterSet: FalconParameterSet;
  publicKey: {
    h: Poly;
    n: number;
    q: number;
    encodedSizeBytes: number;
  };
  privateKey: {
    f: Poly;
    g: Poly;
    seedHex: string;
    encodedSizeBytes: number;
    regenerationsForInvertibility: number;
  };
};

export type SignAttempt = {
  attempt: number;
  squaredNorm: number;
  accepted: boolean;
};

export type FalconSignature = {
  mode: 'Illustrative - not production Falcon';
  parameterSetName: FalconParameterSetName;
  n: number;
  nonceHex: string;
  s: Int16Array;
  digestHex: string;
  challengePoly: Int16Array;
  hashHex: string;
  publishedSizeBytes: number;
  simulatedPayloadBytes: number;
};

export type SignResult = {
  signature: FalconSignature;
  attempts: SignAttempt[];
  rejectionBound: number;
  finalSquaredNorm: number;
};

export type VerifyResult = {
  normCheckOk: boolean;
  recomputeCheckOk: boolean;
  overall: boolean;
  observedSquaredNorm: number;
  rejectionBound: number;
};

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as ArrayBufferView<ArrayBuffer>);
  return new Uint8Array(digest);
}

async function expandHash(seed: Uint8Array, lengthBytes: number): Promise<Uint8Array> {
  const out = new Uint8Array(lengthBytes);
  let offset = 0;
  let counter = 0;
  while (offset < lengthBytes) {
    const input = concatBytes(seed, new Uint8Array([counter]));
    const block = new Uint8Array(await crypto.subtle.digest('SHA-256', input as ArrayBufferView<ArrayBuffer>));
    const toCopy = Math.min(block.length, lengthBytes - offset);
    out.set(block.slice(0, toCopy), offset);
    offset += toCopy;
    counter += 1;
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function polyToBytes(p: Int16Array): Uint8Array {
  const out = new Uint8Array(p.length * 2);
  const view = new DataView(out.buffer);
  for (let i = 0; i < p.length; i += 1) {
    view.setInt16(i * 2, p[i], true);
  }
  return out;
}

function randomNonceHex(): string {
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);
  return bytesToHex(nonce);
}

export async function generateFalconKeyPair(set: FalconParameterSet): Promise<FalconKeyPair> {
  const { n, q } = set.params;
  const ctx = getNttContext(n);

  let f: Poly = randomSmallPoly(n);
  let g: Poly = randomSmallPoly(n);
  let fInv = polyInvNtt(f, ctx);
  let regenerations = 0;
  while (fInv === null) {
    regenerations += 1;
    f = randomSmallPoly(n);
    g = randomSmallPoly(n);
    fInv = polyInvNtt(f, ctx);
    if (regenerations > 64) throw new Error('Failed to find invertible f after 64 attempts');
  }
  const h = polyMulNtt(g, fInv, ctx);

  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);

  return {
    parameterSet: set,
    publicKey: {
      h,
      n,
      q,
      encodedSizeBytes: set.publishedPublicKeyBytes
    },
    privateKey: {
      f,
      g,
      seedHex: bytesToHex(seed),
      encodedSizeBytes: set.publishedPrivateKeyBytes,
      regenerationsForInvertibility: regenerations
    }
  };
}

export async function signFalconIllustrative(message: string, keyPair: FalconKeyPair): Promise<SignResult> {
  const set = keyPair.parameterSet;
  const { n, q } = set.params;
  const ctx = getNttContext(n);

  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(message);
  const nonceHex = randomNonceHex();
  const nonceBytes = hexToBytes(nonceHex);

  const hBytes = polyToBytes(keyPair.publicKey.h);
  const hashInput = concatBytes(msgBytes, nonceBytes, hBytes);
  const hashed = await sha256(hashInput);
  const expanded = await expandHash(hashed, 256);
  const c = challengeFromHash(expanded, n);

  const attempts: SignAttempt[] = [];
  let s = gaussianSamplePoly(n);
  let sqNorm = normSquared(s);
  let attemptNumber = 1;
  attempts.push({ attempt: attemptNumber, squaredNorm: sqNorm, accepted: sqNorm <= set.rejectionBoundSqNorm });

  while (sqNorm > set.rejectionBoundSqNorm && attemptNumber < 32) {
    s = gaussianSamplePoly(n);
    sqNorm = normSquared(s);
    attemptNumber += 1;
    attempts.push({ attempt: attemptNumber, squaredNorm: sqNorm, accepted: sqNorm <= set.rejectionBoundSqNorm });
  }

  // Bind signature to message via u = h·s - c so any tamper changes c (and digest).
  const hs = polyMulNtt(keyPair.publicKey.h, s, ctx);
  const u = polySub(hs, c, q);
  const digestHex = bytesToHex(await sha256(polyToBytes(u)));

  const simulatedPayloadBytes = 16 + s.length * 2 + 32;

  return {
    signature: {
      mode: 'Illustrative - not production Falcon',
      parameterSetName: set.name,
      n,
      nonceHex,
      s,
      digestHex,
      challengePoly: c,
      hashHex: bytesToHex(hashed),
      publishedSizeBytes: set.publishedSignatureBytes,
      simulatedPayloadBytes
    },
    attempts,
    rejectionBound: set.rejectionBoundSqNorm,
    finalSquaredNorm: sqNorm
  };
}

export async function verifyFalconIllustrative(
  message: string,
  signature: FalconSignature,
  publicKey: FalconKeyPair['publicKey']
): Promise<VerifyResult> {
  const set = PARAMETER_SETS[signature.parameterSetName];
  const { n, q } = set.params;
  const ctx = getNttContext(n);

  const observedSquaredNorm = normSquared(signature.s);
  const normCheckOk = observedSquaredNorm <= set.rejectionBoundSqNorm;

  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(message);
  const nonceBytes = hexToBytes(signature.nonceHex);
  const hBytes = polyToBytes(publicKey.h);
  const hashInput = concatBytes(msgBytes, nonceBytes, hBytes);
  const hashed = await sha256(hashInput);
  const expanded = await expandHash(hashed, 256);
  const c = challengeFromHash(expanded, n);

  const hs = polyMulNtt(publicKey.h, signature.s, ctx);
  const u = polySub(hs, c, q);
  const digest = bytesToHex(await sha256(polyToBytes(u)));
  const recomputeCheckOk = digest === signature.digestHex;

  return {
    normCheckOk,
    recomputeCheckOk,
    overall: normCheckOk && recomputeCheckOk,
    observedSquaredNorm,
    rejectionBound: set.rejectionBoundSqNorm
  };
}

export function summarizeSignature(signature: FalconSignature): string {
  const sPreview = Array.from(signature.s.slice(0, 16)).join(',');
  return `${signature.parameterSetName} · nonce=${signature.nonceHex.slice(0, 16)}… · s[0..15]=[${sPreview}] · digest=${signature.digestHex.slice(0, 32)}…`;
}

export function signatureToJson(
  signature: FalconSignature,
  message: string,
  rejectionBound: number,
  observedSquaredNorm: number
): string {
  return JSON.stringify(
    {
      scheme: signature.parameterSetName,
      mode: signature.mode,
      message,
      nonceHex: signature.nonceHex,
      hashHex: signature.hashHex,
      digestHex: signature.digestHex,
      sPreview: Array.from(signature.s.slice(0, 32)),
      sLength: signature.s.length,
      observedSquaredNorm,
      rejectionBound,
      publishedSizeBytes: signature.publishedSizeBytes,
      simulatedPayloadBytes: signature.simulatedPayloadBytes
    },
    null,
    2
  );
}
