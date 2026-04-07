import {
  FALCON_512_PARAMS,
  challengeFromHash,
  gaussianSamplePoly,
  normSquared,
  polyMulNegacyclic,
  polySub,
  randomSmallPoly,
  type Poly
} from './ntru';

export type FalconKeyPair = {
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
  };
};

export type FalconSignature = {
  mode: 'Illustrative - not production Falcon';
  n: number;
  nonceHex: string;
  s: Int16Array;
  uDigestHex: string;
  publishedSizeBytes: number;
  simulatedPayloadBytes: number;
};

export type SignResult = {
  signature: FalconSignature;
  stats: {
    attempts: number;
    squaredNorm: number;
  };
};

const REJECTION_BOUND_512 = 18000;

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

function derivePublicFromSecret(f: Poly, g: Poly): Poly {
  // Educational approximation: for the demo we project g/f coefficient-wise in Z_q.
  // This is not Falcon's true NTRU inversion and is disclosed in the UI.
  const n = f.length;
  const q = FALCON_512_PARAMS.q;
  const out = new Int16Array(n);
  for (let i = 0; i < n; i += 1) {
    const denom = f[i] === 0 ? 1 : f[i];
    out[i] = (((g[i] * 4096) / denom) | 0) % q;
  }
  return out;
}

function randomNonceHex(): string {
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);
  return bytesToHex(nonce);
}

export async function generateFalcon512KeyPair(): Promise<FalconKeyPair> {
  const { n, q } = FALCON_512_PARAMS;
  const f = randomSmallPoly(n);
  const g = randomSmallPoly(n);
  const h = derivePublicFromSecret(f, g);
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);

  return {
    publicKey: {
      h,
      n,
      q,
      encodedSizeBytes: 897
    },
    privateKey: {
      f,
      g,
      seedHex: bytesToHex(seed),
      encodedSizeBytes: 1281
    }
  };
}

export async function signFalcon512Illustrative(message: string, keyPair: FalconKeyPair): Promise<SignResult> {
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(message);
  const nonceHex = randomNonceHex();
  const nonceBytes = hexToBytes(nonceHex);

  const hBytes = polyToBytes(keyPair.publicKey.h);
  const hashInput = concatBytes(msgBytes, nonceBytes, hBytes);
  const hashed = await sha256(hashInput);
  const c = challengeFromHash(hashed, keyPair.publicKey.n);

  let attempts = 0;
  let s = gaussianSamplePoly(keyPair.publicKey.n);
  let u = polySub(polyMulNegacyclic(keyPair.publicKey.h, s, keyPair.publicKey.q), c, keyPair.publicKey.q);
  let sqNorm = normSquared(s) + normSquared(u);

  while (sqNorm > REJECTION_BOUND_512 && attempts < 64) {
    s = gaussianSamplePoly(keyPair.publicKey.n);
    u = polySub(polyMulNegacyclic(keyPair.publicKey.h, s, keyPair.publicKey.q), c, keyPair.publicKey.q);
    sqNorm = normSquared(s) + normSquared(u);
    attempts += 1;
  }

  const uDigestHex = bytesToHex(await sha256(polyToBytes(u)));
  const simulatedPayloadBytes = 16 + s.length * 2 + 32;

  return {
    signature: {
      mode: 'Illustrative - not production Falcon',
      n: keyPair.publicKey.n,
      nonceHex,
      s,
      uDigestHex,
      publishedSizeBytes: 666,
      simulatedPayloadBytes
    },
    stats: {
      attempts: attempts + 1,
      squaredNorm: sqNorm
    }
  };
}

export async function verifyFalcon512Illustrative(
  message: string,
  signature: FalconSignature,
  publicKey: FalconKeyPair['publicKey']
): Promise<boolean> {
  const encoder = new TextEncoder();
  const msgBytes = encoder.encode(message);
  const nonceBytes = hexToBytes(signature.nonceHex);

  const hBytes = polyToBytes(publicKey.h);
  const hashInput = concatBytes(msgBytes, nonceBytes, hBytes);
  const hashed = await sha256(hashInput);
  const c = challengeFromHash(hashed, publicKey.n);

  const u = polySub(polyMulNegacyclic(publicKey.h, signature.s, publicKey.q), c, publicKey.q);
  const digest = bytesToHex(await sha256(polyToBytes(u)));
  return digest === signature.uDigestHex;
}

export function summarizeSignature(signature: FalconSignature): string {
  const sPreview = Array.from(signature.s.slice(0, 24)).join(',');
  return `mode=${signature.mode}; nonce=${signature.nonceHex}; s[0..23]=${sPreview}; digest=${signature.uDigestHex}`;
}
