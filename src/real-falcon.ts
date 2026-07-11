// Production-grade Falcon, live in the browser. Wraps the falcon-crypto npm
// package — a WebAssembly build of the reference Falcon-1024 implementation
// (github.com/cyph/pqcrypto.js) — so the illustrative flow in this demo can be
// compared against the real thing: real key sizes, real signature bytes, real
// timings, on the visitor's own machine.

type FalconWasm = {
  keyPair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }>;
  signDetached(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
  verifyDetached(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
};

let falconPromise: Promise<FalconWasm> | null = null;

async function loadFalcon(): Promise<FalconWasm> {
  if (!falconPromise) {
    falconPromise = import('falcon-crypto').then((mod) => {
      const anyMod = mod as unknown as Record<string, unknown>;
      const falcon = (anyMod.falcon ?? (anyMod.default as Record<string, unknown> | undefined)?.falcon ?? anyMod.default) as FalconWasm;
      if (typeof falcon?.keyPair !== 'function') {
        throw new Error('falcon-crypto module loaded but exposed no keyPair()');
      }
      return falcon;
    });
    falconPromise.catch(() => {
      falconPromise = null; // allow retry after a transient load failure
    });
  }
  return falconPromise;
}

export type RealFalconRun = {
  publicKeyBytes: number;
  privateKeyBytes: number;
  signatureBytes: number;
  keygenMs: number;
  signMs: number;
  verifyMs: number;
  verified: boolean;
  tamperedVerified: boolean;
  signatureHexPreview: string;
};

export async function runRealFalcon(message: string): Promise<RealFalconRun> {
  const falcon = await loadFalcon();
  const encoder = new TextEncoder();
  const msg = encoder.encode(message);

  const t0 = performance.now();
  const keyPair = await falcon.keyPair();
  const t1 = performance.now();
  const signature = await falcon.signDetached(msg, keyPair.privateKey);
  const t2 = performance.now();
  const verified = await falcon.verifyDetached(signature, msg, keyPair.publicKey);
  const t3 = performance.now();
  const tamperedVerified = await falcon.verifyDetached(signature, encoder.encode(`${message} [tampered]`), keyPair.publicKey);

  const preview = [...signature.slice(0, 24)].map((b) => b.toString(16).padStart(2, '0')).join('');

  return {
    publicKeyBytes: keyPair.publicKey.length,
    privateKeyBytes: keyPair.privateKey.length,
    signatureBytes: signature.length,
    keygenMs: t1 - t0,
    signMs: t2 - t1,
    verifyMs: t3 - t2,
    verified,
    tamperedVerified,
    signatureHexPreview: preview
  };
}
