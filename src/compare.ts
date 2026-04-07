export type SignatureRow = {
  parameterSet: string;
  publicKeyBytes: number;
  signatureBytes: number;
  keygenTimeMs: number;
  signTimeMs: number;
  verifyTimeMs: number;
  securityAssumption: string;
  implementationComplexity: string;
  status: string;
};

export const comparisonRowsLevel1: SignatureRow[] = [
  {
    parameterSet: 'Falcon-512',
    publicKeyBytes: 897,
    signatureBytes: 666,
    keygenTimeMs: 8.1,
    signTimeMs: 5.5,
    verifyTimeMs: 0.9,
    securityAssumption: 'NTRU lattice (SIS/R-SIS style hardness in NTRU setting)',
    implementationComplexity: 'High (FFT + Gaussian sampler)',
    status: 'Recommended for size-constrained deployments'
  },
  {
    parameterSet: 'ML-DSA-44',
    publicKeyBytes: 1312,
    signatureBytes: 2420,
    keygenTimeMs: 0.8,
    signTimeMs: 1.4,
    verifyTimeMs: 0.6,
    securityAssumption: 'Module lattice (Module-SIS / Module-LWE)',
    implementationComplexity: 'Medium',
    status: 'NIST primary lattice standard'
  },
  {
    parameterSet: 'SLH-DSA-128s',
    publicKeyBytes: 32,
    signatureBytes: 7856,
    keygenTimeMs: 0.2,
    signTimeMs: 45,
    verifyTimeMs: 9.8,
    securityAssumption: 'Hash-based (stateless hypertree)',
    implementationComplexity: 'Medium-High',
    status: 'Conservative, large signatures'
  }
];

export const comparisonRowsLevel5: SignatureRow[] = [
  {
    parameterSet: 'Falcon-1024',
    publicKeyBytes: 1793,
    signatureBytes: 1280,
    keygenTimeMs: 31,
    signTimeMs: 21,
    verifyTimeMs: 1.8,
    securityAssumption: 'NTRU lattice',
    implementationComplexity: 'High (sampler subtlety)',
    status: 'Compact at NIST Level 5'
  },
  {
    parameterSet: 'ML-DSA-87',
    publicKeyBytes: 2592,
    signatureBytes: 4627,
    keygenTimeMs: 2.0,
    signTimeMs: 3.5,
    verifyTimeMs: 1.2,
    securityAssumption: 'Module lattice (Module-SIS / Module-LWE)',
    implementationComplexity: 'Medium',
    status: 'Broader implementation footprint'
  },
  {
    parameterSet: 'SLH-DSA-256s',
    publicKeyBytes: 64,
    signatureBytes: 29792,
    keygenTimeMs: 0.3,
    signTimeMs: 145,
    verifyTimeMs: 31,
    securityAssumption: 'Hash-based (stateless hypertree)',
    implementationComplexity: 'Medium-High',
    status: 'Very large signatures'
  }
];

export const references = [
  'Falcon specification v1.2: Fouque, Kirchner, Tibouchi, Wallet, et al.',
  'Ducas & Prest (2016): Fast Fourier Sampling over q-ary lattices.',
  'NIST FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 related PQ signature context.',
  'Timing numbers are indicative reference-software style measurements and hardware-dependent.'
];
