# crypto-lab-falcon-seal

Live demo: https://systemslibrarian.github.io/crypto-lab-falcon-seal/

Falcon-512 · Falcon-1024 · NTRU Lattice · Fast Fourier Sampling

## Overview

crypto-lab-falcon-seal is a browser-based interactive demonstration of Falcon, the compact lattice-based digital signature scheme over NTRU lattices. It walks through NTRU structure, key generation ideas, signing and verification flow, and tradeoffs against ML-DSA and SLH-DSA.

Important disclosure: this project uses an educational simulation layer for signing internals and is clearly labeled **Illustrative - not production Falcon**.

## What You Can Explore

- NTRU lattice intuition in Z[x]/(x^n + 1)
- Falcon-512 style key generation concepts
- Sign/verify workflow with tamper detection
- Why Falcon signatures are much smaller than ML-DSA and SLH-DSA
- Practical algorithm selection guidance for constrained environments

## Primitives Used

- Falcon parameter sets (size references): Falcon-512, Falcon-1024
- NTRU lattice arithmetic (educational ring operations)
- WebCrypto SHA-256 (`crypto.subtle.digest`)
- Comparative data for ML-DSA and SLH-DSA published parameter sizes

## Running Locally

```bash
npm install
npm run dev
```

Build for production:

```bash
npm run build
```

Deploy to GitHub Pages:

```bash
npm run deploy
```

## Security Notes

- Falcon's Gaussian sampler requires constant-time implementation to avoid timing side-channels.
- Do not use custom Falcon implementations in production systems.
- Use vetted, maintained cryptographic libraries and reference implementations only.
- This demo intentionally labels its simulation components and does not claim production security.

## Accessibility

The demo targets WCAG 2.1 AA with:

- Keyboard navigation across all controls
- Descriptive ARIA labels and live regions for status/errors
- Visible focus indicators in light and dark themes
- Reduced-motion support via `prefers-reduced-motion`
- Mobile-first responsive layout and scroll-safe output panes

## Why This Matters

Post-quantum migration is now an engineering reality. Signature size directly impacts TLS certificate chains, firmware updates, and constrained IoT links. Falcon's compact signatures can substantially reduce bandwidth pressure in those deployments.

## Related Demos

- https://github.com/systemslibrarian/crypto-lab-dilithium-seal
- https://github.com/systemslibrarian/crypto-lab-sphincs-ledger
- https://github.com/systemslibrarian/crypto-compare
- https://github.com/systemslibrarian/crypto-lab

References:

- Falcon: Fast-Fourier Lattice-Based Compact Signatures over NTRU (official specification document, v1.2)
- Ducas, Prest (2016), Fast Fourier sampling over q-ary lattices
- NIST FIPS 206 and the NIST PQC signature standards context (including ML-DSA and SLH-DSA publications)

So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31
