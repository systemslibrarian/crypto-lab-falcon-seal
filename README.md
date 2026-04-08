# crypto-lab-falcon-seal

Live demo: https://systemslibrarian.github.io/crypto-lab-falcon-seal/

Falcon-512 · Falcon-1024 · NTRU Lattice · Fast Fourier Sampling

## 1. What It Is

crypto-lab-falcon-seal is a browser-based teaching demo for Falcon-512 and Falcon-1024, a post-quantum asymmetric digital signature family built on the NTRU Lattice and Fast Fourier Sampling. It walks through key generation, signing, verification, and comparison with ML-DSA and SLH-DSA. The problem it solves is authenticity and tamper detection: a signer proves authorship of a message, and a verifier can detect changes later. The repository is explicit about scope by labeling the signing path **Illustrative - not production Falcon**.

## 2. When to Use It

- **Bandwidth-constrained certificate chains and handshakes** — Falcon's published signature sizes are much smaller than ML-DSA and SLH-DSA, so it fits when transmitted bytes are a hard limit.
- **IoT firmware signing and secure update delivery** — compact signatures reduce overhead on constrained devices, radios, and boot chains.
- **Signature-heavy systems that can afford implementation care** — Falcon is a strong fit when signature size matters most and you can depend on a constant-time, audited implementation.
- **Not for custom classroom code in production** — this repository intentionally uses educational approximations, so it is for learning and comparison rather than live deployment.

## 3. Live Demo

Try the demo at https://systemslibrarian.github.io/crypto-lab-falcon-seal/. In the browser you can generate a Falcon-512 keypair, sign a message, verify the signature, and run a tamper test to watch verification fail on modified input. The interactive controls are the message textarea plus `Generate Falcon-512 keypair`, `Sign`, `Verify`, and `Tamper test`, alongside the NTRU lattice visualization and comparison tables.

## 4. What Can Go Wrong

- **Non-constant-time Gaussian sampling** — Falcon's sampler must be constant-time because timing leakage can expose information about the private basis.
- **Weak randomness for the nonce or sampler** — predictable randomness makes sampled values easier to analyze and undermines signature security.
- **Incorrect NTRU / FFT / rejection logic** — Falcon depends on precise lattice arithmetic and norm checks, so implementation mistakes can produce invalid or non-interoperable signatures.
- **Parameter-set or encoding mismatches** — mixing Falcon-512 and Falcon-1024 expectations or using nonstandard encodings will break verification across systems.
- **Treating the illustrative flow as production security** — this demo states that it is not the full reference implementation, so using it in a real protocol would create false confidence.

## 5. Real-World Usage

Well-known production deployment is still limited, but these standards and interoperability stacks already use the Falcon family today:

- **FN-DSA / NIST FIPS 206** — NIST's federal post-quantum signature track standardizes the Falcon-derived family for digital signatures.
- **Open Quantum Safe (`liboqs`, `OQS-OpenSSL`, and `oqs-provider`)** — these widely used migration projects expose Falcon for experimental TLS handshakes, X.509 chains, and interoperability testing.
- **PQClean** — the project maintains portable Falcon implementations that downstream researchers and engineers use for validation and integration work.
- **SUPERCOP / eBATS benchmarking** — Falcon is measured in the same benchmarking ecosystem used to compare real signature implementations across platforms.

## Related Demos

- https://github.com/systemslibrarian/crypto-lab-dilithium-seal
- https://github.com/systemslibrarian/crypto-lab-sphincs-ledger
- https://github.com/systemslibrarian/crypto-compare
- https://github.com/systemslibrarian/crypto-lab

References:

- Falcon: Fast-Fourier Lattice-Based Compact Signatures over NTRU (official specification document, v1.2)
- Ducas, Prest (2016), Fast Fourier sampling over q-ary lattices
- NIST FIPS 206 and the NIST PQC signature standards context (including ML-DSA and SLH-DSA publications)

> *"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
