# crypto-lab-falcon-seal

## What It Is

crypto-lab-falcon-seal is a browser-based teaching demo for Falcon-512 and Falcon-1024 (selected by NIST for standardization as **FN-DSA**, to be published as **FIPS 206 (in development)**), a post-quantum asymmetric digital signature family built on the NTRU Lattice and Fast Fourier Sampling. It walks through key generation, signing, verification, and comparison with ML-DSA and SLH-DSA. The problem it solves is authenticity and tamper detection: a signer proves authorship of a message, and a verifier can detect changes later. The repository is explicit about scope, and the scope is not uniform — the lab has three distinct signing layers, and a claim true of one is usually false of another:

- **Layer A — illustrative, full-size (Panels 2-3).** Nominal Falcon-512/1024 dimensions and real NTRU public-key arithmetic, but the signer is intentionally forgeable and never reads the private trapdoor. Labelled **Illustrative - not production Falcon** wherever it appears.
- **Layer B — a real NTRU trapdoor at toy scale (Panel 7).** At `n = 8` it samples `(f, g)` from Falcon's own key distribution, **solves the NTRU equation `f·G − g·F = q`** exactly in BigInt arithmetic for the completion `(F, G)`, signs by Babai round-off against the full 2n-dimensional basis, and verifies Falcon's real equation `s₁ + s₂·h ≡ c (mod q)` together with the norm bound. It demonstrates the unforgeability *mechanism*. It provides no security, and it uses round-off rather than Falcon's fast-Fourier Gaussian sampler.
- **Layer C — real Falcon-1024 (Panel 6).** The reference implementation compiled to WebAssembly, for real key generation, signing, verification, sizes and timings.

Every statement below about what the demo "does not have" is scoped to Layer A unless it says otherwise.

### What "illustrative" means for the Layer A signing path specifically

Sharper than the label suggests: **the Panel 2-3 signing flow does not use the private key.** `signFalconIllustrative` samples `s` from a centred Gaussian and loops on `‖s‖²` alone. The challenge `c` is computed but is not an input to the sampler, and `privateKey.f` / `privateKey.g` are never read — the message is bound afterwards, by publishing the digest of `u = h·s − c`. So the scheme is trivially forgeable, and the **Forge like a pro** button in Panel 3 runs the identical sampling loop with no private key and is accepted by the verifier. `tests/falcon.test.ts` asserts that the forgery succeeds.

This is not a small unimplemented corner. Real Falcon signs by using the full trapdoor basis (f, g, F, G) to sample a short (s₁, s₂) satisfying the fixed equation s₁ + s₂·h = c. Reaching that at Falcon's own dimensions needs two substantial pieces Layer A does not have: its keygen stops at (f, g, h) and never solves the NTRU equation f·G − g·F = q, so the completing pair (F, G) does not exist *at n = 512 or 1024*; and fast-Fourier sampling additionally needs an LDL tree over R = Z[x]/(xⁿ+1) in floating point, where this build has only an integer NTT mod q.

Panel 7 supplies the first of those two pieces, by dropping the dimension until an exact solve is cheap: at n = 8 it does compute (F, G), and it does sign with the completed basis. It does not supply the second — round-off stands in for the Gaussian sampler, and round-off is the NTRUSign approach that leaks the basis over a few thousand signatures (Nguyen-Regev, Eurocrypt 2006). So "(F, G) does not exist" is a statement about Layers A and C's dimensions, not about the lab.

What the Layer A flow still teaches honestly: real NTRU key generation via a real negacyclic NTT, the hash-to-challenge step, the shape of a rejection loop, two independent verification checks that both genuinely catch tampering, and — via the forge button — what it looks like when a norm check is not tied to an equation. What **Layer A** cannot teach is unforgeability, and the page no longer claims otherwise; Panel 7 is where the lab teaches it, by enforcing the equation and the bound together and showing the same forgery fail. One further calibration note: the rejection bound this demo enforces (800 for Falcon-512) is a demo constant tuned to its σ = 1.2 sampler, not Falcon-512's ⌊β²⌋ = 34,034,726; both are now shown side by side wherever the bound appears.

## When to Use It

- **Bandwidth-constrained certificate chains and handshakes** — Falcon's published signature sizes are much smaller than ML-DSA and SLH-DSA, so it fits when transmitted bytes are a hard limit.
- **IoT firmware signing and secure update delivery** — compact signatures reduce overhead on constrained devices, radios, and boot chains.
- **Signature-heavy systems that can afford implementation care** — Falcon is a strong fit when signature size matters most and you can depend on a constant-time, audited implementation.
- Do NOT use this in production — the repository intentionally uses educational approximations, so it is for learning and comparison rather than live deployment.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-falcon-seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/)**

In the browser you can generate a Falcon-512 keypair, sign a message, verify the signature, and run a tamper test to watch verification fail on modified input — or press **▶ Walk me through it** for a guided tour that walks the demo in signing order, from the lattice primer through the toy trapdoor mechanism to the WebAssembly finale. Beyond the core flow:

- **Babai lattice playground** — click to place a target on a 2D lattice, then decode it with the private short basis vs the public long basis (same lattice!) and watch nearest-plane rounding succeed or miss. This is the trapdoor, interactively.
- **Forgery playground** — a random forger satisfies the hash equation but fails the norm check by an order of magnitude; flipping one coefficient of a real signature breaks the digest check instead. A third button, **Forge like a pro**, deliberately breaks the toy scheme itself (short Gaussian s + honest digest) to teach why real Falcon's verification equation s₁ + s₂·h = c — not a stored digest — is what actually requires the trapdoor.
- **Timing-attack lab (a model, not a measurement)** — toggle a constant-time vs leaky Gaussian sampler, chart per-sample timings, then run the attacker's side: a leakage meter that climbs against the leaky sampler and flatlines against the constant-time one (the Espitau et al. 2017 attack shape). The nanosecond figures are computed from a formula, `nanos = 820 + (|sample| + 1) × 70 + jitter`, and the attack correlates against the magnitudes that produced them — so it reproduces the shape of the real result rather than rediscovering it. It has to: browsers coarsen `performance.now()` to microseconds or worse specifically to make this attack unmountable from a web page, so a real 70 ns stratum is not observable here. The panel says so on screen, as prominently as the citations.
- **Paste-to-verify** — signature exports embed the message, full vector s, and public key; trade JSON with a classmate and verify (or tamper with) it on the other end.
- **Real Falcon-1024 in WebAssembly** — real keygen, signing, verification, byte counts, and timings from the reference implementation, run on your machine.
- **Comprehension quizzes** with a persistent score and review links.

## What Can Go Wrong

- **Non-constant-time Gaussian sampling** — Falcon's sampler must be constant-time because timing leakage can expose information about the private basis.
- **Weak randomness for the nonce or sampler** — predictable randomness makes sampled values easier to analyze and undermines signature security.
- **Incorrect NTRU / FFT / rejection logic** — Falcon depends on precise lattice arithmetic and norm checks, so implementation mistakes can produce invalid or non-interoperable signatures.
- **Parameter-set or encoding mismatches** — mixing Falcon-512 and Falcon-1024 expectations or using nonstandard encodings will break verification across systems.
- **Treating the illustrative flow as production security** — this demo states that it is not the full reference implementation, so using it in a real protocol would create false confidence.

## Real-World Usage

Well-known production deployment is still limited, but these standardization efforts and interoperability stacks already carry the Falcon family today:

- **FN-DSA / NIST FIPS 206 (in development)** — NIST selected Falcon for its federal post-quantum signature track and will publish the Falcon-derived family as FN-DSA in FIPS 206. That document has not been drafted yet — not even an initial public draft — unlike FIPS 203/204/205, which were finalized in August 2024.
- **Open Quantum Safe (`liboqs`, `OQS-OpenSSL`, and `oqs-provider`)** — these widely used migration projects expose Falcon for experimental TLS handshakes, X.509 chains, and interoperability testing.
- **PQClean** — the project maintains portable Falcon implementations that downstream researchers and engineers use for validation and integration work.
- **SUPERCOP / eBATS benchmarking** — Falcon is measured in the same benchmarking ecosystem used to compare real signature implementations across platforms.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-falcon-seal
cd crypto-lab-falcon-seal
npm install
npm run dev
```

Run the unit + integration suite (NTT round-trip against schoolbook multiplication, sign/verify/tamper/forgery properties, Babai miss-rate comparison, timing-attack convergence, and a jsdom walk of the whole UI):

```bash
npm test
```

Run the end-to-end suite in real Chromium (drives every panel including the WebAssembly Falcon-1024 run, and screenshots both themes into `test-results/`):

```bash
npm run build && npm run test:e2e
```

## Related Demos

- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA (FIPS 204), the lattice signature standard Falcon is compared against.
- [crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) — SLH-DSA (FIPS 205), the hash-based PQ signature alternative.
- [crypto-lab-hawk](https://systemslibrarian.github.io/crypto-lab-hawk/) — HAWK, a lattice signature often framed as Falcon's conceptual successor.
- [crypto-lab-dilithium-reject](https://systemslibrarian.github.io/crypto-lab-dilithium-reject/) — rejection sampling and timing tradeoffs in ML-DSA.
- [crypto-lab-multivariate](https://systemslibrarian.github.io/crypto-lab-multivariate/) — UOV, a non-lattice PQ signature family for contrast.

## References

- Falcon: Fast-Fourier Lattice-Based Compact Signatures over NTRU (official specification document, v1.2) — [falcon-sign.info](https://falcon-sign.info/)
- Ducas, Prest (2016), Fast Fourier Orthogonalization (ISSAC 2016) — the basis of Falcon's Fast Fourier Sampling
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization) — the selection record and the status of FIPS 206 (in development), alongside the published ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) standards

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
