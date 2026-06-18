# Security-Level Normalization in HHE Kombat

## Overview

This document specifies how security-level normalization is applied across the evaluated hybrid homomorphic encryption (HHE) transciphering benchmarks. The benchmark inventory is interpreted under the primary **HHE-128** profile: a row is part of the main normalized comparison only when both the homomorphic-encryption (HE) parameters and the symmetric/transciphering primitive target at least 128-bit security.

For benchmark row $i$, the effective security level is

$$
\lambda_{\mathsf{eff}}^{(i)} = \min\!\left(\lambda_{\mathsf{HE}}^{(i)},\, \mu_{\mathsf{SKE}}^{(i)}\right).
$$

Here $\lambda_{\mathsf{HE}}^{(i)}$ is the reported or estimated security level of the HE parameter set, and $\mu_{\mathsf{SKE}}^{(i)}$ is the claimed security level of the underlying standardized or HE-friendly symmetric primitive. A row is classified as an HHE-128 row only if $\lambda_{\mathsf{eff}}^{(i)} \ge 128$.

The benchmark tables measure concrete open-source implementations. They do **not** force identical low-level HE parameters across schemes, because BGV, BFV, CKKS, and TFHE-style backends have different ciphertext moduli, plaintext spaces, bootstrapping mechanisms, packing strategies, and circuit-depth requirements. The normalization criterion is therefore a common security target plus common measured functionality, namely client-side $\mathsf{SKE.Enc}$ and server-side $\mathsf{HHE.Decomp}$.


## Normalization Rule

A benchmark result belongs to the main 128-bit normalized interpretation if:

- the HE parameter set targets or is estimated at **at least 128-bit security**;
- the underlying SKE/transciphering primitive claims **at least 128-bit security**; and
- the row is explicitly marked as included in the HHE-128 main table by the audit metadata.

Rows below this target are retained as reference measurements but are not used to support 128-bit security-normalized conclusions. This distinction is necessary because an HHE construction combines two security layers: a fast transciphering result is not a 128-bit HHE result if the symmetric primitive only targets 80-bit security, even when the HE parameters target 128-bit security. Conversely, a 128-bit symmetric primitive paired with weak HE parameters would also fail the HHE-128 criterion.

---

## HHE-128 Profile

| Field | Value |
|---|---|
| Primary profile | HHE-128 |
| Minimum HE security | 128 bits |
| Minimum SKE security | 128 bits |
| Estimator model for HE audit | BKZ.sieve |
| Correctness trials in audit metadata | 1000 |
| Unverified SKE allowed in normalized class? | No |
| Insecure HE validation allowed in normalized class? | No |

---

## Symmetric / Transciphering Security Classification

The symmetric side is classified as either **standardized 128-bit**, **author-claimed 128-bit**, or **below-128 reference**. AES-128 is treated as standardized 128-bit. HE-friendly ciphers use the claimed security level of the exact cipher family or variant from the corresponding paper or implementation metadata. Below-128 variants remain useful for performance context but are excluded from HHE-128 conclusions.

| Cipher | Key (bits) | Claimed Security | Evidence / Source | Classification |
|---|---:|---:|---|---|
| AES-128 | 128 | 128 | FIPS 197 / NIST SP 800-57 | Standardized 128 |
| Trivium | 80 | 80 | eSTREAM / original paper | Reference only |
| Kreyvium | 128 | 128 | Kreyvium paper | Author-claimed 128 |
| LowMC | 128 | 128 | LowMC paper | Author-claimed 128 |
| Rasta | 128 | 128 | Rasta paper | Author-claimed 128 |
| Dasta | 128 | 128 | Dasta paper | Author-claimed 128 |
| Agrasta | 128 | 128 | Agrasta paper | Author-claimed 128 |
| Fasta | 128 | 128 | Fasta paper | Author-claimed 128 |
| FiLIP | 128 | 128 | FiLIP paper | Author-claimed 128 |
| Elisabeth | 128 | 128 | Elisabeth paper | Author-claimed 128 |
| FRAST | 128 | 128 | FRAST paper | Author-claimed 128 |
| Transistor | 128 | 128 | Transistor paper | Author-claimed 128 |
| Margrethe | 128 | 128 | Margrethe paper | Author-claimed 128 |
| Masta | 128 | 128 | Masta paper | Author-claimed 128 |
| Pasta | 128 | 128 | Pasta paper | Author-claimed 128 |
| Pasta2 | 128 | 128 | Pasta2 paper | Author-claimed 128 |
| Hera | 128 | 128 | Hera paper | Author-claimed 128 |
| Rubato | 128 | 128 | Rubato paper | Author-claimed 128 |
| YuX | 128 | 128 | YuX paper | Author-claimed 128 |

> **Variant note.** The generic Transistor entry in the symmetric-scheme registry is 128-bit, but the audit also includes an explicit **Transistor 80-bit security** variant. That variant is below the HHE-128 target and is listed only in the reference rows.

---

## HE Backend Classification

The HE side is classified by the backend security setting or by estimator/HE-standard evidence. For BGV/BFV/CKKS-style schemes, the relevant metadata includes ring dimension, plaintext modulus or CKKS scale, coefficient-modulus chain, total $\log_2 Q$, multiplicative levels, secret and error distributions, and key-switching or bootstrapping settings. For TFHE-style schemes, the relevant metadata includes LWE dimension, RLWE dimension, noise distribution, key-switching parameters, and bootstrapping parameters.

| Library | HE Scheme | Rows | HHE-128 Rows | Dimension Summary | log₂Q | Levels | Security Evidence |
|---|---|---:|---:|---|---|---|---|
| HElib | BGV | 45 | 45 | ring N 32768, 65536, 65536 | 160–600 | 3, 4, 5, 6 | HE standard table |
| SEAL | BFV | 32 | 32 | ring N 8192, 16384, 32768, 65536 | 218, 438, 881, 1740 | 3, 4, 5, 6 | HE standard table |
| Lattigo | BGV | 6 | 6 | ring N 128 | 90–400 | 3, 4 | lattice estimator |
| Lattigo | CKKS | 6 | 6 | ring N 16384, 32768 | 140–200 | 3, 4, 5, 6 | HE standard table, lattice estimator |
| TFHE | TFHE | 25 | 24 | LWE 630, RLWE 1024; workload N 1–32 | — | — | HE standard table |
| TFHE-rs | TFHE | 10 | 8 | LWE 630, RLWE 1024; workload N 1, 16, 64 | — | — | HE standard table |
| TFHEpp | TFHE | 1 | 1 | LWE 630, RLWE 1024; workload N 16 | — | — | HE standard table |

> The workload field $N$ in benchmark tables is not always the cryptographic ring dimension. In some rows it denotes processed elements, state words, slots, or plaintext/ciphertext units. The HE security level is therefore not inferred from workload $N$ alone; it is taken from the backend parameter set and its associated audit evidence.

---

## Security-Normalization: HHE.Decomp Rows

The following tables give the complete normalization breakdown for the uploaded server-side transciphering audit. The parameter column records the relevant HE parameters exposed by the audit metadata. A row with $\lambda_{\mathsf{eff}} = 80$ is retained only for reference and is excluded from HHE-128 conclusions.

### HElib / BGV

| Cipher | Variant | Workload | Recorded Parameters | λ_eff | Included in HHE-128? | Status |
|---|---|---|---|---:|---|---|
| Agrasta | Packed | 5 × 16 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| Agrasta | Standard | 5 × 16 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| Dasta | Packed r=5 | 5 × 16 bits; single | N=32768, t=65537, logQ=240, chain=40×6, L=5 | 128 | Yes | Author-claimed 128 |
| Dasta | Packed r=6 | 5 × 16 bits; single | N=32768, t=65537, logQ=280, chain=40×7, L=6 | 128 | Yes | Author-claimed 128 |
| Dasta | Standard r=5 | 5 × 16 bits; single | N=32768, t=65537, logQ=240, chain=40×6, L=5 | 128 | Yes | Author-claimed 128 |
| Dasta | Standard r=6 | 5 × 16 bits; single | N=32768, t=65537, logQ=280, chain=40×7, L=6 | 128 | Yes | Author-claimed 128 |
| Fasta | Standard | 5 × 359 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| FiLIP | 1216-instance | 5 × 16 bits; single | N=32768, t=65537, logQ=160, chain=40×4, L=4 | 128 | Yes | Author-claimed 128 |
| FiLIP | 1280-instance | 5 × 16 bits; single | N=32768, t=65537, logQ=160, chain=40×4, L=4 | 128 | Yes | Author-claimed 128 |
| Hera | r=5 | 200 × 16 bits; single | N=32768, t=65537, logQ=240, chain=40×6, L=5 | 128 | Yes | Author-claimed 128 |
| Hera | r=5 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=360, chain=60×6, L=5 | 128 | Yes | Author-claimed 128 |
| Hera | r=5 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=600, chain=100×6, L=5 | 128 | Yes | Author-claimed 128 |
| Kreyvium | 12-round | 5 × 16 bits; single | N=32768, t=65537, logQ=160, chain=40×4, L=4 | 128 | Yes | Author-claimed 128 |
| Kreyvium | 12-round B | 5 × 16 bits; single | N=32768, t=65537, logQ=160, chain=40×4, L=4 | 128 | Yes | Author-claimed 128 |
| Kreyvium | 13-round B | 5 × 16 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=5 | 128 | Yes | Author-claimed 128 |
| LowMC | 14-round | 5 × 16 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| Masta | r=4 | 200 × 16 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| Masta | r=4 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=300, chain=60×5, L=4 | 128 | Yes | Author-claimed 128 |
| Masta | r=4 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=500, chain=100×5, L=4 | 128 | Yes | Author-claimed 128 |
| Masta | r=5 | 200 × 16 bits; single | N=32768, t=65537, logQ=240, chain=40×6, L=5 | 128 | Yes | Author-claimed 128 |
| Masta | r=5 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=360, chain=60×6, L=5 | 128 | Yes | Author-claimed 128 |
| Masta | r=5 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=600, chain=100×6, L=5 | 128 | Yes | Author-claimed 128 |
| Pasta | r=3 | 200 × 16 bits; single | N=32768, t=65537, logQ=160, chain=40×4, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=3 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=240, chain=60×4, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=3 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=400, chain=100×4, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 200 × 16 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=300, chain=60×5, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=500, chain=100×5, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=3 | 200 × 16 bits; single | N=32768, t=65537, logQ=160, chain=40×4, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=3 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=240, chain=60×4, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=3 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=400, chain=100×4, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=4 | 200 × 16 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=4 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=300, chain=60×5, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=4 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=500, chain=100×5, L=4 | 128 | Yes | Author-claimed 128 |
| Rasta | Packed | 1 × 329 bits; single | N=32768, t=65537, logQ=280, chain=40×7, L=6 | 128 | Yes | Author-claimed 128 |
| Rasta | Packed r=5 | 5 × 16 bits; single | N=32768, t=65537, logQ=240, chain=40×6, L=5 | 128 | Yes | Author-claimed 128 |
| Rasta | Packed r=6 | 5 × 16 bits; single | N=32768, t=65537, logQ=280, chain=40×7, L=6 | 128 | Yes | Author-claimed 128 |
| Rasta | Standard | 3 × 351 bits; single | N=32768, t=65537, logQ=280, chain=40×7, L=6 | 128 | Yes | Author-claimed 128 |
| Rasta | Standard r=5 | 5 × 16 bits; single | N=32768, t=65537, logQ=240, chain=40×6, L=5 | 128 | Yes | Author-claimed 128 |
| Rasta | Standard r=6 | 5 × 16 bits; single | N=32768, t=65537, logQ=280, chain=40×7, L=6 | 128 | Yes | Author-claimed 128 |
| YuX | GF(2^16) s=16 | 32 × 8 bits; single | N=32768, t=65537, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| YuX | GF(2^8) s=1 | 192 × 8 bits; single | N=32768, t=257, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| YuX | GF(2^8) s=16 | 32 × 8 bits; single | N=32768, t=257, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| YuX | GF(2^8) s=4 | 192 × 8 bits; single | N=32768, t=257, logQ=200, chain=40×5, L=4 | 128 | Yes | Author-claimed 128 |
| YuX | YuXp prime field s=16 | 32 × 64 bits; single | N=32768, t=1152921504606846977, logQ=500, chain=100×5, L=4 | 128 | Yes | Author-claimed 128 |

### SEAL / BFV

| Cipher | Variant | Workload | Recorded Parameters | λ_eff | Included in HHE-128? | Status |
|---|---|---|---|---:|---|---|
| Agrasta | Standard | 5 × 16 bits; single | N=16384, t=65537, logQ=438, L=4 | 128 | Yes | Author-claimed 128 |
| Dasta | Standard r=5 | 5 × 16 bits; single | N=16384, t=65537, logQ=438, L=5 | 128 | Yes | Author-claimed 128 |
| Dasta | Standard r=6 | 5 × 16 bits; single | N=16384, t=65537, logQ=438, L=6 | 128 | Yes | Author-claimed 128 |
| FiLIP | 1216-instance | 5 × 16 bits; single | N=8192, t=65537, logQ=218, L=4 | 128 | Yes | Author-claimed 128 |
| FiLIP | 1280-instance | 5 × 16 bits; single | N=8192, t=65537, logQ=218, L=4 | 128 | Yes | Author-claimed 128 |
| Hera | r=5 | 200 × 16 bits; single | N=32768, t=65537, logQ=881, L=5 | 128 | Yes | Author-claimed 128 |
| Hera | r=5 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=881, L=5 | 128 | Yes | Author-claimed 128 |
| Hera | r=5 | 200 × 60 bits; single | N=65536, t=1152921504606846977, logQ=1740, L=5 | 128 | Yes | Author-claimed 128 |
| Kreyvium | 12-round | 5 × 16 bits; single | N=8192, t=65537, logQ=218, L=4 | 128 | Yes | Author-claimed 128 |
| Kreyvium | 12-round B | 5 × 16 bits; single | N=8192, t=65537, logQ=218, L=4 | 128 | Yes | Author-claimed 128 |
| Kreyvium | 13-round B | 5 × 16 bits; single | N=8192, t=65537, logQ=218, L=5 | 128 | Yes | Author-claimed 128 |
| LowMC | 14-round | 5 × 16 bits; single | N=8192, t=65537, logQ=218, L=4 | 128 | Yes | Author-claimed 128 |
| Masta | r=4 | 200 × 16 bits; single | N=16384, t=65537, logQ=438, L=4 | 128 | Yes | Author-claimed 128 |
| Masta | r=4 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=881, L=4 | 128 | Yes | Author-claimed 128 |
| Masta | r=4 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=881, L=4 | 128 | Yes | Author-claimed 128 |
| Masta | r=5 | 200 × 16 bits; single | N=16384, t=65537, logQ=438, L=5 | 128 | Yes | Author-claimed 128 |
| Masta | r=5 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=881, L=5 | 128 | Yes | Author-claimed 128 |
| Masta | r=5 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=881, L=5 | 128 | Yes | Author-claimed 128 |
| Pasta | r=3 | 200 × 16 bits; single | N=16384, t=65537, logQ=438, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=3 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=881, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=3 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=881, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 200 × 16 bits; single | N=16384, t=65537, logQ=438, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=881, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=881, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=3 | 200 × 16 bits; single | N=16384, t=65537, logQ=438, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=3 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=881, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=3 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=881, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=4 | 200 × 16 bits; single | N=16384, t=65537, logQ=438, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=4 | 200 × 32 bits; single | N=32768, t=4294967297, logQ=881, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta2 | r=4 | 200 × 60 bits; single | N=32768, t=1152921504606846977, logQ=881, L=4 | 128 | Yes | Author-claimed 128 |
| Rasta | Standard r=5 | 5 × 16 bits; single | N=16384, t=65537, logQ=438, L=5 | 128 | Yes | Author-claimed 128 |
| Rasta | Standard r=6 | 5 × 16 bits; single | N=16384, t=65537, logQ=438, L=6 | 128 | Yes | Author-claimed 128 |

### Lattigo / BGV

| Cipher | Variant | Workload | Recorded Parameters | λ_eff | Included in HHE-128? | Status |
|---|---|---|---|---:|---|---|
| Pasta | r=3 | 128 × 16 bits; single | N=128, t=65537, logQ=90, chain=30×3, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=3 | 128 × 32 bits; single | N=128, t=4294967297, logQ=180, chain=60×3, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=3 | 128 × 60 bits; single | N=128, t=1152921504606846977, logQ=300, chain=100×3, L=3 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 128 × 16 bits; single | N=128, t=65537, logQ=120, chain=30×4, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 128 × 32 bits; single | N=128, t=4294967297, logQ=240, chain=60×4, L=4 | 128 | Yes | Author-claimed 128 |
| Pasta | r=4 | 128 × 60 bits; single | N=128, t=1152921504606846977, logQ=400, chain=100×4, L=4 | 128 | Yes | Author-claimed 128 |

### Lattigo / CKKS

| Cipher | Variant | Workload | Recorded Parameters | λ_eff | Included in HHE-128? | Status |
|---|---|---|---|---:|---|---|
| AES | AES-128-CTR | 2048 × 128 bits; single | N=16384, logQ=200, scale=64, chain=60+40+40+60, L=3 | 128 | Yes | Standardized 128 |
| Hera | r=5 | 32768 × 25 bits; single | N=32768, logQ=160, scale=25, chain=30+25+25+25+25+30, L=5 | 128 | Yes | Author-claimed 128 |
| Hera | r=5 | 32768 × 28 bits; single | N=32768, logQ=172, scale=28, chain=30+28+28+28+28+30, L=5 | 128 | Yes | Author-claimed 128 |
| Rubato | r=2 | 32768 × 64 bits; single | N=32768, logQ=188, scale=64, chain=30+64+64+30, L=3 | 128 | Yes | Author-claimed 128 |
| Rubato | r=3 | 32768 × 36 bits; single | N=32768, logQ=168, scale=36, chain=30+36+36+36+30, L=4 | 128 | Yes | Author-claimed 128 |
| Rubato | r=5 | 32768 × 16 bits; single | N=32768, logQ=140, scale=16, chain=30+16+16+16+16+16+30, L=6 | 128 | Yes | Author-claimed 128 |

### TFHE / TFHE

| Cipher | Variant | Workload | Recorded Parameters | λ_eff | Included in HHE-128? | Status |
|---|---|---|---|---:|---|---|
| AES | AES-128 | 32 × 8 bits; multi | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Standardized 128 |
| AES | AES-128 | 32 × 8 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Standardized 128 |
| Agrasta | Standard | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Dasta | Standard r=5 | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Dasta | Standard r=6 | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Elisabeth | 1-key-schedule | 1 × 4 bits; multi | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Elisabeth | 1-key-schedule | 1 × 4 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Elisabeth | 2-key-schedule | 1 × 4 bits; multi | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Elisabeth | 2-key-schedule | 1 × 4 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| FiLIP | 1216-instance | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| FiLIP | 1216-instance | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| FiLIP | 1280-instance | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| FiLIP | 1280-instance | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| FiLIP | FiLIPhat (SortingHat) | 10 × 2 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| FiLIP | FiLIPind | 1 × 4 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Kreyvium | 12-round | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Kreyvium | 12-round B | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Kreyvium | 13-round B | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| LowMC | 14-round | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Margrethe | Multi-thread | 32 × 8 bits; multi | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Margrethe | Standard | 32 × 8 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Rasta | Standard r=5 | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Rasta | Standard r=6 | 5 × 16 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Transistor | 128-bit security | 4 × 4 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Transistor | 80-bit security | 4 × 4 bits; single | LWE=630, RLWE=1024, bootstrapping=default | **80** | **No** | **Below 128 / reference only** |

### TFHE-rs / TFHE

| Cipher | Variant | Workload | Recorded Parameters | λ_eff | Included in HHE-128? | Status |
|---|---|---|---|---:|---|---|
| AES | AES-128 | 16 × 8 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Standardized 128 |
| AES | AES-128 | 16 × 8 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Standardized 128 |
| AES | AES-128 | 16 × 8 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Standardized 128 |
| AES | AES-128 | 16 × 8 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Standardized 128 |
| FRAST | Standard | 64 × 4 bits; multi | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| FRAST | Standard | 64 × 4 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Kreyvium | Bit-sliced | 1 × 64 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Kreyvium | SIMD | 1 × 64 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Author-claimed 128 |
| Trivium | Bit-sliced | 1 × 64 bits; single | LWE=630, RLWE=1024, bootstrapping=default | **80** | **No** | **Below 128 / reference only** |
| Trivium | SIMD | 1 × 64 bits; single | LWE=630, RLWE=1024, bootstrapping=default | **80** | **No** | **Below 128 / reference only** |

### TFHEpp / TFHE

| Cipher | Variant | Workload | Recorded Parameters | λ_eff | Included in HHE-128? | Status |
|---|---|---|---|---:|---|---|
| AES | AES-128 | 16 × 8 bits; single | LWE=630, RLWE=1024, bootstrapping=default | 128 | Yes | Standardized 128 |

---

## Rows Outside HHE-128 Interpretation

The following rows are useful reference measurements, but they are not counted as HHE-128 results because their symmetric/transciphering layer is below the 128-bit target.

| Cipher | Variant | Backend | SKE Security | HE Security | λ_eff | Reason |
|---|---|---|---:|---:|---:|---|
| Transistor | 80-bit security | TFHE / TFHE | 80 | 128 | 80 | SKE/transciphering primitive below 128-bit target |
| Trivium | Bit-sliced | TFHE-rs / TFHE | 80 | 128 | 80 | SKE/transciphering primitive below 128-bit target |
| Trivium | SIMD | TFHE-rs / TFHE | 80 | 128 | 80 | SKE/transciphering primitive below 128-bit target |

---

## Correctness Metadata

All uploaded audit rows report **1000 correctness trials** and **0 total decryption failures**. This means the security-normalization classification is not weakened by observed correctness failures in the supplied metadata. Correctness evidence does not replace security evidence; it only records that the evaluated parameter sets decrypted correctly in the reported trials.

---

## Why Exact Low-Level Normalization Is Not Possible

Forcing identical HE parameters across all schemes would make the comparison less meaningful rather than more fair. The evaluated schemes differ across several structural dimensions:

- **HE scheme family.** BGV and BFV evaluate exact modular arithmetic; CKKS evaluates approximate arithmetic with scale management; TFHE evaluates bit-level or small-integer functions through programmable bootstrapping.
- **Plaintext domain.** Binary ciphers over $\mathbb{F}_2$, prime-field ciphers over $\mathbb{F}_p$, torus/PBS constructions, and CKKS/RtF constructions require different encodings.
- **Circuit depth.** AES-style byte S-boxes, LowMC-style partial S-boxes, Rasta/Dasta linear layers, Pasta/Masta/Hera/Rubato arithmetic rounds, and stream/filter ciphers require different multiplicative levels or bootstrapping patterns.
- **Packing.** Some implementations process a few bits or words, while others pack thousands of slots. Equalizing the number of slots would not equalize the circuit structure or HE noise growth.
- **Bootstrapping model.** TFHE-style systems refresh ciphertexts during programmable bootstrapping, while leveled BGV/BFV/CKKS-style systems rely on modulus chains and remaining noise budget.

The benchmark therefore compares concrete implementations under comparable security targets, not under identical internal HE parameters. Rows at or above the HHE-128 target may be conservatively penalized by larger parameters. Rows below the target may appear artificially fast and are labelled as reference only.

