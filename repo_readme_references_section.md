## External Implementations, Libraries, and Documentation

This repository aggregates and benchmarks publicly available Hybrid Homomorphic Encryption (HHE), HE-friendly symmetric-cipher, AES-transciphering, and supporting Homomorphic Encryption (HE) implementations. The links below point to the original upstream repositories, libraries, and documentation used as reference material while preparing the benchmarking framework.

> **Note.** These projects are maintained by their respective authors. Their inclusion here does not imply endorsement, and their licenses, build instructions, dependencies, and security claims should be checked in the upstream repositories before reuse. When reproducing the benchmarks, prefer recording the exact commit, release tag, compiler version, and dependency versions used for each implementation.

### Main benchmark repository

| Component | Upstream link | Notes |
|---|---|---|
| HHE-Kombat | <https://github.com/hosseinabdinf/HHE-Kombat> | Main all-in-one benchmarking repository for this work. |
| HHELand | <https://github.com/hosseinabdinf/HHELand> | Go implementation used for Pasta, Hera, and Rubato benchmarks. |

### HE-friendly HHE and transciphering implementations

| Framework / implementation | Upstream link | Main ciphers / purpose |
|---|---|---|
| HybridHE Framework | <https://github.com/IAIK/hybrid-HE-framework> | Agrasta, Rasta, Dasta, FiLIP, Hera, Kreyvium, LowMC, Masta, Pasta, and Pasta v2. |
| LowMC | <https://github.com/LowMC/lowmc> | Original LowMC implementation; retained as a historical/upstream reference. |
| Fasta / Rasta | <https://github.com/Simula-UiB/Fasta> | Fasta and Rasta implementations. |
| Elisabeth | <https://github.com/princess-elisabeth/Elisabeth> | Rust implementation of Elisabeth. |
| FiLIP | <https://github.com/princess-elisabeth/FiLIP> | Rust implementation of the FiLIP stream cipher. |
| FiLIP, plaintext-independent transciphering | <https://github.com/hilder-vitor/source_transciphering_ptxt_independent> | Source-transciphering implementation for FiLIP. |
| SortingHat | <https://github.com/KULeuven-COSIC/SortingHat> | FiLIP-based private decision-tree evaluation / transciphering code. |
| FINAL | <https://github.com/KULeuven-COSIC/FINAL> | Library used by FiLIP-related implementations. |
| Margrethe | <https://github.com/antoniocgj/MARGRETHE> | Margrethe cipher implementation for FHE-based MPC. |
| YuX | <https://github.com/YuXenc/Transcipher-Yux> | YuX2 and YuXp transciphering implementations. |
| FRAST | <https://github.com/KAIST-CryptLab/FRAST> | TFHE-friendly FRAST cipher implementation. |
| Transistor | <https://github.com/CryptoExperts/Transistor> | Demo implementation of the Transistor stream cipher. |
| Trivium / Kreyvium with TFHE-rs | <https://github.com/zama-ai/tfhe-rs/tree/main/apps/trivium> | Trivium and Kreyvium applications built on TFHE-rs. |
| RtF Transciphering Framework | <https://github.com/KAIST-CryptLab/RtF-Transciphering> | Additional Rasta-like / transciphering framework reference. |

### AES and standard-transciphering implementations

| Framework / implementation | Upstream link | Main purpose |
|---|---|---|
| Tiny AES-c | <https://github.com/kokke/tiny-AES-c> | Lightweight AES baseline implementation. |
| OpenSSL | <https://www.openssl.org/> | Standard AES baseline implementation. |
| Fregata | <https://github.com/WeiBenqiang/Fregata> | Faster homomorphic evaluation of SM4 and AES based on TFHE. |
| Full-LUT AES benchmark | <https://github.com/daphnetrm/Benchmark-of-AES-Evaluation-with-TFHE/tree/main/TFHElib/full-LUT> | Full-LUT AES evaluation with TFHE. |
| AES evaluation with TFHE | <https://github.com/daphnetrm/Benchmark-of-AES-Evaluation-with-TFHE> | General benchmark repository for AES evaluation with TFHE. |
| FFT-based Circuit Bootstrap | <https://github.com/KAIST-CryptLab/FFT-based-CircuitBootstrap> | FFT-CBS implementation used for AES transciphering benchmarks. |
| Hippogryph | <https://github.com/CryptoExperts/Hippogryph> | AES execution over TFHE. |
| P-enc / Boolean FHE evaluation | <https://github.com/CryptoExperts/bpr-boolean-fhe> | Optimized homomorphic evaluation of Boolean functions. |
| Fast batched transciphering | <https://github.com/KULeuven-COSIC/fast_batched_transciphering> | Batched and reconfigurable LUT-based transciphering. |
| Awesome transciphering list | <https://github.com/AntCPLab/awesome-transciphering> | Curated list related to FHE-friendly symmetric ciphers and transciphering. |

### HE libraries and cryptographic backends

| Library / backend | Upstream link | Notes |
|---|---|---|
| Microsoft SEAL | <https://github.com/Microsoft/SEAL> | BFV/BGV/CKKS-style HE library used by several implementations. |
| HElib | <https://github.com/homenc/HElib> | BGV/CKKS-style HE library. If a different HElib mirror or release was used, record the exact upstream URL and commit in the benchmark metadata. |
| TFHE | <https://github.com/tfhe/tfhe> | Original TFHE library. If a fork or archived release was used, record the exact upstream URL and commit. |
| TFHEpp | <https://github.com/virtualsecureplatform/TFHEpp> | Pure C++ implementation of TFHE. |
| TFHE-rs | <https://github.com/zama-ai/tfhe-rs> | Rust implementation of TFHE used by several Rust-based frameworks. |
| Concrete | <https://github.com/zama-ai/concrete> | TFHE compiler / FHE framework used by Elisabeth/FiLIP-related code. |
| Lattigo | <https://github.com/tuneinsight/lattigo> | Go HE library used by HHELand and other Go-based benchmarks. |
| PALISADE | <https://gitlab.com/palisade/palisade-release> | Deprecated HE library; retained for reproducibility of older implementations. |
| OpenFHE | <https://github.com/openfheorg/openfhe-development> | Successor ecosystem to PALISADE; used as a reference for OpenFHE-based work. |
| MOSFHET | <https://github.com/antoniocgj/MOSFHET> | FHE-over-the-torus backend used by Margrethe-related work. If a different upstream was used, record the exact URL and commit. |

### Benchmarking, tooling, and system documentation

| Resource | Link | Purpose |
|---|---|---|
| RDTSC instruction documentation | <https://learn.microsoft.com/en-us/cpp/intrinsics/rdtsc?view=msvc-170> | Reference for CPU-cycle measurements. |
| Go garbage collector guide | <https://go.dev/doc/gc-guide> | Reference for interpreting Go runtime and GC behavior. |
| Triton Data Center | <https://github.com/TritonDataCenter/triton> | Infrastructure reference for the benchmark environment. |
| SmartOS CPU caps and shares | <https://docs.smartos.org/cpu-caps-and-shares/> | CPU resource-management documentation. |
| illumos | <https://illumos.org/> | Operating-system / zone environment reference. |
| Lattice Estimator | <https://github.com/malb/lattice-estimator> | Tooling reference for estimating lattice-attack complexities. |
| Rayon | <https://github.com/rayon-rs/rayon> | Rust data-parallelism library used by some Rust implementations. |

### Implementations without usable public code at the time of collection

Some recent works were reviewed but could not be included as directly reproducible code artifacts because public code was unavailable or the authors did not respond to code requests at the time of collection.

| Work | Status |
|---|---|
| Thunderbird | No usable public implementation was available during collection. |
| Faster evaluation of AES using TFHE | No usable public implementation was available during collection. |

### Citation policy for upstream code

If you use or extend this repository, please cite the corresponding papers for the cryptographic schemes and also acknowledge the upstream implementation repositories listed above. Repository links are provided here for reproducibility and engineering traceability; cryptographic claims should be attributed to the original peer-reviewed papers or preprints.
