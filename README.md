# HHE-Kombat

<p align="center">
    <img src="logo.png" alt="HHE Kombat Logo" width="400">
</p>

> *This logo was created using OpenAI's DALL·E, an AI-powered image generation tool.*

## Overview

Welcome to **HHE-Kombat**! This repository serves as a centralized hub for various Hybrid Homomorphic Encryption (HHE) frameworks and their corresponding benchmarking utilities. 

Our goal is to provide a comprehensive, easy-to-use environment for experimenting with, developing, and benchmarking different HHE techniques across multiple languages and architectures.

## Frameworks

The `frameworks` directory contains implementations for various HHE protocols and primitives. Currently, the following frameworks are included:

1. **[AES](./frameworks/AES)**: Advanced Encryption Standard Transciphering implementations.
    - **[BtR_framework](./frameworks/AES/BtR_framework)**: The BtR framework implementation for AES.
    - **[FbT](./frameworks/AES/FbT)**: The FbT implementation.
    - **[FFT_CBS](./frameworks/AES/FFT_CBS)**: AES implementation utilizing FFT-based approaches (CBS).
    - **[Fregata](./frameworks/AES/Fregata)**: The Fregata AES framework.
    - **[Full-LUT](./frameworks/AES/Full-LUT)**: AES implementation utilizing a Full Look-Up Table (LUT) approach.
    - **[Hippogryph](./frameworks/AES/Hippogryph)**: The Hippogryph framework for AES.
    - **[P_encoding](./frameworks/AES/P_encoding)**: AES implementation focused on P-encoding schemes.
    - **[Openssl](./frameworks/AES/Openssl)**: Reference AES implementation using the OpenSSL library.
    - **[Tinyaes](./frameworks/AES/Tinyaes)**: Reference implementation utilizing the lightweight TinyAES library.
2. **[Elisabeth](./frameworks/elisabeth)**: The Elisabeth framework.
3. **[Fasta](./frameworks/fasta)**: The Fasta framework.
4. **[Filip](./frameworks/filip)**: The Filip framework.
    - **[FiLIP Independent Ptx](./frameworks/filip/ind_ptx)**: FiLIP Independent Ptx implementation.
    - **[FiLIP rust](./frameworks/filip/rust)**: FiLIP Rust implementation.
    - **[FiLIP sorting_hat](./frameworks/filip/sorting_hat)**: sorting_hat implementation.
5. **[FRAST](./frameworks/FRAST)**: The FRAST framework.
6. **[HHEFramework (Pasta & Pasta2)](./frameworks/hheFramework)**: The core HHE framework implementation.
7. **[HHELand](./frameworks/HHELand)**: The HHELand framework.
8. **[Margrethe](./frameworks/margrethe)**: The Margrethe framework.
9. **[Transistor](./frameworks/Transistor)**: The Transistor framework.
10. **[TrKr (Trivium & Kreyvium)](./frameworks/trkr)**: Implementations of the Trivium and Kreyvium stream ciphers.
11. **[YuX](./frameworks/yux)**: The YuX framework implementation.

## Benchmarking Utilities

To facilitate accurate and consistent performance analysis, we provide a suite of benchmarking utilities located in the `benchmarking-utilities` directory. These tools are available for several programming languages:

- **[C](./benchmarking-utilities/c)**
- **[Go](./benchmarking-utilities/go)**
- **[Python](./benchmarking-utilities/python)**
- **[Rust](./benchmarking-utilities/rust)**

## Getting Started

To get started with this project, clone the repository and navigate to the framework of your choice.

```bash
git clone https://github.com/anonymous-for-now/HHE-Kombat.git
cd HHE-Kombat
```

From there, consult any individual instructions within each framework or language utility subdirectory for specific build and execution details.

🔍 **Note that we already included our benchmarking utilites in each framework directory to make it easier to benchmark the frameworks. So, you just need to follow the instructions in the framework directory to build and run the benchmarks.**

## Security Normalization & References

For details on the benchmark comparison methodology and external references, see:

* **[Security-Level Normalization](./security_level_normalization.md)**: Specification of the security-level normalization and the HHE-128 profile.
* **[External References](./repo_readme_references_section.md)**: Links to upstream implementation repositories, HE libraries, and system documentation.

## License Information

Please note that the available implementations in this repository are covered by their respective licenses. Consult the individual license files within each framework directory for specific terms and conditions.