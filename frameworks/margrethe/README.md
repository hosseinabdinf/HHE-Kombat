# Margrethe cipher for FHE-based MPC

## Build

For processors with `AVX-512` and `VAES`:

``` make ```

For processors with only `AVX2/FMA`:

``` make FFT_LIB=spqlios A_PRNG=none ENABLE_VAES=false ```

For other cases, see [MOSFHET](https://github.com/antoniocgj/MOSFHET) compiling options. 

## Run

Margrethe cipher (single and multi threaded):

```./main_cipher```

Note that:
- Parameters are hard-coded and can be changed at the beginning of `main_cipher.c`.
- The number of threads (currently 14) for the multithreaded version can be changed in `src/cipher_mt.c`.
- Multithreading is used only to improve latency, not throughput (details in the paper).

Key mixing for FHE-based MPC:

```./main_cipher_mp```

The folder `scripts` contains Python scripts to generate cleartext key streams to verify the correctness of the cipher implementation. It also contains scripts to calculate probability of failure based on the output noise.

## License

This code is licensed under Apache-2.0.

We include hard copy of the [MOSFHET](https://github.com/antoniocgj/MOSFHET) library at `src/mosfhet`.
