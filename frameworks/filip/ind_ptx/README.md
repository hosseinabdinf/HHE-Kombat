# source_transciphering_ptxt_independent

This is an implementation of the transciphering for general plaintext space modulo p,
from the paper [Towards Practical Transciphering for FHE with Setup Independent of the Plaintext Space](https://cic.iacr.org/p/1/1/20), 
by [Pierrick Méaux](https://pierrickmeaux.com/),
[Jeongeun Park](https://sites.google.com/view/jeongeunpark/), 
and [Hilder Vitor Lima Pereira](https://hilder-vitor.github.io/), 
which was published in the journal Communications in Cryptology, in 2024.

**WARNING**:

This is proof-of-concept implementation.
It may contain bugs and security issues.
Please do not use in production systems.

## Installation

The key dependencies of this project is a modified version of [FINAL](https://github.com/KULeuven-COSIC/FINAL),
whose source code we included here.
However, the user still need to manually install the dependencies of FINAL, which are:
- [FFTW](https://www.fftw.org/).
- [GNU GMP](https://gmplib.org/).
- [NTL](https://libntl.org/).

For convinience, we prepared Bash scripts to download and install these three dependencies to `/usr/local/bin`. 
So, if you want to use them, you can simply run

`./install_third_party_libs.sh`

## Running our transciphering

Firstly, notice that we use AES to implement a CSPRNG and we have two options for this: a third-party lib called tiny-AES (general, but not very fast) 
and an implementation using AES-NI, which is way faster, but not compatible with all processors. Thus, you have to check if your processor supports AES-NI.
Then, you can run the script `src/switch_aes_lib.sh` to tell our transciphering that you want to use AES-NI (or not).
After that, just run make to compile. That is,

- `cd src/`
- `. switch_aes_lib`
- `make`

This will generate binaries to test our version of FINAL, some auxiliary functions, and the transciphering itself. You
can run each of those binaries with the following commands

- `./test_final`
- `./test_final_mod_p`
- `./test_homomorphic_filip_mod_p`

