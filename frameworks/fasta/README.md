# The Fasta stream cipher

Fasta is a stream cipher designed to be used in hybrid encryption together with the BGV fully homomorphic encryption cipher as implemented in HElib.  This repository contains a reference implementation of Fasta (without any homomorphic computations), as well as code for doing some timing experiments for Fasta and comparing it to Rasta in various FHE libraries.

## Reference implementation of Fasta

The folder named <i>reference implementation</i> contains code implementing Fasta as specified in https://eprint.iacr.org/2021/1205.  The folder includes a sample program that encrypts and decrypts three blocks of plaintext.  The implementation is written in C and makes use of the <a href="https://gmplib.org/">GMP library,</a> which needs to be installed.  To use the code, simply compile the given test program and run the executable.

## Timings of Fasta and some Rasta variants in HElib, TFHE and Palisade

The repository conatins code for timing implementations of Fasta in HElib, and some Rasta variants in HElib, palisade and TFHE.  The code requires the resepctive FHE libraries to already be installed on the machine where it is run, together with <a href="https://libntl.org/">NTL</a> (and GMP).  Otherwise, to run the timing experiments one only needs to compile the .cpp files in the various folders.  Note that the packed version of Rasta in HElib has a 329-bit block size in order to match the number of slots in a BGV ciphertext with m=30269, while all other implementations use the original 351-bit block size for six rounds.
