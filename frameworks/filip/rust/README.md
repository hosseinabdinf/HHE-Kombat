# FiLIP
This is a Rust implementation of the FiLIP stream-cipher, a description of which is available at https://ia.cr/2019/483. 

## Prerequisite

To use filip, you will need the Rust compiler, and the FFTW library. The compiler can be
installed on linux and osx with the following command:

```bash
curl  --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Other rust installation methods are available on the
[rust website](https://forge.rust-lang.org/infra/other-installation-methods.html).

To install the FFTW library on MacOS, one could use the Homebrew package manager. To install
Homebrew, you can do the following:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

And then use it to install FFTW:

```bash
brew install fftw
```

To install FFTW on a debian-based distribution, you can use the following command:

```bash
sudo apt-get update && sudo apt-get install -y libfftw3-dev
```

You can then clone this repository by doing:

```bash
git clone git@github.com:princess-elisabeth/FiLIP.git
```

## Usage
Before running any test or benchmark, you should export the following RUSTFLAGS:
```
export RUSTFLAGS="-C target-cpu=native"
```

### Tests
To run a correctness test of FiLIP, simply run the following command:
```bash
cargo test --release homomorphic -- *NUMBER_OF_BITS*
```
Where *NUMBER_OF_BITS* should be replaced by the actual number of bits over which you want the test to be run.

Nota: the timings given by the tests are indicative and not precisely measured. To have precise time measurment, refer to the benchmark section.

### Benchmarks
To run an benchmark, use the following command:
```
cargo bench
```

## How to cite
```
@inproceedings{hoffmann2020transciphering,
 title={Transciphering, using FiLIP and TFHE for an efficient delegation of computation},
 author={Hoffmann, Cl{\'e}ment and M{\'e}aux, Pierrick and Ricosset, Thomas},
 booktitle={International Conference on Cryptology in India},
 pages={39--61},
 year={2020},
 organization={Springer}
}
```
