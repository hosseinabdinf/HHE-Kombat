# Implementation of the paper "A Homomorphic AES Evaluation in Less than 30 Seconds by Means of TFHE"

## How to Run the code

Everything is inlcuded in CmakeLists and Thirdparty. Ready for build and use:

    mkdir build
    cd build
    cmake ..
    make -j$(nproc)
    cd bin
    ./aes


## Parallelization
To allow parallelization, you can change the value of the NB_THREAD variable line 6 of aes.cpp. It is set to 1 by default, so no parallelization is used.
