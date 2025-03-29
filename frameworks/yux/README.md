Yux Tranciphering Implementation
=====

***

Implementation based on HElib v2.2.1

# Build and Run

    mkdir build
    cd build
    cmake ..
    make -j$(nproc)
    ./test/test-transciphering16


Symmetic test:

    g++ test-blockcipher.cpp -Iinclude ../symmetric/spn-multi.cpp -o test-blockcipher 