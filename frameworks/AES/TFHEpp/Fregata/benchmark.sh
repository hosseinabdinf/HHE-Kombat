#!/bin/bash
# This script will run the Fregata framework benchmarking.

cd CBSmode

mkdir build
cd build

echo -e "\e[1;33m\nCompilation (it can take a few seconds)\e[0m\n"
sleep 3

cmake -DENABLE_TEST=ON ..
make -j$(nproc)

echo -e "\e[1;33m\nSymmetric Benchmarking\e[0m\n"
sleep 1

./homoSM4_CB/sym_aes

echo -e "\e[1;33m\nTransciphering Benchmarking\e[0m\n"
sleep 1
./homoSM4_CB/hom_aes