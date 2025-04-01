# ==========================================================
#     TFHE
# ==========================================================
if [ ! -d "tfhe/installed" ]; then
  echo "TFHE not found. Building..."
  git clone https://github.com/tfhe/tfhe.git
  cd tfhe &&
    cp ../patch_fft.patch . &&
    git apply patch_fft.patch &&
    rm -rf build &&
    mkdir build &&
    cd build &&
    cmake ../src -DCMAKE_BUILD_TYPE=optim -DENABLE_SPQLIOS_AVX=on -DENABLE_SPQLIOS_FMA=on -DCMAKE_INSTALL_PREFIX=./../installed &&
    make -j$(nproc) &&
    make install &&
    cd ../..
else
  echo "TFHE already built. Skipping..."
fi
