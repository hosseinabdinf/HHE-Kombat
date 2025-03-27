#!/usr/bin/env bash

# ###########################################################
# This script is used to build the third-party libraries
# required for the project.
# ###########################################################

# ==========================================================
#     NTL and GMP are required for HElib
# ==========================================================
NTL_VERSION="ntl-11.5.1"
if [ ! -d "NTL/usr/local" ]; then
  echo "NTL not found. Downloading and building..."
  wget https://www.shoup.net/ntl/$NTL_VERSION.tar.gz &&
    tar xf $NTL_VERSION.tar.gz &&
    rm $NTL_VERSION.tar.gz &&
    cd $NTL_VERSION/src &&
    ./configure SHARED=on NTL_GMP_LIP=on NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on &&
    make -j4 &&
    make install DESTDIR=$(pwd)/../../NTL &&
    cd ../.. &&
    rm -r $NTL_VERSION
else
  echo "NTL already built. Skipping..."
fi

GMP_VERSION="6.2.1"
if [ ! -d "GMP/usr/local" ]; then
  echo "GMP not found. Downloading and building..."
  wget https://gmplib.org/download/gmp/gmp-$GMP_VERSION.tar.xz &&
    tar xf gmp-$GMP_VERSION.tar.xz &&
    rm gmp-$GMP_VERSION.tar.xz &&
    cd gmp-$GMP_VERSION &&
    ./configure --enable-cxx --enable-shared &&
    make -j$(nproc) &&
    make install DESTDIR=$(pwd)/../GMP &&
    cd .. &&
    rm -r gmp-$GMP_VERSION
else
  echo "GMP already built. Skipping..."
fi

# ==========================================================
#     HElib
# ==========================================================
if [ ! -d "HElib/install" ]; then
  echo "HElib not found. Building..."
  git clone https://github.com/homenc/HElib.git
  cd HElib
  # Check if the branch exists and switch to it
  if [ "$(git rev-parse --abbrev-ref HEAD)" != "v2.2.1" ]; then
    echo "Switching to branch v2.2.1..."
    git fetch --all
    git checkout v2.2.1
  fi

  # Build and install HElib
  cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DGMP_DIR=./../GMP/usr/local/ -DNTL_DIR=./../NTL/usr/local/ -DBUILD_SHARED=on -DENABLE_THREADS=ON -DCMAKE_INSTALL_PREFIX=./install . &&
    make -j$(nproc) &&
    make install &&
    cd ..
else
  echo "HElib already built. Skipping..."
fi

# ==========================================================
#     M4RI
# ==========================================================
if [ ! -d "m4ri/installed" ]; then
  echo "M4RI not found. Building..."
  git clone https://github.com/malb/m4ri.git
  cd m4ri
  autoreconf --install
  rm -rf installed
  mkdir installed
  ./configure --prefix=$(pwd)/installed
  make -j$(nproc)
  make install
  cd ..
else
  echo "M4RI already built. Skipping..."
fi

# ==========================================================
#     TFHE
# ==========================================================
if [ ! -d "tfhe/installed" ]; then
  echo "TFHE not found. Building..."
  git clone https://github.com/tfhe/tfhe.git
  cd tfhe &&
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
