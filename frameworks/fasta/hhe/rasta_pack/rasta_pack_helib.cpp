/*
  Code implementing Rasta with 329-bit block in HElib, using one ciphertext for
  whole block. Used only for timing purposes, addition of constants and keys not
  implemented.
*/

#include <NTL/BasicThreadPool.h>
#include <helib/helib.h>
#include <helib/matmul.h>
#include <stdlib.h>

#include <iostream>

using namespace std;
using namespace NTL;
using namespace helib;

#include <x86intrin.h>

#include "matrixFromFile.h"
#include "utils.h"

// double timeChi = 0, timeLinLayer = 0;
vector<MatMulFullExec> MAT;

Ctxt Chi(Ctxt input) {
  /* Returns Chi(input). */
  Ctxt i0(input), i1(input), i2(input);
  const EncryptedArray &ea = input.getContext().getEA();

  ea.rotate(i1, 1);
  ea.rotate(i2, 2);

  i1 *= i2;
  i1 += i2;
  i1 += i0;

  return i1;
}

Ctxt LinLayer(Ctxt input, int round) {
  /* Linear layer of Rasta, multiply with random matrix i. */
  Ctxt out(input);

  MAT[round].mul(out);

  return out;
}

Ctxt Round(Ctxt input, int r) {
  /* Returns the state after one round of Rasta. */
  Ctxt out(input);
  int i;
  out = Chi(input);
  out = LinLayer(out, r);
  return out;
}

int main(int argc, char *argv[]) {
  // benchmarking variables
  long start_mem, end_mem;
  uint32_t aux;
  uint64_t start_cycle, end_cycle;
  struct timespec start_time, end_time;

  /*  Example of BGV scheme  */
  int i, j;
  // double secs_taken;

  // Plaintext prime modulus
  unsigned long p = 2;
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = 30269;
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  unsigned long bits = 500;
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 2;

  PrintHeader("Initialising Context Object");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);
  Context context =
      ContextBuilder<BGV>().m(m).p(p).r(r).bits(bits).c(c).build();
  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  // Print the context
  cout << "----------------------------------- \n";
  PrintHeader("HElib Context");
  context.printout();
  cout << "BitQ: " << context.bitSizeOfQ() << endl;
  cout << "P: " << context.getP() << endl;
  cout << "----------------------------------- \n";

  // Secret key management
  PrintHeader("Creating Secret Key");
  SecKey secret_key(context);
  secret_key.GenSecKey();

  PrintHeader("Generating key-switching matrices");
  // Compute key-switching matrices that we need
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);
  addSome1DMatrices(secret_key);
  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  const PubKey &public_key = secret_key;

  // Get the EncryptedArray of the context
  const EncryptedArray &ea = context.getEA();

  // Get the number of slots (phi(m))
  long nslots = ea.size();
  cout << "-> Number of slots: " << nslots << endl;

  // Reading in random matrices
  char filename[80];
  for (i = 0; i < 7; ++i) {
    sprintf(filename, "matrix_%d.txt", i + 1);
    matrixFromFile nyM(ea, filename);
    MatMulFullExec MMFE(nyM);
    MAT.push_back(MMFE);
  }

  // Create plaintext vector of long with nslots elements each
  Ptxt<BGV> ptxt(context);
  cout << "-> Ptx size:" << ptxt.size() << endl;
  // Fill them with random bits
  for (i = 0; i < ptxt.size(); ++i) ptxt[i] = (long)random() % 2;

  // cout<<"ptxt = "<<ptxt<<endl<<endl;
  // Create a ciphertext object
  Ctxt ctxt(public_key);
  // Encrypt the plaintext using the public_key
  public_key.Encrypt(ctxt, ptxt);

  cout << "-> Bit capacit: " << ctxt.bitCapacity() << endl;

  /* Homomorphic evaluation of Rasta */
  PrintHeader("Starting Rasra-Pack Transciphering");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  // Initial linear transformation
  ctxt = LinLayer(ctxt, 0);
  for (i = 1; i <= 6; ++i) {
    ctxt = Round(ctxt, i);
  }

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);
  cout << "-> Bit capacity: " << ctxt.bitCapacity() << endl;
}
