/*
  Code implementing homomorphic evaluation of Fasta in HElib.
  Used only for timing purposes, addition of constants and keys not
  implemented.
*/

#include <gmp.h>
#include <iostream>
#include <stdlib.h>
using namespace std;

#include <helib/helib.h>
using namespace helib;

#include "utils.h"
#include <x86intrin.h>

// arrays for the rotation amounts.  Updated for every linear transformation.
int R1[4], R2[4], R3[4], ii[4], jj[4], kk[4];

void fillRotationAmounts(mpz_t N) {
  /* Generates the 20 rotation amounts given by N and fills them in R1, R2, ii,
   * jj and kk. */
  int i;
  mpz_t r, q;

  mpz_init(r);
  mpz_init(q);
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 3);
    R1[i] = 1 + (int)mpz_get_ui(r);
    N = q;
  }
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 3);
    R2[i] = 4 + (int)mpz_get_ui(r);
    R3[i] = 7 + ((2 * R1[i] + R2[i] + 1) % 3);
    N = q;
  }
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 5);
    ii[i] = (int)mpz_get_ui(r);
    N = q;
  }
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 19);
    jj[i] = (int)mpz_get_ui(r);
    N = q;
  }
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 62);
    kk[i] = (int)mpz_get_ui(r);
    N = q;
  }
}

void printRotationAmounts() {
  /* Prints the current rotation amounts. */
  int i;

  for (i = 0; i < 4; ++i)
    printf("%d ", R1[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%d ", R2[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%d ", R3[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%d ", ii[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%2d ", jj[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%2d ", kk[i]);
  printf("|\n");
}

vector<Ctxt> Chi(vector<Ctxt> input) {
  /* Returns Chi(input). */
  int i;
  vector<Ctxt> output;

  const EncryptedArray &ea = input[0].getContext().getEA();

  for (i = 0; i < 5; ++i) {
    Ctxt i0(input[i]), i1(input[i]), i2(input[i]);
    ea.rotate(i1, 1);
    ea.rotate(i2, 2);

    i1 *= i2;
    i1 += i2;
    i1 += i0;

    output.push_back(i1);
  }

  return output;
}

vector<Ctxt> Iteration(vector<Ctxt> input, int iterationNumber) {
  /* Returns iteration number iterationNumber of the linear layer.
     That is, adding up the input words, applying Theta(), and feeding the
     output back on the words. */
  Ctxt ThetaBlock(input[0]);
  vector<Ctxt> out;
  int i;

  for (i = 1; i < 5; ++i)
    ThetaBlock += input[i];
  // ThetaBlock=i0+i1+i2+i3+i4

  Ctxt rotR1(ThetaBlock);
  const EncryptedArray &ea = rotR1.getContext().getEA();
  ea.rotate(rotR1, R1[iterationNumber]);

  Ctxt rotR2(ThetaBlock);
  ea.rotate(rotR2, R2[iterationNumber]);

  Ctxt rotR3(ThetaBlock);
  ea.rotate(rotR3, R3[iterationNumber]);

  ThetaBlock += rotR1;
  ThetaBlock += rotR2;
  ThetaBlock += rotR3;
  // here ThetaBlock is the output of Theta

  Ctxt tmp(ThetaBlock);
  for (i = 0; i < 5; ++i) {
    tmp = input[i];
    tmp += ThetaBlock;
    out.push_back(tmp);
  }

  return out;
}

vector<Ctxt> LinearTransformation(vector<Ctxt> input) {
  /* Returns the full linear transformation of the input, for the current
   * rotation values */
  vector<Ctxt> out;
  Ctxt tmp(input[0]);
  int w;

  const EncryptedArray &ea = tmp.getContext().getEA();

  out = Iteration(input, 0);
  for (w = 0; w < 4; ++w)
    ea.rotate(out[w + 1], ii[w]);
  // first iteration done

  out = Iteration(out, 1);
  for (w = 0; w < 4; ++w)
    ea.rotate(out[w + 1], jj[w]);
  // second iteration done

  out = Iteration(out, 2);
  for (w = 0; w < 4; ++w)
    ea.rotate(out[w + 1], kk[w]);
  // third iteration done

  out = Iteration(out, 3);
  // fourth iteration done

  return out;
}

vector<Ctxt> Round(vector<Ctxt> input) {
  /* Returns the state after one round of Rasta. */
  vector<Ctxt> out;

  // clock_t chi_start = clock();
  out = Chi(input);
  // clock_t chi_end = clock();
  // timeChi += (double)(chi_end - chi_start) / CLOCKS_PER_SEC;

  // clock_t LT_start = clock();
  out = LinearTransformation(out);
  // clock_t LT_end = clock();
  // timeLin += (double)(LT_end - LT_start) / CLOCKS_PER_SEC;

  return out;
}

// Print the bit capacities of the blocks
void printBitCapacities(const vector<Ctxt> &fastaBlock) {
  vector<long> capacities;
  for (size_t i = 0; i < fastaBlock.size(); ++i) {
    capacities.push_back(fastaBlock[i].bitCapacity());
  }
  cout << "-> Bit capacities: [";
  for (size_t k = 0; k < capacities.size(); ++k) {
    cout << capacities[k];
    if (k != capacities.size() - 1) {
      cout << ", ";
    }
  }
  cout << "]" << endl;
}

int main(int argc, char *argv[]) {
  // benchmarking variables
  long start_mem, end_mem;
  uint32_t aux;
  uint64_t start_cycle, end_cycle;
  struct timespec start_time, end_time;

  int i, j;
  // double secs_taken;
  mpz_t T, N;
  gmp_randstate_t randomState;

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

  PrintHeader("Initialising HE Context Object");
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
  PrintHeader("Generating secret key");
  // Create a secret key associated with the context
  SecKey secret_key(context);
  // Generate the secret key
  secret_key.GenSecKey();

  PrintHeader("Generating key-switching matrices");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);
  // Compute key-switching matrices that we need
  addSome1DMatrices(secret_key);
  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  PrintHeader("Generating public key");
  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  const PubKey &public_key = secret_key;
  // Get the EncryptedArray of the context
  const EncryptedArray &ea = context.getEA();
  // Get the number of slots (phi(m))
  long nslots = ea.size();
  cout << "-> Number of slots: " << nslots << endl;

  // Create five plaintexts of long with nslots elements each
  // 5 * [329] = 1645 slots
  vector<Ptxt<BGV>> ptxt;
  // Fill them with random bits
  for (j = 0; j < 5; ++j) {
    Ptxt<BGV> tmp(context);
    ptxt.push_back(tmp);
    for (i = 0; i < ptxt[j].size(); ++i)
      ptxt[j][i] = (long)random() % 2;
  }

  cout << "-> Ptx Size: " << ptxt[0].size() << endl;
  // Create ciphertext objects
  vector<Ctxt> fastaBlock;
  // Encrypt the plaintext using the public_key
  for (i = 0; i < 5; ++i) {
    Ctxt tmp(public_key);
    public_key.Encrypt(tmp, ptxt[i]);
    fastaBlock.push_back(tmp);
  }

  printBitCapacities(fastaBlock);

  /* Homomorphic evaluation of six-round Fasta */
  gmp_randinit_default(randomState);
  mpz_init_set_str(T, "7896437765612010000", 10);

  mpz_init(N);
  mpz_urandomm(N, randomState, T);

  PrintHeader("Starting Fasta Transciphering");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_cycle = __rdtscp(&aux);
  start_mem = GetMemoryUsage();

  fillRotationAmounts(N);
  fastaBlock = LinearTransformation(fastaBlock);
  for (i = 0; i < 6; ++i) {
    mpz_urandomm(N, randomState, T);
    fillRotationAmounts(N);
    fastaBlock = Round(fastaBlock);
  }

  clock_gettime(CLOCK_MONOTONIC, &end_time);
  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);
  printBitCapacities(fastaBlock);
}
