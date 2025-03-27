#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <stdint.h>
// #include <NTL/ZZX.h>
// #include <NTL/GF2X.h>

#include <helib/helib.h>
// #include <helib/ArgMap.h>
// #include <helib/DoubleCRT.h>
// #include <helib/timing.h>

// #include "../symmetric/Yux-F_p.h"
#include "../transciphering/transciphering-F_p-16.h"

#include "utils.h"
#include "utils/utils.h"
#include <x86intrin.h>

using namespace helib;
using namespace std;
using namespace NTL;

#define homDec
// #define DEBUG
//  #define homEnc

static long mValues[][4] = {
    //{   p,       m,   c,  bits}
    {65537, 16384, 2, 120},  // 0
    {65537, 32768, 4, 750},  // 1
    {65537, 65536, 12, 750}, // 4,3,2
    {65537, 131072, 2, 750},

    // { 65537,   4369,  360}, // m=17*(257)
    // { 65537,}, // m=5*17*(257)
    // { 65537,}, // m=7*17*(241) bits: 600
    // { 65537, }, // m=13*17*(241) bits: 630
    // { 65537,}  // m=97*(673)
};

bool dec_test() {
  // benchmarking variables
  long start_mem, end_mem;
  uint32_t aux;
  uint64_t start_cycle, end_cycle;
  struct timespec start_time, end_time;

  int idx = 2;
  if (idx > 3) {
    idx = 2;
  }
  int i, Nr = pROUND; // Nr is round number
  int Nk = 16;        // a block has Nk Words
  long plain_mod = 65537;
  long roundKeySize = (Nr + 1) * Nk;
  int nBlocks = 1;
  uint64_t in[Nk], Key[Nk];

  uint64_t plain[16] = {0x09990, 0x049e1, 0x0dac4, 0x053b5, 0x0ff86, 0x06f91,
                        0x07a8f, 0x0e700, 0x0152e, 0x034b6, 0x0a16f, 0x01219,
                        0x00b83, 0x09ab7, 0x06b12, 0x0e2b1};
  uint64_t plain1[16] = {0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999,
                         0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999,
                         0x09999, 0x09999, 0x09999, 0x09999};
  uint64_t temp3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  Vec<uint64_t> ptxt(INIT_SIZE, nBlocks * Nk); // 8*10
  Vec<uint64_t> symEnced(INIT_SIZE, nBlocks * Nk);

  // Copy the Key and PlainText
  for (i = 0; i < Nk; i++) {
    Key[i] = temp3[i];
    ptxt[i] = plain1[i];
  }

  Yux_F_p cipher = Yux_F_p(Nk, Nr, plain_mod);

  //  ********************************************************
  // The KeyExpansion routine must be called before encryption.
  PrintHeader("Symmetric Key Expansion");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  uint64_t keySchedule[roundKeySize];
  cipher.KeyExpansion(keySchedule, Key);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  // 1. Symmetric encryption: symCtxt = Enc(symKey, ptxt)
  PrintHeader("Symmetric Encryption");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  for (long i = 0; i < nBlocks; i++) {
    Vec<uint64_t> tmp(INIT_SIZE, Nk);
    cipher.encryption(&symEnced[Nk * i], &ptxt[Nk * i], keySchedule);
  }

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  // Output the encrypted text.
  printf("\n-> Text after Yux encryption:\n");
  for (i = 0; i < Nk; i++) {
    printf("%05lx ", symEnced[i]);
  }
  printf("\n\n");

  /*
   * FHE dec Yux-F_p Begin
   */

  // Decrypt roundkey
  uint64_t RoundKey_invert[roundKeySize];
  cipher.decRoundKey(RoundKey_invert, keySchedule);

  printf("-> RoundKeyInvert:\n");
  for (int r = 0; r < Nr + 1; r++) {
    cout << "round" << r << " : ";
    for (int d = 0; d < Nk; d++) {
      cout << d;
      printf(". %05lx ", RoundKey_invert[r * Nk + d]);
    }
    cout << "\n";
  }
  printf("\n-> RoundKeyInvert---END!\n");

  PrintHeader("Initialising HE Context Object");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  auto context = Transcipher16_F_p::create_context(
      mValues[idx][1], mValues[idx][0], /*r=*/1, /*bits*/ mValues[idx][3],
      /*c=*/mValues[idx][2], /*d=*/1, /*k=*/128, /*s=*/1);
  Transcipher16_F_p FHE_cipher(context);

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
  FHE_cipher.print_parameters();
  cout << "----------------------------------- \n";
  // cipher.activate_bsgs(use_bsgs);
  // cipher.add_gk_indices();
  FHE_cipher.create_pk();

  PrintHeader("HE encrypting symmetric key");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  vector<Ctxt> heKey;
  vector<uint64_t> keySchedule_dec(roundKeySize);
  for (int i = 0; i < roundKeySize; i++)
    keySchedule_dec[i] = RoundKey_invert[i];
  FHE_cipher.encryptSymKey(heKey, keySchedule_dec);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  cout << "-> initial noise:" << endl;
  FHE_cipher.print_noise(heKey);

  vector<Ctxt> homEncrypted;
  PrintHeader("Yux Tranciphering");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  FHE_cipher.FHE_YuxDecrypt(homEncrypted, heKey, symEnced);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  cout << "-> final noise:" << endl;
  FHE_cipher.print_noise(homEncrypted);

  cout << "Final decrypt..." << flush;
  // time_start = chrono::high_resolution_clock::now();
  
  PrintHeader("Decrypt the final ciphertext");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  // homomorphic decryption
  Vec<uint64_t> poly(INIT_SIZE, homEncrypted.size());
  cout << endl;
  for (long i = 0; i < poly.length(); i++) {
    FHE_cipher.decrypt(homEncrypted[i], poly[i]);
    cout << i;
    printf(". %05lx ", poly[i]);
  }
  cout << endl;

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);
  

  Vec<uint64_t> symDeced(INIT_SIZE, nBlocks * Nk);
  for (long i = 0; i < nBlocks; i++) {
    cipher.decryption(&symDeced[Nk * i], &symEnced[Nk * i], RoundKey_invert);
  }
  // Output the encrypted text.
  printf("\nText after Yux decryption:\n");
  for (i = 0; i < Nk; i++) {
    cout << i;
    printf(". %05lx ", symDeced[i]);
  }
  printf("\n\n");
  printState_p(symDeced);
  cout << endl;

  if (ptxt != symDeced) {
    cout << "@ decryption error\n";
    if (ptxt.length() != symDeced.length())
      cout << "  size mismatch, should be " << ptxt.length() << " but is "
           << symDeced.length() << endl;
    else {
      cout << "  input symCtxt = ";
      printState_p(symEnced);
      cout << endl;
      cout << "  output    got = ";
      printState_p(symDeced);
      cout << endl;
      cout << " should be ptxt = ";
      printState_p(ptxt);
      cout << endl;
    }
  }
  // if (plain != plaintext) {
  // //   cerr << cipher.get_cipher_name() << " KATS failed!\n";
  // //   utils::print_vector("key:      ", key, cerr);
  // //   utils::print_vector("ciphertext", ciphertext_expected, cerr);
  // //   utils::print_vector("plain:    ", plaintext, cerr);
  // //   utils::print_vector("got:      ", plain, cerr);
  // //   return false;
  // // }
  return true;
}

int main(int argc, char **argv) { dec_test(); }