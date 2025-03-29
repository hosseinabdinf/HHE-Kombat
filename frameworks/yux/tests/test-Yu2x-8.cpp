#include <x86intrin.h>

#include <cstdio>

#include "../Yux/Yu2x-8.h"
#include "utils/utils.h"

#if 1
// int main(int argc, char **argv)
int main() {
  // benchmarking variables
  long start_mem, end_mem;
  uint32_t aux;
  uint64_t start_cycle, end_cycle;
  struct timespec start_time, end_time;

  int ROUND = 12;
  int BlockSize = 128;
  int BlockByte = BlockSize / 8;

  int i, Nr = ROUND;
  int Nk = BlockByte;  // a block has Nk bytes
  long roundKeySize = (Nr + 1) * Nk;
  unsigned char in[Nk], enced[Nk], Key[Nk], RoundKey[roundKeySize];

  // Part 1 is for demonstrative purpose. The key and plaintext are given in the program itself.
  //     Part 1: ********************************************************
  // The array temp stores the key.
  // The array temp2 stores the plaintext.
  unsigned char temp[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  unsigned char temp3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char temp2[16] = {0x30, 0x00, 0x22, 0x33, 0x30, 0x55, 0x66, 0x77,
                             0x30, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  // Copy the Key and PlainText
  for (i = 0; i < Nk; i++) {
    Key[i] = temp[i];
    in[i] = temp3[i];
  }

  // The KeyExpansion routine must be called before encryption.
  PrintHeader("Symmetric Key Expansion");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  KeyExpansion(RoundKey, ROUND, BlockByte, Key);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  // Decrypt roundkey
  PrintHeader("Decrypt RoundKey");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  unsigned char RoundKey_invert[roundKeySize];
  decRoundKey(RoundKey_invert, RoundKey, ROUND, BlockByte);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  // printf("roundKeySchedule---:\n");
  // for (int r = 0; r < ROUND + 1; r++) {
  //   for (int d = 0; d < Nk; d++) {
  //     cout << d;
  //     printf(". %02x ;", RoundKey[r * Nk + d]);
  //   }
  //   cout << "\n";
  // }
  // printf("\nroundKeySchedule---END!\n");

  // The next function call encrypts the PlainText with the Key using Symmetric algorithm.
  PrintHeader("Symmetric Encryption");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  encryption(enced, in, RoundKey, ROUND);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  PrintHeader("Symmetric Decryption");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_mem = GetMemoryUsage();
  start_cycle = __rdtscp(&aux);

  unsigned char deced[Nk];
  decryption(deced, enced, RoundKey_invert, ROUND);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  // print the benchmarks
  cout << "-> done! \n";
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  // output the original text.
  printf("\nText before encryption:\n");
  for (i = 0; i < Nk; i++) {
    printf("%02x ", in[i]);
  }
  printf("\n\n");

  // Output the deccrypted text.
  printf("\nText after encryption:\n");
  for (i = 0; i < Nk; i++) {
    printf("%02x ", enced[i]);
  }
  printf("\n\n");

  // Output the encrypted text.
  printf("\nText after decryption:\n");
  for (i = 0; i < Nk; i++) {
    printf("%02x ", deced[i]);
  }
  printf("\n\n");

  return 0;
}
#endif
