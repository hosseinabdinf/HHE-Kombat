#include <x86intrin.h>

#include <cstdio>

#include "../Yux/Yu2x-8.h"
#include "utils/printer.h"
#include "utils/utils.h"

#if 1
// int main(int argc, char **argv)
int main() {
  Printer printer(true);
  printer.PrintHeader("Yux 2-8 Symmetric Cipher");


  int ROUND = 12;
  int BlockSize = 128;
  int BlockByte = BlockSize / 8;

  int i, Nr = ROUND;
  int Nk = BlockByte;  // a block has Nk bytes
  long roundKeySize = (Nr + 1) * Nk;
  unsigned char in[Nk], enced[Nk], Key[Nk], RoundKey[roundKeySize];

  // Part 1 is for demonstrative purpose. The key and plaintext are given in the
  // program itself.
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
  BENCHMARK("Symmetric Key Expansion",
            { KeyExpansion(RoundKey, ROUND, BlockByte, Key); });

  // Decrypt roundkey
  unsigned char RoundKey_invert[roundKeySize];
  BENCHMARK("Decrypt RoundKey",
            { decRoundKey(RoundKey_invert, RoundKey, ROUND, BlockByte); });

  // printf("roundKeySchedule---:\n");
  // for (int r = 0; r < ROUND + 1; r++) {
  //   for (int d = 0; d < Nk; d++) {
  //     cout << d;
  //     printf(". %02x ;", RoundKey[r * Nk + d]);
  //   }
  //   cout << "\n";
  // }
  // printf("\nroundKeySchedule---END!\n");

  // The next function call encrypts the PlainText with the Key using Symmetric
  // algorithm.
  printer.PrintMessages("Number of plaintexts:", Nk,
                        ", size of element (bit): ", sizeof(in[0])*8);
  BENCHMARK("Symmetric Encryption",
            { encryption(enced, in, RoundKey, ROUND); });

  unsigned char deced[Nk];
  BENCHMARK("Symmetric Decryption",
            { decryption(deced, enced, RoundKey_invert, ROUND); });

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
