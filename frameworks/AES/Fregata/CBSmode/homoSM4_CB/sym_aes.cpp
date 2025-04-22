// sym_aes.cpp
#include <cstdio>

#include "AES.h"
#include "utils/printer.h"
#include "utils/utils.h"

void printData(const char* msg, const unsigned char* arr, int length) {
  printf("\n%s\n", msg);
  for (int i = 0; i < length; i++) {
    printf("%02x ", arr[i]);
  }
  printf("\n");
}

int main() {
  Printer printer(true);
  printer.PrintHeader("AES Symmetric Encryption");

  int i, Nr = 0, Nk = 0, NN = 128;
  unsigned char in[16], out[16], dec[16], Key[32], RoundKey[240];

  Nk = NN / 32;
  Nr = Nk + 6;

  unsigned char plain[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                             0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
  unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  for (i = 0; i < Nk * 4; i++) {
    Key[i] = key[i];
    in[i] = plain[i];
  }

  BENCHMARK("AES Key Expansion", { AESKeyExpansion(RoundKey, Key, NN); });

  BENCHMARK("AES Sym Encryption", { Cipher(out, in, RoundKey, Nr); });

  printData("Text before encryption:", in, Nk * 4);

  printData("Text after encryption:", out, Nk * 4);

  return 0;
}
