#include <x86intrin.h>

#include <cstdio>

#include "../Yux/Yu2x-16.h"
#include "utils/printer.h"
#include "utils/utils.h"

#if 1
int main() {
  Printer printer(true);
  printer.PrintHeader("Yux 2-16 Symmetric Cipher");

  int ROUND = 12;
  int BlockSize = 256;
  int BlockByte = BlockSize / 8;

  // static uint8_t polyBytes[] = { 0x1B,0x1}; // X^8+X^4+X^3+X+1
  static uint8_t polyBytes16[] = {0x0B, 0x10, 0x1};  // x^16+x^12+x^3+x+1

  GF2X poly16 = GF2XFromBytes(polyBytes16, 3);
  cout << "-----_Poly16: " << poly16 << "\n";
  GF2E::init(poly16);

  int i, Nr = ROUND;
  int Nk = BlockByte / 2;  // a block has Nk 2 bytes

  Vec<GF2E> RoundKey;
  unsigned char in[32], enced[32], deced[32], Key[32];

  // Part 1 is for demonstrative purpose. The key and plaintext are given in the
  // program itself.
  // *****************************************************
  unsigned char temp[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  unsigned char temp3[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char temp2[32] = {0x30, 0x00, 0x22, 0x33, 0x30, 0x55, 0x66, 0x77,
                             0x30, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                             0x30, 0x00, 0x22, 0x33, 0x30, 0x55, 0x66, 0x77,
                             0x30, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

  // Copy the Key and PlainText
  for (i = 0; i < BlockByte; i++) {
    Key[i] = temp[i];
    in[i] = temp2[i];
  }

  // The KeyExpansion routine must be called before encryption.
  RoundKey.SetLength(Nk * (Nr + 1));
  unsigned char RoundKeyCh[BlockByte * (Nr + 1)];
  BENCHMARK("Symmetric Key Expansion",
            { Yu2x_16_KeyExpansion(RoundKeyCh, ROUND, BlockByte, Key); });

  for (i = 0; i < Nk * (Nr + 1); i++) {
    unsigned char tmp[2] = {RoundKeyCh[2 * i], RoundKeyCh[2 * i + 1]};
    RoundKey[i] = conv<GF2E>(GF2XFromBytes(tmp, 2));
  }

  // printf("RoundKey---:\n");
  //   for(int r=0;r<Nk*(Nr+1); r++)
  //   {
  //     for (int d=0; d< Nk; d++)
  //     {
  //       cout<<d;
  //       // printf(". %02x ;",RoundKey_invert[r*Nk+d]);
  //       unsigned char p[2];
  //       BytesFromGF2X(p, conv<GF2X>(RoundKey[r*Nk+d]), 2);
  //       printf(" [%02x,%02x], ",p[0], p[1]);
  //     }
  //     cout<< "\n";
  //   }
  //   printf("RoundKey---END!\n");

  // Decrypt roundkey
  Vec<GF2E> RoundKey_invert;
  RoundKey_invert.SetLength(Nk * (Nr + 1));
  BENCHMARK("Decrypt RoundKey",
            { Yu2x_16_decRoundKey(RoundKey_invert, RoundKey, ROUND, Nk); });

  // RoundKey_invert = RoundKey;
  printer.PrintMessages("Number of plaintexts:", 32,
                        ", size of element (bit): ", sizeof(in[0]) * 8);

  BENCHMARK("Symmetric Encryption",
            { Yu2x_16_encryption(enced, in, RoundKey, ROUND); });

  // deced.SetLength(Nk);
  BENCHMARK("Symmetric Decryption",
            { Yu2x_16_decryption(deced, enced, RoundKey_invert, ROUND); });

  // output the original text.
  printf("\nText before encryption:\n");
  for (i = 0; i < BlockByte; i++) {
    printf("%02x ", in[i]);
  }
  printf("\n\n");

  // Output the enccrypted text.
  printf("\n1.Text after encryption:\n");
  for (i = 0; i < BlockByte; i++) {
    printf("%02x ", enced[i]);
    // unsigned char p;
    // BytesFromGF2X(&p, conv<GF2X>(enced[i]), 1);
    // printf(" %02x, ",p);
  }
  printf("\n\n");

  // // Output the deccrypted text.
  printf("\n2.Text after decryption:\n");
  for (i = 0; i < BlockByte; i++) {
    printf("%02x ", deced[i]);
    // unsigned char p;
    // BytesFromGF2X(&p, conv<GF2X>(deced[i]), 1);
    // printf(" %02x, ",p);
  }
  printf("\n\n");
  return 0;
}
#endif
