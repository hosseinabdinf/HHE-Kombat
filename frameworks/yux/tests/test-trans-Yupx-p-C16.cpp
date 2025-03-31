#include <helib/helib.h>
#include <stdint.h>

#include <cstring>

#include "../transciphering/trans-Yupx-p-C16.h"
#include "params.h"
#include "utils/printer.h"
#include "utils/utils.h"

using namespace helib;
using namespace std;
using namespace NTL;

#define homDec
// #define DEBUG
#define homEnc

static long mValues[][4] = {
    //{   p,       m,   bits}
    {65537, 131072, 1320, 6},  // m=(3)*{257} 1250
    {65537, 65536, 853, 17},   // m=(3)*{257}
};

bool dec_test() {
  Printer printer(true);
  printer.PrintHeader("Yu[p]x-C16");

  int idx = 1;
  if (idx > 1) {
    idx = 1;
  }

  int i, Nr = pROUND;  // Nr is round number
  int Nk = 16;         // a block has Nk Words
  long plain_mod = 65537;
  long roundKeySize = (Nr + 1) * Nk;
  int nBlocks = 2;
  uint64_t in[Nk], Key[Nk];

  uint64_t plain[16] = {0x09990, 0x049e1, 0x0dac4, 0x053b5, 0x0ff86, 0x06f91,
                        0x07a8f, 0x0e700, 0x0152e, 0x034b6, 0x0a16f, 0x01219,
                        0x00b83, 0x09ab7, 0x06b12, 0x0e2b1};
  uint64_t plain1[32] = {
      7,       14794,   19266,   12709,   17341,   20442,   7,       7,
      27241,   22276,   9410,    7,       1822,    7,       13834,   4821,
      0x09990, 0x049e1, 0x0dac4, 0x053b5, 0x0ff86, 0x06f91, 0x07a8f, 0x0e700,
      0x0152e, 0x034b6, 0x0a16f, 0x01219, 0x00b83, 0x09ab7, 0x06b12, 0x0e2b1};
  uint64_t temp3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  Vec<uint64_t> ptxt(INIT_SIZE, nBlocks * Nk);  // 8*10
  Vec<uint64_t> symEnced(INIT_SIZE, nBlocks * Nk);

  // Copy the Key and PlainText
  for (i = 0; i < Nk; i++) {
    Key[i] = temp3[i];
  }
  for (i = 0; i < Nk * nBlocks; i++) {
    ptxt[i] = plain1[i];
  }

  Yux_F_p cipher = Yux_F_p(Nk, Nr, plain_mod);

  // The KeyExpansion routine must be called before encryption.
  uint64_t keySchedule[roundKeySize];
  BENCHMARK("Symmetric Key Expansion",
            { cipher.KeyExpansion(keySchedule, Key); });

  printer.PrintMessages(
      "Number of plaintexts:", ptxt.length(),
      ", size of element (bit): ", sizeof(ptxt.data()[0]) * 8);
      
  // 1. Symmetric encryption: symCtxt = Enc(symKey, ptxt)
  BENCHMARK("Symmetric Encryption", {
    for (long i = 0; i < nBlocks; i++) {
      Vec<uint64_t> tmp(INIT_SIZE, Nk);
      cipher.encryption(&symEnced[Nk * i], &ptxt[Nk * i], keySchedule);
    }
  });

  printf("\nText after Yux encryption:\n");
  for (i = 0; i < Nk; i++) {
    printf("%05llx ", static_cast<unsigned long long>(symEnced[i]));
  }
  printf("\n\n");

  /************************************FHE dec Yupx-p-sym Begin
   * ******************************************************/
  printer.PrintMessages("Test Symmetric: [", "c=", mValues[idx][3],
                        ", packed=", true, ", m=", mValues[idx][1],
                        ", rounds=", pROUND, ", block words=", BlockWords, "]");

  // Decrypt roundkey
  uint64_t RoundKey_invert[roundKeySize];
  BENCHMARK("Decrypt Round Key",
            { cipher.decRoundKey(RoundKey_invert, keySchedule); });

  printer.PrintMessage("Generating HE context");
  auto context = Transcipher16_F_p::create_context(
      mValues[idx][1], mValues[idx][0], /*r=*/1, mValues[idx][2],
      /*c=*/mValues[idx][3], /*d=*/1, /*k=*/128, /*s=*/1);

  Transcipher16_F_p FHE_cipher(context);

  FHE_cipher.print_parameters();
  // cipher.activate_bsgs(use_bsgs);
  // cipher.add_gk_indices();
  FHE_cipher.create_pk();

  vector<Ctxt> heKey;
  vector<uint64_t> keySchedule_dec(roundKeySize);

  BENCHMARK("KeySchedule", {
    for (int i = 0; i < roundKeySize; i++)
      keySchedule_dec[i] = RoundKey_invert[i];
  });

  BENCHMARK("HE.Enc(symKey)",
            { FHE_cipher.encryptSymKey(heKey, keySchedule_dec); });

  // print the HE.Enc(symKey) noise
  printer.PrintMessage("HE.Enc(symKey) noise: ");
  FHE_cipher.print_noise(heKey);

  vector<Ctxt> homEncrypted;
  BENCHMARK("Transciphering (Sym.Dec) ... ",
            { FHE_cipher.FHE_YuxDecrypt(homEncrypted, heKey, symEnced); });

  // print the noise after transciphering
  printer.PrintMessage("Transciphering (Sym.Dec) noise: ");
  FHE_cipher.print_noise(homEncrypted);

  // homomorphic decryption
  Vec<ZZX> poly(INIT_SIZE, homEncrypted.size());
  Vec<uint64_t> HHEResult(INIT_SIZE, nBlocks * Nk);

  BENCHMARK("Final Homomorphic Decryption & Decoding", {
    for (long i = 0; i < poly.length(); i++) {
      FHE_cipher.decrypt(homEncrypted[i], poly[i]);
    }
    FHE_cipher.decodeTo16Ctxt(HHEResult, poly);
  });

  Vec<uint64_t> symDeced(INIT_SIZE, nBlocks * Nk);
  BENCHMARK("Symmetric Decryption", {
    for (long i = 0; i < nBlocks; i++) {
      cipher.decryption(&symDeced[Nk * i], &symEnced[Nk * i], RoundKey_invert);
    }
  });

  cout << "-> Original ptxt: ";
  printState_p(ptxt);

  cout << "-> Encrypted: ";
  printState_p(symEnced);

  cout << "-> Final output (HE.Dec): ";
  printState_p(HHEResult);

  cout << "-> Final output (SKE.Dec): ";
  printState_p(symDeced);
  cout << endl;

  // Output the encrypted text.
  // printf("\nText after Yux decryption:\n");
  // for (i = 0; i < Nk * nBlocks; i++) {
  //   if ((i + 1) % 17 == 0) cout << endl;
  //   cout << i;
  //   printf(". %05llx ", static_cast<unsigned long long>(symDeced[i]));
  // }
  // printf("\n\n");

  if (ptxt != HHEResult) {
    cout << "@ decryption error\n";
    if (ptxt.length() != HHEResult.length())
      cout << "  size mismatch, should be " << ptxt.length() << " but is "
           << HHEResult.length() << endl;
    else {
      cout << "-> Original ptx: ";
      printState_p(ptxt);
      cout << "-> Encrypted: ";
      printState_p(symEnced);
      cout << endl;
      cout << "-> Final output (HE.Dec): ";
      printState_p(HHEResult);
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