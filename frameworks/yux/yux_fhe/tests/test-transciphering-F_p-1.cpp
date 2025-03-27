
#include "../transciphering/transciphering-F_p-1.h"

using namespace helib;
using namespace std;
using namespace NTL;

#define homDec
// #define DEBUG
//  #define homEnc

static long mValues[][3] = {
    //{   p,       m,   bits}
    {65537, 16384, 119},  // m=(3)*{257}
    {65537, 131072, 600}, // m=(3)*{257}
    {65537, 65537, 600},  // m=(3)*{257}
    {65537, 8191, 600},   // m=(3)*{257}

    // { 65537,   4369,  360}, // m=17*(257)
    // { 65537,}, // m=5*17*(257)
    // { 65537,}, // m=7*17*(241) bits: 600
    // { 65537, }, // m=13*17*(241) bits: 630
    // { 65537,}  // m=97*(673)
};

bool dec_test() {
  chrono::high_resolution_clock::time_point time_start, time_end;
  chrono::milliseconds time_diff;

  int i, Nr = pROUND; // Nr is round number
  int Nk = 16;        // a block has Nk Words
  long plain_mod = 65537;
  long roundKeySize = (Nr + 1) * Nk;
  int nBlocks = 2;
  uint64_t in[Nk], Key[Nk];

  uint64_t plain[16] = {0x09990, 0x049e1, 0x0dac4, 0x053b5, 0x0ff86, 0x06f91,
                        0x07a8f, 0x0e700, 0x0152e, 0x034b6, 0x0a16f, 0x01219,
                        0x00b83, 0x09ab7, 0x06b12, 0x0e2b1};
  uint64_t plain1[16 * 3] = {
      0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999,
      0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999,
      0x00,    0x00,    0x00,    0x00,    0x00,    0x00,    0x00,    0x00,
      0x00,    0x00,    0x00,    0x00,    0x00,    0x00,    0x00,    0x00,
      0x09990, 0x049e1, 0x0dac4, 0x053b5, 0x0ff86, 0x06f91, 0x07a8f, 0x0e700,
      0x0152e, 0x034b6, 0x0a16f, 0x01219, 0x00b83, 0x09ab7, 0x06b12, 0x0e2b1};
  uint64_t temp3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  Vec<uint64_t> ptxt(INIT_SIZE, nBlocks * Nk); // 8*10
  Vec<uint64_t> symEnced(INIT_SIZE, nBlocks * Nk);

  // Copy the Key and PlainText
  for (i = 0; i < Nk; i++) {
    Key[i] = temp3[i];
  }
  for (i = 0; i < nBlocks * Nk; i++) {
    ptxt[i] = plain1[i];
  }

  Yux_F_p cipher = Yux_F_p(Nk, Nr, plain_mod);

  //             ********************************************************
  // The KeyExpansion routine must be called before encryption.
  uint64_t keySchedule[roundKeySize];
  cipher.KeyExpansion(keySchedule, Key);
  // printf("roundKeySchedule---:\n");
  // for(int r=0;r<ROUND+1; r++)
  // {
  //   cout<<"round" << r <<" : ";
  //   for (int d=0; d< Nk; d++)
  //   {
  //     cout<<d;
  //     printf(". %05lx  ;",keySchedule[r*Nk+d]);
  //   }
  //   cout<< "\n";
  // }
  // printf("\nroundKeySchedule---END!\n");
  int idx = 0;
  if (idx > 5) {
    idx = 0;
  }

  // 1. Symmetric encryption: symCtxt = Enc(symKey, ptxt)
  for (long i = 0; i < nBlocks; i++) {
    Vec<uint64_t> tmp(INIT_SIZE, Nk);
    cipher.encryption(&symEnced[Nk * i], &ptxt[Nk * i], keySchedule);
  }

  printf("\nText after Yux encryption:\n");
  for (i = 0; i < Nk; i++) {
    printf("%05lx ", symEnced[i]);
  }
  printf("\n\n");

  /************************************FHE dec Yux-F_p Begin
   * ******************************************************/

  // Decrypt roundkey
  uint64_t RoundKey_invert[roundKeySize];
  cipher.decRoundKey(RoundKey_invert, keySchedule);

  // printf("RoundKey_invert---:\n");
  // for(int r=0;r<Nr+1; r++)
  // {
  //   cout<<"round" << r <<" : ";
  //   for (int d=0; d< Nk; d++)
  //   {
  //     cout<<d;
  //     printf(". %05lx ",RoundKey_invert[r*Nk+d]);
  //   }
  //   cout<< "\n";
  // }
  // printf("\nRoundKey_invert---END!\n");

  auto context = Transcipher1_F_p::create_context(
      mValues[idx][1], mValues[idx][0], /*r=*/1, mValues[idx][2],
      /*c=*/2, /*d=*/1, /*k=*/128, /*s=*/1);
  Transcipher1_F_p FHE_cipher(context);
  // FHE_cipher.print_parameters();
  FHE_cipher.create_pk();

  cout << "HE encrypting key..." << flush;
  time_start = chrono::high_resolution_clock::now();
  vector<Ctxt> heKey;
  vector<uint64_t> keySchedule_dec(roundKeySize);
  for (int i = 0; i < roundKeySize; i++)
    keySchedule_dec[i] = RoundKey_invert[i];
  FHE_cipher.encryptSymKey(heKey, keySchedule_dec);
  time_end = chrono::high_resolution_clock::now();
  time_diff =
      chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
  cout << "...done" << endl;

  cout << "initial noise:" << endl;
  FHE_cipher.print_noise(heKey);

  cout << "HE decrypting..." << flush;
  time_start = chrono::high_resolution_clock::now();
  vector<Ctxt> homEncrypted;
  FHE_cipher.FHE_YuxDecrypt(homEncrypted, heKey, symEnced);
  time_end = chrono::high_resolution_clock::now();
  time_diff =
      chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
  cout << "...done";
  cout << "           [FHE_YuxDecrypt Time]: " << time_diff.count()
       << " milliseconds" << endl;

  cout << "final noise:" << endl;
  FHE_cipher.print_noise(homEncrypted);

  cout << "Final decrypt..." << flush;
  time_start = chrono::high_resolution_clock::now();

  // homomorphic decryption
  cout << endl;
  for (long i = 0; i < homEncrypted.size(); i++) {
    vector<long> poly = FHE_cipher.decrypt(homEncrypted[i], nBlocks * Nk);
    printState_p(poly);
  }
  cout << endl;

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
  for (i = 0; i < Nk; i++) {
    cout << i;
    printf(". %05lx ", symDeced[i + BlockWords]);
  }
  printf("\n\n");
  // printState_p(symDeced);  cout << endl;

  // if (ptxt != symDeced) {
  //   cout << "@ decryption error\n";
  //   if (ptxt.length()!=symDeced.length())
  //     cout << "  size mismatch, should be "<<ptxt.length()
  //   << " but is "<<symDeced.length()<<endl;
  //   else {
  //     cout << "  input symCtxt = "; printState_p(symEnced); cout << endl;
  //     cout << "  output    got = "; printState_p(symDeced); cout << endl;
  //     cout << " should be ptxt = "; printState_p(ptxt); cout << endl;
  //   }
  // }
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