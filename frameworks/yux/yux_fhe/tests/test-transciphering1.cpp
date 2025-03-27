#include <NTL/GF2X.h>
#include <NTL/ZZX.h>
#include <cstring>
#include <stdint.h>

#include "../symmetric/spn-multi.h"
#include "../transciphering/transciphering1.h"
#include "../transciphering/utils.h"
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include <helib/helib.h>

using namespace helib;
using namespace std;
using namespace NTL;

#define homDec
// #define DEBUG

int main(int argc, char **argv) {

  // ArgMapping amap;

  long idx = 3; // 0
  // amap.arg("sz", idx, "parameter-sets: toy=0 through huge=5");

  long c = 9;
  // amap.arg("c", c, "number of columns in the key-switching matrices");

  bool packed = true;
  // amap.arg("packed", packed, "use packed bootstrapping");

  // amap.parse(argc, argv);
  if (idx > 5)
    idx = 5;

  long p = mValues[idx][0];
  //  long phim = mValues[idx][1];
  long m = mValues[idx][2];

  long bits = mValues[idx][4];

  cout << "-----Test_Sym: c=" << c << ", packed=" << packed << ", m=" << m
       << ", Round=" << ROUND << endl;

  ofstream myfile;
  stringstream filename;
  filename << "result//SPN_1Ctxt_128bit_m = " << m << ", p = " << p
           << ", c = " << c << ", nRounds = " << ROUND << ".txt";

  setTimersOn();
  double tm = -GetTime();

  static const uint8_t YuxPolyBytes[] = {0x1B, 0x1}; // X^8+X^4+X^3+X+1
  const GF2X YuxPoly = GF2XFromBytes(YuxPolyBytes, 2);
  cout << "-----X^8+X^4+X^3+X+1-------\n";
  cout << "-----YuxPoly: " << YuxPoly << "\n";

  cout << "computing key-independent tables..." << std::flush;
  // Some code here to choose all the parameters, perhaps
  // using the fucntion FindM(...) in the FHEContext module

  Context context(ContextBuilder<BGV>().m(m).p(p).r(1).c(c).bits(bits).build());
  // initialize context

  tm += GetTime();
  cout << "done in " << tm << " seconds\n";

  //  context.getZMStar().printout();
  {
    IndexSet allPrimes(0, context.numPrimes() - 1);
    cout << "-----" << context.numPrimes()
         << " total bitsize=" << context.logOfProduct(allPrimes)
         << ", security level: " << context.securityLevel() << endl;

    myfile.open(filename.str(), ios::out);
    myfile << "[ m = " << m << ", p = " << p << ", c = " << c
           << ", nRounds = " << ROUND << "]\n";
    myfile << "1. " << context.numPrimes() << " primes. \n2. total bitsize = "
           << context.logOfProduct(allPrimes)
           << ", \n3. security level = " << context.securityLevel()
           << ", \n4. nslots = " << context.getZMStar().getNSlots() << " ("
           << (context.getZMStar().getNSlots()) / 16 << " blocks) per ctxt\n";
    myfile.close();
  }
  long e = mValues[idx][3] / 8; // extension degree
  cout << "-----" << context.getZMStar().getNSlots() << " slots ("
       << (context.getZMStar().getNSlots() / 8)
       << " blocks) per ctxt, red(p) = " << (context.getZMStar().getOrdP());
  if (packed)
    cout << ". x" << e << " ctxts";
  cout << endl;

  //----生成同态加密的公私钥，
  cout << "computing key-dependent tables..." << std::flush;
  tm = -GetTime();
  SecKey secretKey(context);
  // construct a secret key structure associated with the context

  const PubKey &publicKey = secretKey;
  // an "upcast": SecKey is a subclass of PubKey

  secretKey.GenSecKey();
  // actually generate a secret key with Hamming weight w

  /*
  // Add key-switching matrices for the automorphisms that we need
  long ord = context.getZMStar().OrderOf(0);
  for (long i = 1; i < 16; i++) { // rotation along 1st dim by size i*ord/16
    long exp = i*ord/16;
    long val = PowerMod(context.getZMStar().ZmStarGen(0), exp, m); // val =
  g^exp

    // From s(X^val) to s(X)
    secretKey.GenKeySWmatrix(1, val);
    if (!context.getZMStar().SameOrd(0))
      // also from s(X^{1/val}) to s(X)
      secretKey.GenKeySWmatrix(1, InvMod(val,m));
  }
  */

  addSome1DMatrices(secretKey);
  // compute key-switching matrices that we need

  // addFrbMatrices(secretKey);      // Also add Frobenius key-switching
  // if (boot) { // more tables
  //   addSome1DMatrices(secretKey);
  //   secretKey.genRecryptData();
  // }
  tm += GetTime();
  cout << "done in " << tm << " seconds\n";

  EncryptedArrayDerived<PA_GF2> ea(context, YuxPoly, context.getAlMod());
  cout << "constuct an Encrypted array object ea that is.\n";

  long nslots = ea.size();
  // number of plaintext slots
  cout << "-----number of plaintext slots: " << nslots << "\n\n";
  cout << " !!!!!!!!!!!!dimension() = " << ea.dimension() << endl;
  GF2X rnd;
  //  生成秘钥 Vec_length = BlockByte
  Vec<uint8_t> symKey(INIT_SIZE, BlockByte); // 8*BlockByte
  random(rnd, 8 * symKey.length());
  BytesFromGF2X(symKey.data(), rnd, symKey.length());

  // Choose random plain data

  Vec<uint8_t> ptxt(INIT_SIZE, nBlocks * BlockByte); // 8*10
  Vec<uint8_t> symCtxt(INIT_SIZE, nBlocks * BlockByte);
  Vec<uint8_t> tmpBytes(INIT_SIZE, nBlocks * BlockByte);
  random(rnd, 8 * ptxt.length());
  BytesFromGF2X(ptxt.data(), rnd, nBlocks * BlockByte);

#ifdef DEBUG
  /*---Test Begin----*/
  unsigned char temp[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  unsigned char temp2[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

  // cout << "-------symKey: \n";
  for (int d = 0; d < BlockByte; d++) {
    // printf("%02x ",symKey.data()[d]);
    symKey.data()[d] = temp[d];
    // printf("[new] %02x ;",symKey.data()[d]);
  }
  // cout << "\n-------Ptxt: \n";
  for (int d = 0; d < BlockByte; d++) {
    // printf("%02x ", ptxt.data()[d]);
    ptxt.data()[d] = temp2[d % BlockByte];
    // printf("[new] %02x ;",ptxt.data()[d]);
  }
// cout << "-------Ptxt:  " << ptxt.data() << "\n\n";
/*---Test END----*/
#endif

  // 1. Symmetric encryption: symCtxt = Enc(symKey, ptxt)
  uint8_t keySchedule[BlockByte * (ROUND + 1)];
  KeyExpansion(keySchedule, ROUND, BlockByte, symKey.data());
  for (long i = 0; i < nBlocks; i++) {
    Vec<uint8_t> tmp(INIT_SIZE, BlockByte);
    encryption(&symCtxt[BlockByte * i], &ptxt[BlockByte * i], keySchedule,
               ROUND);
  }
  // cout << "-----symkey random: " << symKey << "\n\n";
  cout << "  ptxt random= ";
  printState(ptxt);
  cout << endl;
  cout << "  encrypted symCtxt ";
  printState(symCtxt);
  cout << endl;

  vector<Ctxt> encryptedSymKey;
  // 2. Decrypt the symKey under the HE key
  Transcipher1 trans;
#ifdef homDec
  cout << "computing symmetric round key tables..." << std::flush;
  tm = -GetTime();
  bool key2dec = true;
  trans.encryptSymKey(encryptedSymKey, symKey, publicKey, ea, key2dec);
  tm += GetTime();
  cout << "done in " << tm << " seconds\n";

  myfile.open(filename.str(), ios::app);
  myfile << "\nHomEnc symmetric round key done in " << tm << " seconds\n";

  // Perform homomorphic Symmetry
  cout << "Homomorphic symmtric decryption Begin!\n" << endl;

  vector<Ctxt> homEncrypted;
  tm = -GetTime();
  auto start = std::chrono::high_resolution_clock::now();
  trans.homSymDec(homEncrypted, encryptedSymKey, symCtxt, ea);
  tm += GetTime();
  auto stop = std::chrono::high_resolution_clock::now();

  cout << "Homomorphic symmtric decryption done in " << tm << " seconds\n";
  // homomorphic decryption
  Vec<ZZX> poly(INIT_SIZE, homEncrypted.size());
  for (long i = 0; i < poly.length(); i++)
    secretKey.Decrypt(poly[i], homEncrypted[i]);
  trans.decodeTo1Ctxt(tmpBytes, poly, ea);

  // Check that homSymDec(symCtxt) = ptxt succeeeded
  // symCtxt = symEnc(ptxt)
  if (ptxt != tmpBytes) {
    cout << "@ decryption error\n";
    if (ptxt.length() != tmpBytes.length())
      cout << "  size mismatch, should be " << ptxt.length() << " but is "
           << tmpBytes.length() << endl;
    else {
      cout << "  input symCtxt = ";
      printState(symCtxt);
      cout << endl;
      cout << "output tmpBytes = ";
      printState(tmpBytes);
      cout << endl;
      cout << " should be ptxt = ";
      printState(ptxt);
      cout << endl;
    }
  } else {
    auto glasped =
        std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    cout << "Homomorphic symmtric decryption correct!! Done [glasped.count()] "
            "in "
         << glasped.count() << " ms" << endl;
    cout << "Homomorphic symmtric decryption correct!! Done in " << tm
         << " seconds\n";
    //  Write file
    // myfile << "[homEncrypted] :  " << homEncrypted << "\n\n";
    {
      myfile << "Homomorphic symmtric decryption Finish! done in " << tm
             << " seconds\n";
      myfile << "[After homomorphic decrypt.length]   " << tmpBytes.length()
             << "\n\n";
      myfile << "  input symCtxt = ";
      myfile << "[";
      for (long i = 0; i < symCtxt.length() && i < 32; i++)
        myfile << std::hex << std::setw(2) << (long)symCtxt[i] << " ";
      if (tmpBytes.length() > 32)
        myfile << "...";
      myfile << "]\n";
      myfile << "output tmpBytes = ";
      myfile << "[";
      for (long i = 0; i < tmpBytes.length() && i < 32; i++)
        myfile << std::hex << std::setw(2) << (long)tmpBytes[i] << " ";
      if (tmpBytes.length() > 32)
        myfile << "...";
      myfile << "]\n";
      myfile << " should be ptxt = ";
      myfile << "[";
      for (long i = 0; i < ptxt.length() && i < 32; i++)
        myfile << std::hex << std::setw(2) << (long)ptxt[i] << " ";
      if (ptxt.length() > 32)
        myfile << "...";
      myfile << "]\n";
    }
    cout << "-------After homomorphic decrypt and Decode's length:   "
         << tmpBytes.length() << "\n";
    cout << "  input symCtxt = ";
    printState(symCtxt);
    cout << endl;
    cout << "output tmpBytes = ";
    printState(tmpBytes);
    cout << endl;
    cout << " should be ptxt = ";
    printState(ptxt);
    cout << endl;
  }
  myfile.close();
  cout << "\n-------Homomorphic symmtric decryption END! \n";
  resetAllTimers();
#endif
}
