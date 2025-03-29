#include <NTL/GF2X.h>
#include <NTL/ZZX.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include <helib/helib.h>
#include <helib/timing.h>
#include <stdint.h>

#include <cstring>

#include "../Yux/Yu2x-8.h"
#include "../transciphering/trans-Yu2x-8-C16.h"
#include "../transciphering/utils.h"
#include "printer.h"
#include "utils/utils.h"

using namespace helib;
using namespace std;
using namespace NTL;

#define homDec
// #define DEBUG
// #define homEnc

int main(int argc, char** argv) {
  // parameter-sets: toy=0 through huge=5
  long idx = 3;

  // number of columns in the key-switching matrices
  long c = 9;

  // use packed bootstrapping
  bool packed = true;

  if (idx > 5) idx = 5;

  long p = mValues[idx][0];
  //  long phim = mValues[idx][1];
  long m = mValues[idx][2];

  long bits = mValues[idx][4];
#ifdef homEnc
  bits += 15;
#endif
  Printer printer(true);
  printer.PrintHeader("Yu2x-8-C16");
  printer.PrintMessages("Test Symmetric: [", "c=", c, ", packed=", packed, ", m=", m, ", rounds=", ROUND,
                        ", block size=", BlockSize, ", bits=", bits, "]");

  // X^8+X^4+X^3+X+1
  static const uint8_t YuxPolyBytes[] = {0x1B, 0x1};

  const GF2X YuxPoly = GF2XFromBytes(YuxPolyBytes, 2);
  printer.PrintMessage("Poly: X^8+X^4+X^3+X+1");
  printer.PrintMessages("Yux Poly: ", YuxPoly);

  printer.PrintMessage("computing key-independent tables...");
  // Some code here to choose all the parameters, perhaps
  // using the fucntion FindM(...) in the FHEContext module
  printer.PrintMessage("Generating HE context");
  Context context(ContextBuilder<BGV>().m(m).p(p).r(1).c(c).bits(bits).build());

  // Print HE context
  {
    IndexSet allPrimes(0, context.numPrimes() - 1);
    printer.PrintMessages("HE context:", " #p=", context.numPrimes(),
                          ", total bitsize=", context.logOfProduct(allPrimes),
                          ", security level=", context.securityLevel());
  }

  long e = mValues[idx][3] / 8;  // extension degree
  printer.PrintMessages(" #slots=", context.getZMStar().getNSlots(), ", #blocks=", (context.getZMStar().getNSlots()),
                        ", Ord(p)=", context.getZMStar().getOrdP());
  if (packed) cout << ". x" << e << " ctxts";
  cout << endl;

  printer.PrintMessage("computing key-dependent tables...");

  // construct a secret key structure associated with the context
  SecKey secretKey(context);

  // an "upcast": FHESecKey is a subclass of PubKey
  const PubKey& publicKey = secretKey;

  // actually generate a secret key with Hamming weight w
  secretKey.GenSecKey();

#ifdef homEnc
  addFrbMatrices(secretKey);
#endif

  // construct an Encrypted array object ea.
  EncryptedArrayDerived<PA_GF2> ea(context, YuxPoly, context.getAlMod());

  // number of plaintext slots
  long nslots = ea.size();
  printer.PrintMessages("#plaintext slots=", nslots, ", dim(Encrypted Array)=", ea.dimension(), "\n");

  GF2X rnd;
  // Choose random symKey data
  // 生成秘钥 Vec_length = BlockByte
  Vec<uint8_t> symKey(INIT_SIZE, BlockByte);  // 8*BlockByte
  random(rnd, 8 * symKey.length());
  BytesFromGF2X(symKey.data(), rnd, symKey.length());

  // Choose random plain data

  Vec<uint8_t> ptxt(INIT_SIZE, nBlocks * BlockByte);  // 8*10
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
    symKey.data()[d] = temp[d];
  }
  // cout << "\n-------Ptxt: \n";
  for (int d = 0; d < BlockByte; d++) {
    ptxt.data()[d] = temp2[d % BlockByte];
  }

// cout << "-------Ptxt:  " << ptxt.data() << "\n\n";
/*---Test END----*/
#endif

  // 1. Symmetric encryption: symCtxt = Enc(symKey, ptxt)
  uint8_t keySchedule[BlockByte * (ROUND + 1)];
  BENCHMARK("Symmetric Key Expansion", { KeyExpansion(keySchedule, ROUND, BlockByte, symKey.data()); });

  BENCHMARK("Symmetric Encryption", {
    for (long i = 0; i < nBlocks; i++) {
      Vec<uint8_t> tmp(INIT_SIZE, BlockByte);
      encryption(&symCtxt[BlockByte * i], &ptxt[BlockByte * i], keySchedule, ROUND);
    }
  });

  vector<Ctxt> encryptedSymKey;
  // 2. Decrypt the symKey under the HE key

  Transcipher16 trans;

#ifdef homDec
  BENCHMARK("HE.Enc(symKey)", {
    bool key2dec = true;
    trans.encryptSymKey(encryptedSymKey, symKey, publicKey, ea, key2dec);
  });

  // Perform homomorphic Symmetrytic decryption
  vector<Ctxt> homEncrypted;
  BENCHMARK("Transciphering (Sym.Dec) ... ", { trans.homSymDec(homEncrypted, encryptedSymKey, symCtxt, ea); });

  // homomorphic decryption
  Vec<ZZX> poly(INIT_SIZE, homEncrypted.size());
  BENCHMARK("Final Homomorphic Decryption & Decoding", {
    for (long i = 0; i < poly.length(); i++) secretKey.Decrypt(poly[i], homEncrypted[i]);
    trans.decodeTo16Ctxt(tmpBytes, poly, ea);
  });

  // Check that homSymDec(symCtxt) = ptxt succeeeded
  // symCtxt = symEnc(ptxt)
  if (ptxt != tmpBytes) {
    cout << "@ decryption error\n";
    if (ptxt.length() != tmpBytes.length())
      cout << "  size mismatch, should be " << ptxt.length() << " but is " << tmpBytes.length() << endl;
    else {
      cout << "-> Original ptx: ";
      printState(ptxt);
      cout << "-> Encrypted: ";
      printState(symCtxt);
      cout << "-> Final output: ";
      printState(tmpBytes);
      cout << endl;
    }
  } else {
    printer.PrintMessage("Yux Transciphering for Sym.Dec() was successful.");
    cout << "-> After final homomorphic decryption the length of output is " << tmpBytes.length() << "\n";

    cout << "-> Original ptx: ";
    printState(ptxt);
    cout << "-> Encrypted: ";
    printState(symCtxt);
    cout << "-> Final output: ";
    printState(tmpBytes);
    cout << endl;
  }
#endif

// 3. Encrypt and check that you have the same thing as before
#ifdef homEnc
  vector<Ctxt> doublyEncrypted;
  BENCHMARK("HE.Enc(symKey)", { trans.encryptSymKey(encryptedSymKey, symKey, publicKey, ea, /*key2dec=*/false); });

  BENCHMARK("Transciphering (Sym.Enc)", { trans.homSymEnc(doublyEncrypted, encryptedSymKey, ptxt, ea); });

  Vec<ZZX> polyEnc(INIT_SIZE, doublyEncrypted.size());
  BENCHMARK("Final Homomorphic Decryption & Decoding", {
    for (long i = 0; i < polyEnc.length(); i++) secretKey.Decrypt(polyEnc[i], doublyEncrypted[i]);
    trans.decodeTo16Ctxt(tmpBytes, polyEnc, ea);
  });

  if (symCtxt != tmpBytes) {
    cout << "@ Encryption error\n";
    if (symCtxt.length() != tmpBytes.length())
      cout << "  size mismatch, should be " << symCtxt.length() << " but is " << tmpBytes.length() << endl;
    else {
      cout << "-> Original ptx: ";
      printState(ptxt);
      cout << "-> Encrypted: ";
      printState(symCtxt);
      cout << "-> Final output: ";
      printState(tmpBytes);
      cout << endl;
    }
  } else {
    printer.PrintMessage("Yux Transciphering for Sym.Enc() was successful.");
    cout << "-> After final homomorphic decryption the length is " << tmpBytes.length() << "\n";

    cout << "-> Original ptx: ";
    printState(ptxt);
    cout << "-> Encrypted: ";
    printState(symCtxt);
    cout << "-> Final output: ";
    printState(tmpBytes);
    cout << endl;
  }
#endif
}
