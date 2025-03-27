#include <cstring>
#include <stdint.h>
#include <iostream>
#include <chrono>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>

#include "../Yux/Yu2x-8.h"
#include "../transciphering/trans-Yu2x-8-C16.h"
#include "../transciphering/utils.h"

using namespace helib;
using namespace std;
using namespace NTL;

#define homDec
//#define DEBUG

//TODO: too long time, so you can run it in a server

void verify(Vec<uint8_t> symCtxt, Vec<uint8_t> tmpBytes, Vec<uint8_t> ptxt,
            double tm, std::chrono::time_point<std::chrono::high_resolution_clock> stop,
            std::chrono::time_point<std::chrono::high_resolution_clock> start)
{
  // Check that homSymDec(symCtxt) = ptxt succeeeded
  // symCtxt = symEnc(ptxt)
  if (ptxt != tmpBytes) {
    cout << "@ decryption error\n";
    if (ptxt.length()!=tmpBytes.length())
      cout << "  size mismatch, should be "<<ptxt.length()
	   << " but is "<<tmpBytes.length()<<endl;
    else {
      cout << "  input symCtxt = "; printState(symCtxt); cout << endl;
      cout << "output tmpBytes = "; printState(tmpBytes); cout << endl;
      cout << " should be ptxt = "; printState(ptxt); cout << endl;
    }
  } else {
    auto glasped = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    cout << "Homomorphic symmtric decryption correct!! Done [glasped.count()] in "<<glasped.count()<<" ms"<<endl;
    cout << "Homomorphic symmtric decryption correct!! Done in "<<tm<<" seconds\n";

    cout << "-------After homomorphic decrypt and DecodeTo16Ctxt's length:   " << tmpBytes.length() <<"\n";
    cout << "  input symCtxt = "; printState(symCtxt); cout << endl;
    cout << "output tmpBytes = "; printState(tmpBytes); cout << endl;
    cout << " should be ptxt = "; printState(ptxt); cout << endl;
  }
  cout << "\n-------Homomorphic symmtric decryption END! \n";
}


void test()
{
  cout << "-----------Begin-------\n";

  long idx = 4; // m = 53261
  if (idx>5) idx = 5;

  long p = mValues[idx][0];
  long m = mValues[idx][2];
  long bits = mValues[idx][4] + 20;

  cout << "-----Test_Sym: p=" << p
      << ", m=" << m
      << endl;
  
  setTimersOn();
  double tm = -GetTime();

  static const uint8_t YuxPolyBytes[] = { 0x1B, 0x1 }; // X^8+X^4+X^3+X+1
  const GF2X YuxPoly = GF2XFromBytes(YuxPolyBytes, 2);  
  cout << "-----YuxPoly: X^8+X^4+X^3+X+1 (" << YuxPoly << ") -------\n";  

  cout << "computing key-independent tables..." << std::flush;
  // Some code here to choose all the parameters, perhaps
  // using the fucntion FindM(...) in the FHEContext module  

  Context context(ContextBuilder<BGV>()
                  .m(m)
                  .p(p)
                  .r(1)
                  .c(m==28679?9:3)
                  .bits(bits)
                  .build());

  
  tm += GetTime();
  cout << "done in "<<tm<<" seconds\n";
 
  {//IndexSet allPrimes(0,context.numPrimes()-1);
   IndexSet allPrimes = context.allPrimes();
   cout <<"-----"<<context.numPrimes()<<" primes , total bitsize="
	<<context.logOfProduct(allPrimes)
	<<", security level: "<<context.securityLevel() << endl;
  }

  cout << "-----"<<context.getZMStar().getNSlots()<<" slots ("
       << (context.getZMStar().getNSlots()/8)<<" blocks) per ctxt, ord(p) = "
       << (context.getZMStar().getOrdP()) << "\n";
  cout << endl;

  //----生成同态加密的公私钥， 
  cout << "computing key-dependent tables..." << std::flush;
  tm = -GetTime();
  SecKey secretKey(context);
  // construct a secret key structure associated with the context

  const PubKey& publicKey = secretKey;
  // an "upcast": FHESecKey is a subclass of PubKey

  secretKey.GenSecKey();
  // actually generate a secret key with Hamming weight w
  addSome1DMatrices(secretKey);

  tm += GetTime();
  cout << "done in "<<tm<<" seconds\n";

  EncryptedArrayDerived<PA_GF2> ea(context, YuxPoly, context.getAlMod());
  cout << "constuct an Encrypted array object ea that is.\n";

  long nslots = ea.size(); // number of plaintext slots
  //----FHE system setup End----

  GF2X rnd;
  // Choose random symKey data
  // 生成秘钥 Vec_length = BlockByte
  Vec<uint8_t> symKey(INIT_SIZE, BlockByte); // 8*BlockByte
  random(rnd, 8*symKey.length());
  BytesFromGF2X(symKey.data(), rnd, symKey.length());

  // Choose random plain data
  
  Vec<uint8_t> ptxt(INIT_SIZE, nBlocks*BlockByte); //8*10
  Vec<uint8_t> symCtxt(INIT_SIZE, nBlocks*BlockByte);
  Vec<uint8_t> tmpBytes(INIT_SIZE, nBlocks*BlockByte);
  random(rnd, 8*ptxt.length());
  BytesFromGF2X(ptxt.data(), rnd, nBlocks*BlockByte);
  
#ifdef DEBUG
  /*---Test Begin----*/
  unsigned char temp[16] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07,0x08  ,0x09  ,0x0A  ,0x0B  ,0x0C  ,0x0D  ,0x0E  ,0x0F};
  unsigned char temp2[16]= {0x00  ,0x11  ,0x22  ,0x33  ,0x44  ,0x55  ,0x66  ,0x77, 0x88  ,0x99  ,0xAA  ,0xBB  ,0xCC  ,0xDD  ,0xEE  ,0xFF};
  
  // cout << "-------symKey: \n";
  for(int d=0; d<BlockByte; d++)
  {
    symKey.data()[d] = temp[d];
  }
  // cout << "\n-------Ptxt: \n";
  for(int d=0; d<BlockByte; d++)
  {
    ptxt.data()[d] = temp2[d%BlockByte];
  }

  //cout << "-------Ptxt:  " << ptxt.data() << "\n\n";
  /*---Test END----*/
#endif

  // 1. Symmetric encryption: symCtxt = Enc(symKey, ptxt) 
  uint8_t keySchedule[BlockByte * (ROUND+1)];
  KeyExpansion(keySchedule, ROUND, BlockByte, symKey.data());
  for (long i=0; i<nBlocks; i++) {
    Vec<uint8_t> tmp(INIT_SIZE, BlockByte);
    encryption(&symCtxt[BlockByte*i], &ptxt[BlockByte*i], keySchedule, ROUND);
  }
  
  Ctxt encryptedSymKey(publicKey);
  // 2. Decrypt the symKey under the HE key

  Transcipher16 trans;

  #ifdef homDec
  cout << "computing symmetric round key tables..." << std::flush;
  tm = -GetTime();
  bool key2dec = true;
  trans.encryptSymKeyForExpand(encryptedSymKey, symKey, publicKey, ea, key2dec);
  tm += GetTime();  
  cout << "done in "<<tm<<" seconds\n";

  cout << "handle round key" << endl;
  vector<Ctxt> expandSymKey;
  long length_s = BlockByte * (ROUND+1);
  tm = -GetTime();
  auto start = std::chrono::high_resolution_clock::now();
  trans.handleRoundKey(expandSymKey, encryptedSymKey, publicKey, ea, length_s);
  tm += GetTime();
  auto stop = std::chrono::high_resolution_clock::now();
  cout << "done in "<<tm<<" seconds\n";
  auto glasped = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
  cout << "done [glasped.count()] in "<<glasped.count()<<" ms"<<endl;

  // Perform homomorphic Symmetry
  cout << "Homomorphic symmtric decryption Begin!\n"<< endl;
  vector<Ctxt> homEncrypted;
  tm = -GetTime();
  start = std::chrono::high_resolution_clock::now();
  trans.homSymDec(homEncrypted, expandSymKey, symCtxt, ea);
  tm += GetTime();
  stop = std::chrono::high_resolution_clock::now();

  // homomorphic decryption
  Vec<ZZX> poly(INIT_SIZE, homEncrypted.size());
  for (long i=0; i<poly.length(); i++)
    secretKey.Decrypt(poly[i], homEncrypted[i]);
  trans.decodeTo16Ctxt(tmpBytes, poly, ea);
  
  // Check that homSymDec(symCtxt) = ptxt succeeeded
  verify(symCtxt, tmpBytes, ptxt, tm, stop, start);

  resetAllTimers();
  #endif
}


int main(int argc, char **argv){
  test();

  return 0;
}
