#include <cstring>
#include <stdint.h>
#include <chrono>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include <helib/timing.h>

#include "../Yux/Yu2x-8.h"
#include "../transciphering/trans-Yu2x-8-C16.h"
#include "../transciphering/utils.h"

using namespace helib;
using namespace std;
using namespace NTL;

#define homDec
//#define DEBUG
// #define homEnc

int main(int argc, char **argv){
  cout << "-----------Begin-------\n";
  // ArgMapping amap;
  //            security Level/2，L, c, p,  d=16/24,  s=预计的槽数， chosen_m=0，false)
  // long FindM(long k, long L, long c, long p, long d, long s, long chosen_m, bool verbose)
  long idx = 3;
  // amap.arg("sz", idx, "parameter-sets: toy=0 through huge=5");

  long c=9;
  // amap.arg("c", c, "number of columns in the key-switching matrices");

  bool packed=true;
  // amap.arg("packed", packed, "use packed bootstrapping");

  // amap.parse(argc, argv);
  if (idx>5) idx = 5;

  long p = mValues[idx][0];
  //  long phim = mValues[idx][1];
  long m = mValues[idx][2];

  long bits = mValues[idx][4];
  #ifdef homEnc
  bits +=15;
  #endif

  cout << "-----Test_Sym: c=" << c
      << ", m=" << m << ", bits =" << bits 
      << endl;

  ofstream myfile;
  stringstream filename;
  filename << "result//SPN_16Ctxt_128bit_m = " << m << ", p = " << p <<  
  ", c = " << c << 
  ", nRounds = " << ROUND << ".txt"; 
  
  setTimersOn();
  double tm = -GetTime();

  static const uint8_t YuxPolyBytes[] = { 0x1B, 0x1 }; // X^8+X^4+X^3+X+1
  
  const GF2X YuxPoly = GF2XFromBytes(YuxPolyBytes, 2);  
  cout << "-----X^8+X^4+X^3+X+1-------\n";  
  cout << "-----YuxPoly: " << YuxPoly << "\n";

  cout << "computing key-independent tables..." << std::flush;
  // Some code here to choose all the parameters, perhaps
  // using the fucntion FindM(...) in the FHEContext module  
  // startFHEtimer("setup");
  Context context(ContextBuilder<BGV>()
                  .m(m)
                  .p(p)
                  .r(1)
                  .c(c)
                  .bits(bits)
                  .build());

  // stopFHEtimer("setup");
  tm += GetTime();
  cout << "done in "<<tm<<" seconds\n";

  //  context.getZMStar().printout();
  myfile.open(filename.str());
  {//IndexSet allPrimes(0,context.numPrimes()-1);
  IndexSet allPrimes = context.allPrimes();
   cout <<"-----"<<context.numPrimes()<<" primes , total bitsize="
	<<context.logOfProduct(allPrimes)
	<<", security level: "<<context.securityLevel() << endl;

  myfile << "[ m = " << m << ", p = " << p
        << ", c = " << c <<", bits = " << bits << ", nRounds = " << ROUND << "]\n"
        <<"1. "<<context.numPrimes()<<" primes , \n2. total bitsize = "
        <<context.logOfProduct(allPrimes)
        <<", \n3. security level = "<<context.securityLevel() 
        << ", \n4. nslots = "<<context.getZMStar().getNSlots()<<" ("
        << (context.getZMStar().getNSlots())<<" blocks) per ctxt"<< endl;
  }
  myfile.close();
  long e = mValues[idx][3] /8; // extension degree
  cout << "-----"<<context.getZMStar().getNSlots()<<" slots ("
       << (context.getZMStar().getNSlots())<<" blocks total), ord(p) = "
       << (context.getZMStar().getOrdP()) << "\n";
  if (packed)
    cout << ". x"<<e<<" ctxts";
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
  
  #ifdef homEnc
  addFrbMatrices(secretKey);
  #endif
  
  tm += GetTime();
  cout << "done in "<<tm<<" seconds\n";

  EncryptedArrayDerived<PA_GF2> ea(context, YuxPoly, context.getAlMod());
  cout << "constuct an Encrypted array object ea.\n";

  long nslots = ea.size(); // number of plaintext slots
  cout << "-----number of plaintext slots: " << nslots << "\n\n";
  //----FHE system setup End----

  cout << " !!!!!!!!!!!!dimension() = " << ea.dimension() <<endl;

    
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
  
  vector<Ctxt> encryptedSymKey;
  // 2. Decrypt the symKey under the HE key

  Transcipher16 trans;

  #ifdef homDec
  cout << "computing symmetric round key tables..." << std::flush;
  tm = -GetTime();
  bool key2dec = true;
  trans.encryptSymKey(encryptedSymKey, symKey, publicKey, ea, key2dec);
  tm += GetTime();  
  cout << "done in "<<tm<<" seconds\n";
  
  myfile.open(filename.str(), ios::app);
  myfile << "\nHomEnc symmetric round key done in "<<tm<<" seconds\n";

  // Perform homomorphic Symmetry
  cout << "Homomorphic symmtric decryption Begin!\n"<< endl;
  vector< Ctxt > homEncrypted;
  tm = -GetTime();
  auto start = std::chrono::high_resolution_clock::now();
  trans.homSymDec(homEncrypted, encryptedSymKey, symCtxt, ea);
  tm += GetTime();
  auto stop = std::chrono::high_resolution_clock::now();

  // homomorphic decryption
  Vec<ZZX> poly(INIT_SIZE, homEncrypted.size());
  for (long i=0; i<poly.length(); i++)
    secretKey.Decrypt(poly[i], homEncrypted[i]);
  trans.decodeTo16Ctxt(tmpBytes, poly, ea);
  
  // Check that homSymDec(symCtxt) = ptxt succeeeded
  // symCtxt = symEnc(ptxt)
  if (ptxt != tmpBytes) {
    myfile << "@ decryption error\n";
    cout << "@ decryption error\n";
    if (ptxt.length()!=tmpBytes.length())
      cout << "  size mismatch, should be "<<ptxt.length()
	   << " but is "<<tmpBytes.length()<<endl;
    else {
      cout << "  input symCtxt = "; printState(symCtxt); cout << endl;
      cout << "output tmpBytes = "; printState(tmpBytes); cout << endl;
      cout << " should be ptxt = "; printState(ptxt); cout << endl;
    }
  }
  else {
    auto glasped = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    cout << "Homomorphic symmtric decryption correct!! Done [glasped.count()] in "<<glasped.count()<<" ms"<<endl;
    cout << "Homomorphic symmtric decryption correct!! Done in "<<tm<<" seconds\n"; 
    //  Write file
    // myfile << "【homEncrypted】:  " << homEncrypted << "\n\n";
    { 
      myfile << "Homomorphic symmtric decryption correct!! done in "<<tm<<" seconds\n\n"; 
      myfile << "【After homomorphic decrypt.length】  " << tmpBytes.length() << "\n\n";
      myfile << "  input symCtxt = "; 
        myfile << "["; for (long i=0; i<symCtxt.length() && i<32; i++)  myfile << std::hex << std::setw(2) << (long) symCtxt[i] << " ";
        if (tmpBytes.length()>32) myfile << "..."; myfile << "]" <<endl; 
      myfile << "output tmpBytes = "; 
        myfile << "["; for (long i=0; i<tmpBytes.length() && i<32; i++) myfile << std::hex << std::setw(2) << (long) tmpBytes[i] << " ";
        if (tmpBytes.length()>32) myfile << "..."; myfile << "]" <<endl;
      myfile << " should be ptxt = ";     
        myfile << "["; for (long i=0; i<ptxt.length() && i<32; i++)   myfile << std::hex << std::setw(2) << (long) ptxt[i] << " ";
        if (ptxt.length()>32) myfile << "...";  myfile << "]" <<endl;
    }
      cout << "-------After homomorphic decrypt and DecodeTo16Ctxt's length:   " << tmpBytes.length() <<"\n";
      cout << "  input symCtxt = "; printState(symCtxt); cout << endl;
      cout << "output tmpBytes = "; printState(tmpBytes); cout << endl;
      cout << " should be ptxt = "; printState(ptxt); cout << endl;
  }
  myfile.close();
  cout << "\n-------Homomorphic symmtric decryption END! \n";
  resetAllTimers();
  #endif


  // 3. Encrypt and check that you have the same thing as before
  #ifdef homEnc
  vector< Ctxt > doublyEncrypted;
  trans.encryptSymKey(encryptedSymKey, symKey, publicKey, ea, /*key2dec=*/false);
  
  cout << "Homomorphic symmtric encryption Begin"<< endl; 
  tm = -GetTime();
  trans.homSymEnc(doublyEncrypted, encryptedSymKey, ptxt, ea);
  tm += GetTime();
  cout << "Homomorphic symmtric encryption End in "<<tm<<" seconds\n";;

  Vec<ZZX> polyEnc(INIT_SIZE, doublyEncrypted.size());
  for (long i=0; i<polyEnc.length(); i++)
    secretKey.Decrypt(polyEnc[i], doublyEncrypted[i]);
  trans.decodeTo16Ctxt(tmpBytes, polyEnc, ea);

  if (symCtxt != tmpBytes) {
    cout << "@ Encryption error\n";
    if (symCtxt.length()!=tmpBytes.length())
      cout << "  size mismatch, should be "<<symCtxt.length()
	   << " but is "<<tmpBytes.length()<<endl;
    else {
      cout << "       input ptxt= "; printState(ptxt); cout << endl;
      cout << "  output tmpBytes= "; printState(tmpBytes); cout << endl;
      cout << "should be symCtxt= "; printState(symCtxt); cout << endl;
    }
  }
  else {
    cout << "correct!! Done in "<<tm<<" seconds\n"; 
    cout << "       input ptxt= "; printState(ptxt); cout << endl;
    cout << "  output tmpBytes= "; printState(tmpBytes); cout << endl;
    cout << "should be symCtxt= "; printState(symCtxt); cout << endl;

  }
  #endif
}
