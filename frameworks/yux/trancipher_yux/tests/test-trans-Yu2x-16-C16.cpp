#include <cstring>
#include <stdint.h>
#include <chrono>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include <helib/timing.h>

#include "../Yux/Yu2x-16.h"
#include "../transciphering/trans-Yu2x-16-C16.h"
#include "../transciphering/utils.h"

using namespace helib;
using namespace std;
using namespace NTL;
#define DEBUG

// lm: I have set the parameters of idx = 0, 4

int nowBlockByte = 256/8;

#if 1
int main(int argc, char **argv){
  cout << "-----------Begin-------\n";

  // ArgMapping amap;
  //            security Level/2，L, c, p,  d=16/24,  s=预计的槽数， chosen_m=0，false)
  // long FindM(long k, long L, long c, long p, long d, long s, long chosen_m, bool verbose)
  long idx = 3;
  // amap.arg("sz", idx, "parameter-sets: toy=0 through huge=5");

  long c=9;
  // amap.arg("c", c, "number of columns in the key-switching matrices");

  long L=25;
  // amap.arg("L", L, "# of levels in the modulus chain",  "heuristic");

  long B=21;
  // amap.arg("B", B, "# of bits per level (only 64-bit machines)");

  bool boot=false;
  // amap.arg("boot", boot, "includes bootstrapping");

  bool packed=true;
  // amap.arg("packed", packed, "use packed bootstrapping");

  // amap.parse(argc, argv);
  if (idx>7) idx =3;
  // {65536, 65537, 32,  1273}, // gens=2(32),3(!2048)

  long p = mValues[idx][0];
  //  long phim = mValues[idx][1];
  long m = mValues[idx][2];
  // long m = 65535;

  long bits = mValues[idx][4];

  cout << "-----Test_Sym: c=" << c
      << ", packed=" << packed
      << ", m=" << m
      << endl;

  ofstream myfile;
  stringstream filename;
  filename << "result//Yu2x-16-Ctxt16_m = " << m << ", p = " << p <<  
  ", L = " << L << ", c = " << c << ", B = " << B << 
  ", nRounds = " << ROUND << ".txt"; 
  
  setTimersOn();
  double tm = -GetTime();

  static uint8_t polyBytes16[] = { 0x0B, 0x10, 0x1}; // x^16+x^12+x^3+x+1

  const GF2X Poly16 = GF2XFromBytes(polyBytes16, 3);  
  cout << "-----x^16+x^12+x^3+x+1-------\n";  
  cout << "-----Poly16: " << Poly16 << "\n";
  GF2E::init(Poly16);
  cout << "computing key-independent tables..." << std::flush;
  // Some code here to choose all the parameters, perhaps
  // using the fucntion FindM(...) in the FHEContext module  

  Context context(ContextBuilder<BGV>()
                  .m(m)
                  .p(p)
                  .r(1)
                  .c(c)
                  .bits(bits)
                  .build());

  
  tm += GetTime();
  cout << "done in "<<tm<<" seconds\n";

  //  context.getZMStar().printout();
  myfile.open(filename.str());
  {IndexSet allPrimes(0,context.numPrimes()-1);
   cout <<"-----"<<context.numPrimes()<<" primes , total bitsize="
	<<context.logOfProduct(allPrimes)
	<<", security level: "<<context.securityLevel() << endl;

  myfile << "[ m = " << m << ", p = " << p << ", L = " << L 
        << ", c = " << c << ", B = " << B << ", nRounds = " << ROUND << "]\n"
        <<"1. "<<context.numPrimes()<<" primes , \n2. total bitsize = "
        <<context.logOfProduct(allPrimes)
        <<", \n3. security level = "<<context.securityLevel() 
        << ", \n4. nslots = "<<context.getZMStar().getNSlots() <<" (blocks) per ctxt"<< endl;
  }
  myfile.close();
  long e = mValues[idx][3] /8; // extension degree
  cout << "-----"<<context.getZMStar().getNSlots()<<" slots ( blocks) per ctxt, ord(p) = "
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

  // Add key-switching matrices for the automorphisms that we need
  // long ord = context.getZMStar().OrderOf(0);
  // for (long i = 1; i < 16; i++) { // rotation along 1st dim by size i*ord/16
  //   long exp = i*ord/16;
  //   long val = PowerMod(context.getZMStar().getZMStar()Gen(0), exp, m); // val = g^exp

  //   // From s(X^val) to s(X)
  //   secretKey.GenKeySWmatrix(1, val);
  //   if (!context.getZMStar().SameOrd(0))
  //     // also from s(X^{1/val}) to s(X)
  //     secretKey.GenKeySWmatrix(1, InvMod(val,m));
  // }
  // addSome1DMatrices(secretKey);
  // addFrbMatrices(secretKey);      // Also add Frobenius key-switching

  tm += GetTime();
  cout << "done in "<<tm<<" seconds\n";

  EncryptedArrayDerived<PA_GF2> ea(context, Poly16, context.getAlMod());
  cout << "constuct an Encrypted array object ea that is.\n";

  long nslots = ea.size(); // number of plaintext slots
  cout << "-----number of plaintext slots: " << nslots << "\n\n";
  //----FHE system setup End----

    
  GF2X rnd;
  // Choose random symKey data
  // 生成秘钥 Vec_length = nowBlockByte
  Vec<uint8_t> symKey(INIT_SIZE, nowBlockByte); // 8*nowBlockByte
  random(rnd, 8*symKey.length());
  BytesFromGF2X(symKey.data(), rnd, symKey.length());

  // Choose random plain data
  
  Vec<uint8_t> ptxt(INIT_SIZE, nBlocks*nowBlockByte); //8*10
  Vec<uint8_t> symCtxt(INIT_SIZE, nBlocks*nowBlockByte);
  Vec<uint8_t> tmpBytes(INIT_SIZE, nBlocks*nowBlockByte);
  random(rnd, 8*ptxt.length());
  BytesFromGF2X(ptxt.data(), rnd, nBlocks*nowBlockByte);
  
  #ifdef DEBUG
  /*---Test Begin----*/
  unsigned char temp[32] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07,0x08  ,0x09  ,0x0A  ,0x0B  ,0x0C  ,0x0D  ,0x0E  ,0x0F,0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07,0x08  ,0x09  ,0x0A  ,0x0B  ,0x0C  ,0x0D  ,0x0E  ,0x0F};
  unsigned char temp3[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char temp2[32]= {0x30  ,0x00  ,0x22  ,0x33  ,0x30  ,0x55  ,0x66  ,0x77, 0x30  ,0x99  ,0xAA  ,0xBB  ,0xCC  ,0xDD  ,0xEE  ,0xFF, 0x30  ,0x00  ,0x22  ,0x33  ,0x30  ,0x55  ,0x66  ,0x77, 0x30  ,0x99  ,0xAA  ,0xBB  ,0xCC  ,0xDD  ,0xEE  ,0xFF};
  // cout << "-------symKey: \n";
  for(int d=0;d<nowBlockByte; d++)
  {
    // printf("%02x ",symKey.data()[d]);
    symKey.data()[d] = temp[d];
    // printf("[new] %02x ;",symKey.data()[d]);

  }
    // cout << "\n-------Ptxt: \n";
  for(int d=0;d<nowBlockByte; d++)
  {
    // printf("%02x ",ptxt.data()[d]);
    ptxt.data()[d] = temp2[d%nowBlockByte];
    // printf("[new] %02x ;",ptxt.data()[d]);
  }

  //cout << "-------Ptxt:  " << ptxt.data() << "\n\n";
  /*---Test END----*/
  #endif

  // 1. Symmetric encryption: symCtxt = Enc(symKey, ptxt) 
  Vec<GF2E>  keySchedule;
  keySchedule.SetLength(BlockWords*(ROUND+1));
  unsigned char RoundKeyCh[nowBlockByte*(ROUND+1)];
  Yu2x_16_KeyExpansion(RoundKeyCh, ROUND, nowBlockByte, symKey.data());

  for(int i=0;i<BlockWords*(ROUND+1);i++)
  {
    unsigned char tmp[2]={RoundKeyCh[2*i], RoundKeyCh[2*i+1]};
    keySchedule[i] = conv<GF2E>(GF2XFromBytes(tmp, 2));
  }


  for (long i=0; i<nBlocks; i++) {
    Vec<uint8_t> tmp(INIT_SIZE, nowBlockByte);
    Yu2x_16_encryption(&symCtxt[nowBlockByte*i], &ptxt[nowBlockByte*i], keySchedule, ROUND);
  }
  // cout << "-----symkey random: " << symKey << "\n\n";
  // cout << "  ptxt random= "; printState(ptxt); cout << endl;
  // cout << "  encrypted symCtxt "; printState(symCtxt); cout << endl;
  
  vector<Ctxt> encryptedSymKey;
  // 2. Decrypt the symKey under the HE key

  Trans_Yu2x_16_16 trans;
  cout << "computing symmetric round key tables..." << std::flush;
  tm = -GetTime();
  bool key2dec = true;
  trans.encryptSymKey(encryptedSymKey, RoundKeyCh, publicKey, ea, key2dec);
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
  trans.decodeTo32Ctxt(tmpBytes, poly, ea);
  
  auto glasped = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    cout << "Homomorphic symmtric decryption  Done [glasped.count()] in "<<glasped.count()<<" ms"<<endl;
    cout << "Homomorphic symmtric decryption  Done in "<<tm<<" seconds\n"; 
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
    auto glasped = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    cout << "Homomorphic symmtric decryption  Done [glasped.count()] in "<<glasped.count()<<" ms"<<endl;
    cout << "Homomorphic symmtric decryption  Done in "<<tm<<" seconds\n"; 
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
      cout << "-------After homomorphic decrypt and DecodeTo32Ctxt's length:   " << tmpBytes.length() <<"\n";
      cout << "  input symCtxt = "; printState(symCtxt); cout << endl;
      cout << "output tmpBytes = "; printState(tmpBytes); cout << endl;
      cout << " should be ptxt = "; printState(ptxt); cout << endl;
  }
  myfile.close();
  cout << "\n-------Homomorphic symmtric decryption END! \n";
  resetAllTimers();



  // 3. Encrypt and check that you have the same thing as before
  #ifdef homEnc
  vector< Ctxt > doublyEncrypted;
  encryptSymKey(encryptedSymKey, symKey, publicKey, ea, /*key2dec=*/false);
  
  cout << "Homomorphic symmtric encryption Begin"<< endl; 
  tm = -GetTime();
  homSymEnc(doublyEncrypted, encryptedSymKey, ptxt, ea);
  tm += GetTime();
  cout << "Homomorphic symmtric encryption ";

  Vec<ZZX> polyEnc(INIT_SIZE, doublyEncrypted.size());
  for (long i=0; i<polyEnc.length(); i++)
    secretKey.Decrypt(polyEnc[i], doublyEncrypted[i]);
  decodeTo32Ctxt(tmpBytes, polyEnc, ea);

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
#endif
