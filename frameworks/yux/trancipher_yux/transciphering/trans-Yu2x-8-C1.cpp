#include <cstring>
#include <stdint.h>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include "../Yux/Yu2x-8.h"
#include "trans-Yu2x-8-C1.h"

using namespace helib;
using namespace std;
using namespace NTL;

// Encode plaintext/ciphertext bytes as native HE plaintext
void Transcipher1::encodeTo1Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  long nAllBlocks = divc(data.length(),16); // ceil( data.length()/16 )
  long blocksPerCtxt = ea.size() / 16;  // = nSlots/16
  long nCtxt = divc(nAllBlocks, blocksPerCtxt);

  // We encode blocksPerCtxt = n/16 blocks in the slots of one ctxt.
  encData.SetLength(nCtxt);

  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<GF2X> slots(ea.size(), GF2X::zero());
    for (long j=0; j<blocksPerCtxt; j++) { // j is the block number in this ctxt
      long blockShift = (i*blocksPerCtxt +j)*16;  // point to block
      for (long k=0; k<16; k++) {         // k is the byte number in this block
        long byteIdx= blockShift+ k;      // column orded within block
        if (byteIdx < data.length()) {
          long slotIdx = j + k*blocksPerCtxt;
          GF2XFromBytes(slots[slotIdx], &data[byteIdx], 1);// copy byte as poly
        }
      }
    }
    ea.encode(encData[i], slots);
  }
}

// Decode native HE plaintext as Yux plaintext/ciphertext bytes
void Transcipher1::decodeTo1Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // Check the size of the data array
  long nBytes = encData.length() * ea.size(); // total number of input bytes
  if (data.length()<=0 || data.length()>nBytes)
    data.SetLength(nBytes);
  long nAllBlocks = divc(data.length(),16);       // ceil( data.length()/16 )
  long blocksPerCtxt = ea.size() / 16;        // = nSlots/16
  long nCtxt = divc(nAllBlocks, blocksPerCtxt);   // <= encData.length()

  // We encode blocksPerCtxt = n/16 blocks in the slots of one ctxt.

  vector<GF2X> slots;
  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    ea.decode(slots, encData[i]);
    for (long j=0; j<blocksPerCtxt; j++) { // j is the block number in this ctxt
      long blockShift = (i*blocksPerCtxt +j)*16;  // point to block
      for (long k=0; k<16; k++) {         // k is the byte number in this block
        long byteIdx= blockShift +k;      // column orded within block
        if (byteIdx < data.length()) {
          long slotIdx = j + k*blocksPerCtxt;
          BytesFromGF2X(&data[byteIdx], slots[slotIdx], 1);// copy poly as byte
        }
      }
    }
  }
}


void Transcipher1::buildRoundConstant(Ctxt& encA,
			const EncryptedArrayDerived<PA_GF2>& ea)
{
  // char --> GF2X --> ZZX -->Ctxt 
  GF2X polyConstant;
  GF2XFromBytes(polyConstant, &roundConstant, 1);
  // cout << "----Round Constant: " << polyConstant << "  \n";
  vector<GF2X> slots(ea.size(), polyConstant);
  ZZX ZZXConstant;
  ea.encode(ZZXConstant, slots);
  encA.DummyEncrypt(ZZXConstant);
}

// run the Yux key-expansion and then encrypt the expanded key.
void Transcipher1::encryptSymKey(vector<Ctxt>& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
    const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec)
{
    // Round Key length
    long round_key_length = BlockByte;
    // Compute the key expansion 
    long length_s = round_key_length * (ROUND+1);
    uint8_t roundKeySchedule[length_s];

    long blocksPerCtxt = ea.size() / BlockByte;

    // symKey.length() =16
    uint8_t encRoundKeySchedule[length_s];
    long nRoundKeys = KeyExpansion(encRoundKeySchedule, ROUND, BlockByte, symKey.data());
   if(key2dec)
    {
      // Change to Decrypt roundkey
      decRoundKey(roundKeySchedule, encRoundKeySchedule, ROUND, BlockByte);
    }
    else
    {
      for(long i=0; i<length_s; i++)
        roundKeySchedule[i] = encRoundKeySchedule[i];
    }
      // printf("roundKeySchedule---:\n");
      // for(int d=0;d<length_s; d++)
      // {
      //   cout<<d;
      //   printf(". %02x ;",roundKeySchedule[d]);
      // }
      // printf("\nroundKeySchedule---END!\n");
    
    // -------roundKeySchedule ---->  expanded ---> encode
 
    // Expand the key-schedule, copying each round key blocksPerCtxt times
    Vec<uint8_t> expanded(INIT_SIZE, nRoundKeys*blocksPerCtxt*BlockByte);
    for (long i=0; i<nRoundKeys; i++) {
      uint8_t* roundKey = &roundKeySchedule[16*i];
      for (long j=0; j<blocksPerCtxt; j++)
        memcpy(&expanded[16*(i*blocksPerCtxt +j)], roundKey, 16);
    }
    Vec<ZZX> encoded;
    encodeTo1Ctxt(encoded, expanded, ea);      // encode as HE plaintext

    {   
        Ctxt tmpCtxt(hePK);
        eKey.resize(encoded.length(), tmpCtxt);
    } // allocate space
    for (long i=0; i<(long)eKey.size(); i++) // encrypt the encoded key
        hePK.Encrypt(eKey[i], encoded[i]);
}

// Compute the constants for Sbox
void Transcipher1::buildLinEnc(vector<PolyType>& encLinTran,
			const EncryptedArrayDerived<PA_GF2>& ea)
{
  // encLinTran[0]: The constants only have nonzero entires in their slots corresponding
  // to bytes 3,7,11,15 of each blocks
  // encLinTran[1]: The constants only have zero entires in their slots corresponding
  // to bytes 0,4,8,12 of each blocks, others is 1;

  Vec<uint8_t> bytes(INIT_SIZE, ea.size());
  long blocksPerCtxt = ea.size() / 16;
  Vec<ZZX> tmp;

  memset(bytes.data(), 0, bytes.length());
  /*
    void Transcipher1::*memset(void Transcipher1::*s, int ch, size_t n);
    函数解释：将s中前n个字节 （typedef unsigned int size_t）用 ch 替换并返回 s
    讲bytes设置为0
  */
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 1;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[0] = tmp[0];

  memset(bytes.data(), 1, bytes.length());
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 0;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[1] = tmp[0];
}

// Compute the constants for Sbox
void Transcipher1::buildLinEnc2(vector<PolyType>& encLinTran,
			const EncryptedArrayDerived<PA_GF2>& ea)
{
  // encLinTran[0]: The constants only have nonzero entires in their slots corresponding
  // to bytes 3,7,11,15 of each blocks // 0001000100010001
  // encLinTran[1]: The constants only have nonzero entires in their slots corresponding
  // to bytes 2,6,10,14 of each blocks // 0010001000100010
  // encLinTran[1]: The constants only have zero entires in their slots corresponding
  // to bytes 01,45,89,1213 of each blocks, others is 1; //1100110011001100

  Vec<uint8_t> bytes(INIT_SIZE, ea.size());
  long blocksPerCtxt = ea.size() / 16;
  Vec<ZZX> tmp;

  memset(bytes.data(), 0, bytes.length());
  /*
    void Transcipher1::*memset(void Transcipher1::*s, int ch, size_t n);
    函数解释：将s中前n个字节 （typedef unsigned int size_t）用 ch 替换并返回 s
    讲bytes设置为0
  */
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 1;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[0] = tmp[0];

  memset(bytes.data(), 0, bytes.length());
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[2] = bptr[6] = bptr[10] = bptr[14] = 1;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[1] = tmp[0];

  memset(bytes.data(), 1, bytes.length());
  for (long j=0; j<blocksPerCtxt; j++) {
    uint8_t* bptr = &bytes[16*j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 0;
    bptr[2] = bptr[6] = bptr[10] = bptr[14] = 0;
  }
  encodeTo1Ctxt(tmp, bytes, ea);
  encLinTran[2] = tmp[0];
}

void Transcipher1::decSboxFunc(Ctxt& c, vector<PolyType> encLinTran, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
  long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 16;

  c.cleanUp();
  Ctxt c1(c), c2(c), c3(c), c4(c);
  ea.rotate1D(c1, 0, 1*rotAmount);
  ea.rotate1D(c2, 0, 2*rotAmount);
  ea.rotate1D(c3, 0, 3*rotAmount);
  ea.rotate1D(c4, 0,15*rotAmount);
  c1.cleanUp();  c2.cleanUp();  c3.cleanUp(); c4.cleanUp();
  
  c1.multiplyBy(c2);
  c += c1;
  c += c3;
  c += encA;

  const PolyType& p4 = encLinTran[0]; // 0001000100010001
  const PolyType& p123 = encLinTran[1]; //1110111011101110 

  c.multByConstant(p4);
  c4.multByConstant(p123);
  c += c4;

  c.cleanUp();
}

void Transcipher1::decSboxFunc2(Ctxt& c, vector<PolyType> encLinTran, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
  long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 16;

  const PolyType& p3 = encLinTran[0];   // 0001000100010001
  const PolyType& p2 = encLinTran[1];   // 0010001000100010
  const PolyType& p01 = encLinTran[2];   //1100110011001100

  c.cleanUp();
  Ctxt c1(c), c2(c), c15(c);
  ea.shift1D(c1, 0, 1*rotAmount);
  ea.shift1D(c2, 0, 2*rotAmount);
  ea.rotate1D(c15, 0,15*rotAmount);
  c1.cleanUp();  c2.cleanUp(); c15.cleanUp();
  
  c1.multiplyBy(c);
  c1 += c2;
  c1 += encA;

  Ctxt y3(c1);

  y3.multByConstant(p3);

  c15 += c1;
  c15.multByConstant(p2);
  Ctxt y2(c15); 
  ea.shift1D(c15, 0, 1*rotAmount); c15.cleanUp();
  y3 += c15;

  ea.rotate1D(c, 0, 14*rotAmount); c.cleanUp();
  c.multByConstant(p01);
  c += y2;
  c += y3;
  c.cleanUp();
}

void Transcipher1::Linear_function(Ctxt& c, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
    long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 16;

    c.cleanUp();
    // 循环左移   3  4  8 9 12 14
    // 即循环右移 13 12 8 7  4  2
    Ctxt c3(c), c4(c), c8(c), c9(c), c12(c), c14(c);
    ea.rotate1D(c3, 0, 13*rotAmount);
    ea.rotate1D(c4, 0, 12*rotAmount);
    ea.rotate1D(c8, 0, 8*rotAmount);
    ea.rotate1D(c9, 0, 7*rotAmount);
    ea.rotate1D(c12, 0, 4*rotAmount);
    ea.rotate1D(c14, 0, 2*rotAmount);
    
    c3.cleanUp();  c4.cleanUp(); c8.cleanUp();
    c9.cleanUp();  c12.cleanUp();  c14.cleanUp();

    c +=c3; 
    c +=c4; c +=c8; c +=c9; c +=c12;  c +=c14;
    c.cleanUp();
}

void Transcipher1::homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const EncryptedArrayDerived<PA_GF2>& ea) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;
  
  for (long j=0; j<(long)eData.size(); j++) eData[j] += symKey[0];  // initial key addition
  // apply the symmetric rounds
  // (long)symKey.size()
  cout << "homSymDec Begin\n";
  cout << "eData.size() = " << eData.size() << "\n";
  cout << "symKey.size() = " << symKey.size() << "\n";

  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA, ea);

  vector<PolyType> encLinTran;
  encLinTran.resize(3, DoubleCRT(ea.getContext(), ea.getContext().fullPrimes())); 
  buildLinEnc2(encLinTran, ea);
  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<ROUND; i++){
    for (long j=0; j<(long)eData.size(); j++){
      // S Layer 
      for (long step=0; step<2; step++)
        decSboxFunc2(eData[j], encLinTran, encA, ea);
      // Linear Layer
      Linear_function(eData[j], ea);
      // Add round key
      eData[j] += symKey[i];
    }
  }

  // The last round is given below.
  // Linear layer is not here in the last round
    for (long j=0; j<(long)eData.size(); j++){
      
      // S Layer 
      for (long step=0; step<2; step++)
        decSboxFunc2(eData[j], encLinTran, encA, ea);
      // Add round key
      eData[j] += symKey[ROUND];
    }

  cout << "enc Finish! \n";
  // return to natural PrimeSet to save memery
  for (int i = 0; i < eData.size(); i++)
    eData[i].bringToSet(eData[i].naturalPrimeSet());
}



// Perform sym encryption on plaintext bytes (ECB mode). The input are
// raw plaintext bytes, and the sym key encrypted under HE. The output
// is a doubly-encrypted ciphertext, out=Enc_HE(Enc_Sym(X)). The symKey
// array contains an encryption of the expanded sym key, the number of
// sym rounds is YuxKey.size() -1.
// NOTE: This is a rather useless method, other than for benchmarking
void Transcipher1::homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo1Ctxt(encodedBytes, inBytes, ea); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }
  homSymDec(eData, symKey, ea); // do the real work
}
