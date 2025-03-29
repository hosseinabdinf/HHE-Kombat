#include <cstring>
#include <stdint.h>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include "../Yux/Yu2x-8.h"
#include "trans-Yu2x-8-C4.h"

using namespace helib;
using namespace std;
using namespace NTL;


// Encode plaintext/ciphertext bytes as native HE plaintext
void Transcipher4::encodeTo4Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  long nAllBlocks = divc(data.length(),16); // ceil( data.length()/16 )
  long blocksPerCtxt = ea.size() / 4;  // = nSlots/4
  long nCtxt = divc(nAllBlocks, blocksPerCtxt);

  // We encode blocksPerCtxt = n/4 blocks in the slots of one ctxt.
  // All need 4 * nCtxt 
  encData.SetLength(nCtxt*4);
  for (long group=0; group<nCtxt ; group++) {
    for (long s=0; s<4; s++) { 
      long i = 4*group + s;       // i is the cipehrtext number
      long blockBegin = (group*blocksPerCtxt)*16;  // point to block
      // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
      vector<GF2X> slots(ea.size(), GF2X::zero());
      for (long j=0; j<blocksPerCtxt; j++) { // j is the block number in this ctxt
        for (long k=0; k<4; k++) {         // k is the byte number in this block
          long byteIdx= blockBegin + j*16+ k*4 +s; 
          if (byteIdx < data.length()) {
            long slotIdx = j + k*blocksPerCtxt;
            GF2XFromBytes(slots[slotIdx], &data[byteIdx], 1);// copy byte as poly
          }
        }
      }
      // cout << "\n!!-------------slots[" << i << "]:"<< slots <<"\n";
      ea.encode(encData[i], slots);
    }
  }
  
}

// Decode native HE plaintext as Yux plaintext/ciphertext bytes
void Transcipher4::decodeTo4Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // Check the size of the data array
  long nBytes = encData.length() * ea.size(); // total number of input bytes
  if (data.length()<=0 || data.length()>nBytes)
    data.SetLength(nBytes);
  long nAllBlocks = divc(data.length(),16);       // ceil( data.length()/16 )
  long blocksPerCtxt = ea.size() / 4;        // = nSlots/16
  long nCtxt = divc(nAllBlocks, blocksPerCtxt);   // <= encData.length()

  // We encode blocksPerCtxt = n/16 blocks in the slots of one ctxt.
  vector<GF2X> slots;
  for (long group=0; group<nCtxt ; group++) {
    for (long s=0; s<4; s++) { 
      long i = 4*group + s;       // i is the cipehrtext number
      ea.decode(slots, encData[i]);
      long blockBegin = (group*blocksPerCtxt)*16;  // point to block
      for (long j=0; j<blocksPerCtxt; j++) { // j is the block number in this ctxt
        for (long k=0; k<4; k++) {         // k is the byte number in this block
          long byteIdx= blockBegin + j*16+ k*4 +s;      // column orded within block
          if (byteIdx < data.length()) {
            long slotIdx = j + k*blocksPerCtxt;
            BytesFromGF2X(&data[byteIdx], slots[slotIdx], 1);
          }
        }
      }
    }
  }

}

void Transcipher4::buildRoundConstant(Ctxt& encA,
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
void Transcipher4::encryptSymKey(vector<Ctxt>& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
    const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec)
{
    // Round Key length 
    long round_key_length = BlockByte;
    // Compute the key expansion 
    long length_s = round_key_length * (ROUND+1);
    uint8_t roundKeySchedule[length_s];

    long blocksPerCtxt = ea.size() / 4;

    // symKey.length() =16
    uint8_t encRoundKeySchedule[length_s];
    long nRoundKeys = KeyExpansion(encRoundKeySchedule,ROUND,BlockByte, symKey.data());
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
    // for(int r=0;r<ROUND+1; r++)
    // {
    //   for (int d=0; d< 16; d++)
    //   {
    //     cout<<d;
    //     printf(". %02x ;",roundKeySchedule[r*16+d]);
    //   }
    //   cout<< "\n";
    //   for (int d=0; d< 16; d++)
    //   {
    //     cout<<d;
    //     printf(". %02x ;",encRoundKeySchedule[r*16+d]);
    //   }
    //   cout<< "\n";
    // }
    // printf("\nroundKeySchedule---END!\n");
    
    // -------roundKeySchedule ---->  expanded ---> encode
    // Expand the key-schedule, copying each round key blocksPerCtxt times
    Vec<uint8_t> expanded(INIT_SIZE, nRoundKeys*blocksPerCtxt*BlockByte);
    // cout << "!!-------------expanded.length:" << expanded.length() <<"\n";
    for (long i=0; i<nRoundKeys; i++) {
      uint8_t* roundKey = &roundKeySchedule[16*i];
      for (long j=0; j<blocksPerCtxt; j++)
        memcpy(&expanded[16*(i*blocksPerCtxt +j)], roundKey, 16);
    }
    Vec<ZZX> encoded;
    encodeTo4Ctxt(encoded, expanded, ea);      // encode as HE plaintext

    {   
        Ctxt tmpCtxt(hePK);
        eKey.resize(encoded.length(), tmpCtxt);
    } // allocate space
    for (long i=0; i<(long)eKey.size(); i++) // encrypt the encoded key
        hePK.Encrypt(eKey[i], encoded[i]);
}


void Transcipher4::decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
  Ctxt c0(eData[begin]);
  Ctxt c1(eData[begin+1]);
  Ctxt c2(eData[begin+2]);
  Ctxt c3(eData[begin+3]);
  Ctxt temp(c1);
  temp.multiplyBy(c2);
  temp += c0;
  temp += c3;
  temp += encA;
  eData[begin] = c1;
  eData[begin+1] = c2;
  eData[begin+2] = c3;
  eData[begin+3] = temp;
}

void Transcipher4::decLinearFunc(vector<Ctxt>& eData, long begin, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
    long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 4;
    
    vector<Ctxt> in;
    in.resize(4, Ctxt(ZeroCtxtLike,eData[begin]));
    for(long j=0; j<4; j++){
      in[j] = eData[j+begin];
    }
    // 0 4 8 12
    eData[begin] += in[3];
    Ctxt c4(in[0]); ea.rotate1D(c4, 0, 3*rotAmount); eData[begin] += c4;
    Ctxt c8(in[0]); ea.rotate1D(c8, 0, 2*rotAmount); eData[begin] += c8;
    Ctxt c9(in[1]); ea.rotate1D(c9, 0, 2*rotAmount); eData[begin] += c9;
    Ctxt c12(in[0]); ea.rotate1D(c12, 0, 1*rotAmount); eData[begin] += c12;
    Ctxt c14(in[2]); ea.rotate1D(c14, 0, 1*rotAmount); eData[begin] += c14;
    
    // 1 5 9 13
    eData[begin+1] += c4;
    Ctxt c5(in[1]);  ea.rotate1D(c5, 0, 3*rotAmount); eData[begin+1] += c5;
    eData[begin+1] += c9;
    Ctxt c10(in[2]); ea.rotate1D(c10, 0, 2*rotAmount); eData[begin+1] += c10;
    Ctxt c13(in[1]); ea.rotate1D(c13, 0, 1*rotAmount); eData[begin+1] += c13;
    Ctxt c15(in[3]); ea.rotate1D(c15, 0, 1*rotAmount); eData[begin+1] += c15;

    // 2 6 10 14
    eData[begin+2] += c5;
    Ctxt c6(in[2]); ea.rotate1D(c6, 0, 3*rotAmount);  eData[begin+2] += c6;
    eData[begin+2] += c10;
    Ctxt c11(in[3]); ea.rotate1D(c11, 0, 2*rotAmount); eData[begin+2] += c11;
    eData[begin+2] += c14;
    eData[begin+2] += in[0];

    //3 7 11 15
    eData[begin+3] += c6;
    Ctxt c7(in[3]); ea.rotate1D(c7, 0, 3*rotAmount); eData[begin+3] += c7;
    eData[begin+3] += c11;
    eData[begin+3] += c12;
    eData[begin+3] += c15;
    eData[begin+3] += in[1];

    eData[begin+0].cleanUp();
    eData[begin+1].cleanUp();
    eData[begin+2].cleanUp();
    eData[begin+3].cleanUp();
}

void Transcipher4::homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const EncryptedArrayDerived<PA_GF2>& ea) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;
  
  // for (long j=0; j<(long)eData.size(); j++) eData[j] += symKey[0];  // initial key addition
  // apply the symmetric rounds
  // (long)symKey.size()
  // cout << "eData.size() = " << eData.size() << "\n";
  // cout << "symKey.size() = " << symKey.size() << "\n";

  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA, ea);

  // initial key addition
  for(long j=0; j<(eData.size()/4); j++)
  {
    for(long k = 0; k<4; k++)
    {
      long key_id = k;
      eData[4*j+k] += symKey[key_id];
    } 
  }

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<ROUND; i++){
    for(long j=0; j<(eData.size()/4); j++)
    {
      // S Layer
      for (long step=0; step<4; step++)
        decSboxFunc(eData, j*4, encA, ea);
      
      // Linear layer
      decLinearFunc(eData, j*4, ea);
    }
    // Add Round Key
    for(long j=0; j<(eData.size()/4); j++)
    {
      for(long k = 0; k<4; k++)
      {
        long key_id = 4*i+k;
        eData[4*j+k] += symKey[key_id];
      } 
    }
  }

  // The last round is given below.
  // Linear layer is not here in the last round
  {
    for(long j=0; j<(eData.size()/4); j++)
    {
      // S Layer
      for (long step=0; step<4; step++)
        decSboxFunc(eData, j*4, encA, ea);
    }
    // Add Round Key
    for(long j=0; j<(eData.size()/4); j++)
    {
      for(long k = 0; k<4; k++)
      {
        long key_id = 4*ROUND+k;
        eData[4*j+k] += symKey[key_id];
      } 
    }
  }
  
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
void Transcipher4::homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo4Ctxt(encodedBytes, inBytes, ea); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }
  homSymDec(eData, symKey, ea); // do the real work
}

void Transcipher4::encSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
  Ctxt c0(eData[begin]);
  Ctxt c1(eData[begin+1]);
  Ctxt c2(eData[begin+2]);;
  Ctxt c3(eData[begin+3]);
  Ctxt temp(c0);
  temp.multiplyBy(c1);
  temp += c2;
  temp += c3;
  temp += encA;
  eData[begin] = temp;
  eData[begin+1] = c0;
  eData[begin+2] = c1;
  eData[begin+3] = c2;
}

void Transcipher4::encLinearFunc(vector<Ctxt>& eData, long begin, const EncryptedArrayDerived<PA_GF2>& ea){
  // The basic rotation amount along the 1st dimension
    long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 4;
    
    vector<Ctxt> in;
    in.resize(4, Ctxt(ZeroCtxtLike,eData[0]));
    for(long j=0; j<4; j++){
      in[j] = eData[j+begin];
    }
    Ctxt inAll(in[0]); inAll += in[1]; inAll += in[2]; inAll += in[3];
    Ctxt c4(in[0]);  ea.rotate1D(c4, 0, 3*rotAmount);  inAll += c4;
    Ctxt c5(in[1]);  ea.rotate1D(c5, 0, 3*rotAmount);  inAll += c5;
    Ctxt c6(in[2]);  ea.rotate1D(c6, 0, 3*rotAmount);  inAll += c6;
    Ctxt c7(in[3]);  ea.rotate1D(c7, 0, 3*rotAmount);  inAll += c7;
    Ctxt c8(in[0]);  ea.rotate1D(c8, 0, 2*rotAmount);  inAll += c8;
    Ctxt c9(in[1]);  ea.rotate1D(c9, 0, 2*rotAmount);  inAll += c9;
    Ctxt c10(in[2]); ea.rotate1D(c10, 0, 2*rotAmount); inAll += c10;
    Ctxt c11(in[3]); ea.rotate1D(c11, 0, 2*rotAmount); inAll += c11;
    Ctxt c12(in[0]); ea.rotate1D(c12, 0, 1*rotAmount); inAll += c12;
    Ctxt c13(in[1]); ea.rotate1D(c13, 0, 1*rotAmount); inAll += c13;
    Ctxt c14(in[2]); ea.rotate1D(c14, 0, 1*rotAmount); inAll += c14;
    Ctxt c15(in[3]); ea.rotate1D(c15, 0, 1*rotAmount); inAll += c15;
    

    // 0 4 8 12
    eData[begin] += c4; eData[begin] += c9; eData[begin] += c10; eData[begin] += c11;
    eData[begin] += inAll;
    
    // 1 5 9 13
    eData[begin+1] += c5; eData[begin+1] += c10; eData[begin+1] += c11; eData[begin+1] += c12;
    eData[begin+1] += inAll;

    // 2 6 10 14
    eData[begin+2] += c6; eData[begin+2] += c11; eData[begin+2] += c12; eData[begin+2] += c13;
    eData[begin+2] += inAll;

    //3 7 11 15
    eData[begin+3] += c7; eData[begin+3] += c12; eData[begin+3] += c13; eData[begin+3] += c14;
    eData[begin+3] += inAll;
}

void Transcipher4::homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const EncryptedArrayDerived<PA_GF2>& ea) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  // apply the symmetric rounds
  cout << "enc Begin\n";
  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA, ea);

  // initial key addition
  for(long j=0; j<(eData.size()/4); j++)
  {
    for(long k = 0; k<4; k++)
    {
      eData[4*j+k] += symKey[k];
    } 
  }

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<ROUND; i++){
    for(long j=0; j<(eData.size()/4); j++)
    {
      // S Layer
      for (long step=0; step<4; step++)
        encSboxFunc(eData, 4*j, encA, ea);
      
      // Linear layer
      encLinearFunc(eData, 4*j, ea);
      
    }
    

    // Add Round Key
    for(long j=0; j<(eData.size()/4); j++)
    {
      for(long k = 0; k<4; k++)
      {
        long key_id = 4*i+k;
        eData[4*j+k] += symKey[key_id];
      } 
    }
  }

  // The last round is given below.
  // Linear layer is not here in the last round
  {
    for(long j=0; j<(eData.size()/4); j++)
    {
      // S Layer
      for (long step=0; step<4; step++)
        encSboxFunc(eData, 4*j, encA, ea);
    }

    // Add Round Key
    for(long j=0; j<(eData.size()/4); j++)
    {
      for(long k = 0; k<4; k++)
      {
        long key_id = 4*ROUND+k;
        eData[4*j+k] += symKey[key_id];
      } 
    }
  }

  cout << "enc Finish! \n";
}

void Transcipher4::homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo4Ctxt(encodedBytes, inBytes, ea); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }
  homSymEnc(eData, symKey, ea); // do the real work
}
