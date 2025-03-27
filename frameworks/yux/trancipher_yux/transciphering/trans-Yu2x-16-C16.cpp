#include <cstring>
#include <stdint.h>
#include <chrono>
#include <thread>
#include <pthread.h>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>
#include "../Yux/Yu2x-16.h"
#include "trans-Yu2x-16-C16.h"

using namespace helib;
using namespace std;
using namespace NTL;


// Encode  plaintext/ciphertext bytes as native HE plaintext
// packing
void Trans_Yu2x_16_16::encodeToKeys(Vec<ZZX>& encData, const Vec<GF2E>& data,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // 一个分组有个 Round+1 * BlockWords 个秘钥字节
  long nBytes = data.length();
  long nCtxt = nBytes;
  encData.SetLength(nCtxt);

  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<GF2X> slots(ea.size(), GF2X::zero());
    for (long j=0; j<ea.size(); j++) { // j is the block number in this ctxt
      long byteIdx = i; 
      if (byteIdx < data.length()) {
          slots[j]= conv<GF2X>(data[byteIdx]);// copy byte as poly
        }
    }
    ea.encode(encData[i], slots);
  }
}

// Encode  plaintext/ciphertext bytes as native HE plaintext
// packing
void Trans_Yu2x_16_16::encodeTo32Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // 一个分组有16个字节
  long nBytes = NkGF16;
  long nAllBlocks = divc(data.length(), nBytes); // ceil( data.length()/16 ) =(a + b - 1)/b
  // long blocksPerCtxt = ea.size() / 16;  // = nSlots/16
  long nCtxt = nBytes;

  encData.SetLength(nCtxt);

  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<GF2X> slots(ea.size(), GF2X::zero());
    for (long j=0; j<nAllBlocks; j++) { // j is the block number in this ctxt
      long byteIdx = (j*nBytes+ i)*2; 
      if (byteIdx < data.length()) {
          unsigned char tmp[2]={data[byteIdx], data[byteIdx+1]};
          GF2XFromBytes(slots[j], tmp, 2);// copy byte as poly
        }
    }
    ea.encode(encData[i], slots);
  }
}


// Decode native HE plaintext as AES plaintext/ciphertext bytes
void Trans_Yu2x_16_16::decodeTo32Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // Check the size of the data array
  long nAllBytes = encData.length() * ea.size()*2; // total number of input bytes
  if (data.length()<=0 || data.length()>nAllBytes)
    data.SetLength(nAllBytes);

  // 一个分组有64个字节
  long nBytes = NkGF16;
  long nAllBlocks = divc(data.length(), nBytes); // ceil( data.length()/16 ) =(a + b - 1)/b
  // long blocksPerCtxt = ea.size() / 16;  // = nSlots/16
  long nCtxt = nBytes;

  vector<GF2X> slots;
  for (long i=0; i<nCtxt; i++) {
    ea.decode(slots, encData[i]);
    for(long j=0; j<nAllBlocks; j++) {
      long slotIdx = j;
      long byteIdx = (j*nBytes+ i)*2;
      if (byteIdx < data.length()) {
        // BytesFromGF2X(&data[byteIdx], slots[slotIdx], 1);
        unsigned char p[2];
        BytesFromGF2X(p, conv<GF2X>(slots[slotIdx]), 2);
        data[byteIdx] = p[0];
        data[byteIdx+1] = p[1];
      }
    }
  }
}

void Trans_Yu2x_16_16::buildRoundConstant(Ctxt& encA,
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

// run the key-expansion and then encrypt the expanded key.
void Trans_Yu2x_16_16::encryptSymKey(vector<Ctxt>& eKey, unsigned char encRoundKeySchedule[], const PubKey& hePK,
    const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec)
{
    // Round Key length
    // Compute the key expansion 
    long length_s = BlockWords *2* (ROUND+1);
    
    // unsigned char encRoundKeySchedule[length_s];
    
    // KeyExpansion(encRoundKeySchedule,ROUND,BlockWords*2, symKey.data()); // symKey.length() =16

    Vec<GF2E>  keySchedule;
    keySchedule.SetLength(NkGF16*(ROUND+1));
    for(int i=0;i<NkGF16*(ROUND+1);i++)
    {
      unsigned char tmp[2]={encRoundKeySchedule[2*i], encRoundKeySchedule[2*i+1]};
      keySchedule[i] = conv<GF2E>(GF2XFromBytes(tmp, 2));
    }

    // Decrypt roundkey
    Vec<GF2E>  roundKeySchedule;
    roundKeySchedule.SetLength(NkGF16*(ROUND+1));

    if(key2dec)
    { 
      Vec<GF2E> RoundKey_invert;
      RoundKey_invert.SetLength(length_s);
      // Change to Decrypt roundkey
      Yu2x_16_decRoundKey(RoundKey_invert, keySchedule, ROUND, NkGF16);
      // for(long i=0; i<length_s; i++)
      //   BytesFromGF2X(&roundKeySchedule[i], conv<GF2X>(RoundKey_invert[i]), 1);
      for(int i=0; i<NkGF16*(ROUND+1); i++)
      {
        roundKeySchedule[i] = RoundKey_invert[i];
      }   
    }
    else
    {
      for(long i=0; i<NkGF16*(ROUND+1); i++)
        roundKeySchedule[i]= keySchedule[i];
    }

    // -------roundKeySchedule ---->  expanded ---> encode
    // Expand the key-schedule, copying each round key blocksPerCtxt times
    // Vec<uint8_t> expanded(INIT_SIZE, length_s);
    // memcpy(&expanded[0], &roundKeySchedule[0], length_s);
    Vec<ZZX> encoded;
    encodeToKeys(encoded, roundKeySchedule, ea);      // encode as HE plaintext

    {   
        Ctxt tmpCtxt(hePK);
        eKey.resize(encoded.length(), tmpCtxt);
    } // allocate space
    for (long i=0; i<(long)eKey.size(); i++) // encrypt the encoded key
        hePK.Encrypt(eKey[i], encoded[i]);
}

void Trans_Yu2x_16_16::decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA)
{
    Ctxt c0(eData[begin]);
    Ctxt c1(eData[begin+1]);
    Ctxt c2(eData[begin+2]);;
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

void Trans_Yu2x_16_16::homYuxDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, Ctxt& encA) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;
  
  // apply the symmetric rounds
  cout << "homSymDec Begin\n";
  // cout << "eData.size() = " << eData.size() << "\n";
  // cout << "symKey.size() = " << symKey.size() << "\n";
  
  for (long j=0; j<(long)eData.size(); j++) eData[j] += symKey[j];  // initial key addition
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<ROUND; i++) { 
    // S Layer -- 4 sbox
    cout<< "round "<< i << " ";
    for(long j = 0; j<4; j++){
      for(int step = 0; step<4; step++){
        decSboxFunc(eData, 4*j, encA);
      }
    }

    // Linear layer
    vector<Ctxt> in;
    in.resize(eData.size(), Ctxt(ZeroCtxtLike,eData[0]));
    for(long j=0; j<eData.size(); j++){
      in[j] = eData[j];
    }
    for(long j=0; j<eData.size(); j++){
      eData[j] += in[(j+3)%NkGF16];
      eData[j] += in[(j+4)%NkGF16];
      eData[j] += in[(j+8)%NkGF16];
      eData[j] += in[(j+9)%NkGF16];
      eData[j] += in[(j+12)%NkGF16];
      eData[j] += in[(j+14)%NkGF16];

      // add Round Key
      long key_id = NkGF16*i+j;
      eData[j] += symKey[key_id];
      
    } 
  }
  // The last round is given below.
  // Linear layer is not here in the last round
  {
    // S Layer - 4 sbox
    for(long j = 0; j<4; j++){
      for(int step = 0; step<4; step++){
        decSboxFunc(eData, 4*j, encA);
      }
    }
    // add Round Key
    for(long j=0; j<eData.size(); j++){
      long key_id = NkGF16*ROUND+j;
      eData[j] += symKey[key_id];
    }
  }
  cout << "homSymDec Finish! \n";
  // return to natural PrimeSet to save memery
  for (int i = 0; i < eData.size(); i++)
    eData[i].bringToSet(eData[i].naturalPrimeSet());
}

// Perform sym encryption on plaintext bytes (ECB mode). The input are
// raw plaintext bytes, and the sym key encrypted under HE. The output
// is a doubly-encrypted ciphertext, out=Enc_HE(Enc_Sym(X)). The symKey
// array contains an encryption of the expanded sym key, the number of
// sym rounds is aesKey.size() -1.
// NOTE: This is a rather useless method, other than for benchmarking
void Trans_Yu2x_16_16::homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo32Ctxt(encodedBytes, inBytes, ea); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }

  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA, ea);
  homYuxDec(eData, symKey, encA); // do the real work
}

void Trans_Yu2x_16_16::encSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA)
{
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

void Trans_Yu2x_16_16::encSboxFuncV2(vector<Ctxt>& eData, long begin, Ctxt& encA)
{
  Ctxt c0(eData[begin]);
  Ctxt c1(eData[begin+1]);
  Ctxt c2(eData[begin+2]);;
  Ctxt c3(eData[begin+3]);
  
  Ctxt tempadd(c2);
  tempadd += c3;
  tempadd += encA;

  Ctxt temp0(c0);               // tmp0   = eData[0] = X
  temp0.frobeniusAutomorph(1);  // tmp0   = X^2   after Z -> Z^2
  temp0.multiplyBy(c1);
  eData[begin].multiplyBy(tempadd);
  eData[begin] += c1;
  eData[begin] += c2;
  eData[begin] += encA;
  eData[begin] += temp0;
  eData[begin+1].multiplyBy(c0);
  eData[begin+1] += tempadd;
  eData[begin+2] = c0;
  eData[begin+3] = c1;

}


void Trans_Yu2x_16_16::homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey, Ctxt& encA) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;
  
    // apply the symmetric rounds
  cout << "homSymEnc Begin\n";
  for (long j=0; j<(long)eData.size(); j++) eData[j] += symKey[j];  // initial key addition
  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<ROUND; i++){ 
    // // S Layer -- 4 sbox
    // for(long j = 0; j<4; j++){
    //   for(int step = 0; step<4; step++){
    //     encSboxFunc(eData, 4*j, encA);
    //   }
    // }

    // S Layer -- 4Sbox 2*2 step
    for(long j = 0; j<4; j++){
      for(int step = 0; step<2; step++){
        encSboxFuncV2(eData, 4*j, encA);
      }
    }

    // Linear layer
    vector<Ctxt> in;
    Ctxt in_all(ZeroCtxtLike,eData[0]);
    in.resize(eData.size(), Ctxt(ZeroCtxtLike,eData[0]));
    for(long j=0; j<eData.size(); j++){
      in[j] = eData[j];
      in_all += eData[j];
    }

    for(long j=0; j<eData.size(); j++){
      eData[j] += in[(j+4)%NkGF16];
      eData[j] += in[(j+9)%NkGF16];
      eData[j] += in[(j+10)%NkGF16];
      eData[j] += in[(j+11)%NkGF16];
      eData[j] += in_all;

      // add Round Key
      long key_id = NkGF16*i+j;
      eData[j] += symKey[key_id];
    } 
  }
  // The last round is given below.
  // Linear layer is not here in the last round
  {
    // // S Layer - 4 sbox
    // for(long j = 0; j<4; j++){
    //   for(int step = 0; step<4; step++){
    //     encSboxFunc(eData, 4*j, encA);
    //   }
    // }
    // S Layer -- 4Sbox 2*2 step
    for(long j = 0; j<4; j++){
      for(int step = 0; step<2; step++){
        encSboxFuncV2(eData, 4*j, encA);
      }
    }
    // add Round Key
    for(long j=0; j<eData.size(); j++){
      long key_id = NkGF16*ROUND+j;
      eData[j] += symKey[key_id];
    }
  }
  cout << "homSymEnc Finish! \n";
}

void Trans_Yu2x_16_16::homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo32Ctxt(encodedBytes, inBytes, ea); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }

  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA, ea);
  homSymEnc(eData, symKey, encA); // do the real work
}
