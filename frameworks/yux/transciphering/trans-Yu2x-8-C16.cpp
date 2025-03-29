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
#include "../Yux/Yu2x-8.h"
#include "trans-Yu2x-8-C16.h"

using namespace helib;
using namespace std;
using namespace NTL;


// Encode  plaintext/ciphertext bytes as native HE plaintext
// packing
void Transcipher16::encodeToKeys(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // 一个分组有个 Round+1 * BlockByte 个秘钥字节
  long nBytes = data.length();
  long nCtxt = nBytes;
  encData.SetLength(nCtxt);

  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<GF2X> slots(ea.size(), GF2X::zero());
    for (long j=0; j<ea.size(); j++) { // j is the block number in this ctxt
      long byteIdx = i; 
      if (byteIdx < data.length()) {
          GF2XFromBytes(slots[j], &data[byteIdx], 1);// copy byte as poly
        }
    }
    ea.encode(encData[i], slots);
  }
}

// Encode  plaintext/ciphertext bytes as native HE plaintext
// packing
void Transcipher16::encodeTo16Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // 一个分组有8个字节
  long nBytes = BlockByte;
  long nAllBlocks = divc(data.length(), nBytes); // ceil( data.length()/16 ) =(a + b - 1)/b
  // long blocksPerCtxt = ea.size() / 16;  // = nSlots/16
  long nCtxt = nBytes;

  encData.SetLength(nCtxt);

  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<GF2X> slots(ea.size(), GF2X::zero());
    for (long j=0; j<nAllBlocks; j++) { // j is the block number in this ctxt
      long byteIdx = j*nBytes+ i; 
      if (byteIdx < data.length()) {
          GF2XFromBytes(slots[j], &data[byteIdx], 1);// copy byte as poly
        }
    }
    ea.encode(encData[i], slots);
  }
}


// Decode native HE plaintext as Yux plaintext/ciphertext bytes
void Transcipher16::decodeTo16Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  // Check the size of the data array
  long nAllBytes = encData.length() * ea.size(); // total number of input bytes
  if (data.length()<=0 || data.length()>nAllBytes)
    data.SetLength(nAllBytes);

  // 一个分组有16个字节
  long nBytes = BlockByte;
  long nAllBlocks = divc(data.length(), nBytes); // ceil( data.length()/16 ) =(a + b - 1)/b
  // long blocksPerCtxt = ea.size() / 16;  // = nSlots/16
  long nCtxt = nBytes;

  vector<GF2X> slots;
  for (long i=0; i<nCtxt; i++) {
    ea.decode(slots, encData[i]);
    for(long j=0; j<nAllBlocks; j++) {
      long slotIdx = j;
      long byteIdx = i + nBytes*j;
      if (byteIdx < data.length()) {
        BytesFromGF2X(&data[byteIdx], slots[slotIdx], 1);
      }
    }
  }
}

void Transcipher16::buildRoundConstant(Ctxt& encA,
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
void Transcipher16::encryptSymKey(vector<Ctxt>& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
    const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec)
{
    // Round Key length
    long round_key_length = BlockByte;
    // Compute the key expansion 
    long length_s = round_key_length * (ROUND+1);
    unsigned char encRoundKeySchedule[length_s];
    KeyExpansion(encRoundKeySchedule,ROUND,BlockByte, symKey.data()); // symKey.length() =16
    // Decrypt roundkey
    uint8_t roundKeySchedule[length_s];
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

    // -------roundKeySchedule ---->  expanded ---> encode
    // Expand the key-schedule, copying each round key blocksPerCtxt times
    Vec<uint8_t> expanded(INIT_SIZE, length_s);
    memcpy(&expanded[0], &roundKeySchedule[0], length_s);
    Vec<ZZX> encoded;
    encodeToKeys(encoded, expanded, ea);      // encode as HE plaintext

    {   
      Ctxt tmpCtxt(hePK);
      eKey.resize(encoded.length(), tmpCtxt);
    } // allocate space
    for (long i=0; i<(long)eKey.size(); i++) // encrypt the encoded key
      hePK.Encrypt(eKey[i], encoded[i]);
}

void Transcipher16::decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA)
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

struct thread_data{
   vector<Ctxt> *eData;
   long j;
   Ctxt *encA;
};

void *Transcipher16::decSbox_Pre(void *threadarg)
{
  struct thread_data *my_data;
  my_data = (struct thread_data *) threadarg;
  for(int step = 0; step<4; step++){
    decSboxFunc(*my_data->eData, 4*my_data->j, *my_data->encA);
  }
  pthread_exit(NULL);
}

void Transcipher16::decSbox(vector<Ctxt>& eData, long j, Ctxt& encA)
{
  for(int step = 0; step<4; step++){
    decSboxFunc(eData, 4*j, encA);
  }
}

void Transcipher16::homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, Ctxt& encA) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;
  
  // apply the symmetric rounds
  cout << "homSymDec Begin\n";
  
  for (long j=0; j<(long)eData.size(); j++) eData[j] += symKey[j];  // initial key addition
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<ROUND; i++){ 
    // S Layer -- 4 sbox

#ifdef multiThreads
    /*
    // 定义线程的 id 变量，多个变量使用数组
    {  
      int NUM_THREADS=4;
      pthread_t threads[NUM_THREADS];
      struct thread_data td[NUM_THREADS];

      int rc;
      pthread_attr_t attr;
      void *status;

      // 初始化并设置线程为可连接的（joinable）
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
      cout <<"main() : Round  " << i << endl;
      for(int j = 0; j < NUM_THREADS; ++j)
      {
        cout <<"homSymDec() Round " << i << ": creating thread, " << j << endl;
        td[j].eData = &eData;
        td[j].j = j;
        td[j].encA = &encA;
        //参数依次是：创建的线程id，线程参数，调用的函数，传入的函数参数
        int ret = pthread_create(&threads[j], NULL, decSbox_Pre, (void *)&td[j]);
        if (ret != 0)
        {
          cout << "pthread_create error: error_code=" << ret << endl;
        }
      }
      //等各个线程退出后，进程才继续
      // 删除属性，并等待其他线程
      pthread_attr_destroy(&attr);
      for(int j=0; j < NUM_THREADS; j++ ){
        rc = pthread_join(threads[j], NULL);
        if (rc){
          cout << "Error:unable to join," << rc << endl;
          exit(-1);
        }
        cout << "Main: completed thread id :" << j ;
        cout << "  exiting with status :" << status << endl;
      }
      cout <<"main() : Round  " << i << ", 4 subthreads over!"<< endl;
    }
    */
    int NUM_THREADS = 4;
    thread threads[NUM_THREADS];
    for (int j=0; j<NUM_THREADS; j++)
      threads[j] = thread(decSbox, ref(eData), j, ref(encA));

    for (int j=0; j<NUM_THREADS; j++)
      threads[j].join();
    
#else // else multiThreads
    for(long j = 0; j<4; j++){
       decSbox(eData, j, encA); 
    }
#endif // end multiThreads

    // Linear layer
    vector<Ctxt> in;
    in.resize(eData.size(), Ctxt(ZeroCtxtLike,eData[0]));
    for(long j=0; j<eData.size(); j++){
      in[j] = eData[j];
    }
    for(long j=0; j<eData.size(); j++){
      eData[j] += in[(j+3)%16];
      eData[j] += in[(j+4)%16];
      eData[j] += in[(j+8)%16];
      eData[j] += in[(j+9)%16];
      eData[j] += in[(j+12)%16];
      eData[j] += in[(j+14)%16];

      // add Round Key
      long key_id = BlockByte*i+j;
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
      long key_id = BlockByte*ROUND+j;
      eData[j] += symKey[key_id];
    }
  }
  cout << "homSymDec Finish! \n";
  // return to natural PrimeSet to save memery
  for (int i = 0; i < eData.size(); i++)
    eData[i].bringToSet(eData[i].naturalPrimeSet());
}

void Transcipher16::homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo16Ctxt(encodedBytes, inBytes, ea); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }

  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA, ea);
  homSymDec(eData, symKey, encA); // do the real work
}

void Transcipher16::encSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA)
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

void Transcipher16::encSboxFuncFrobenius(vector<Ctxt>& eData, long begin, Ctxt& encA)
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


void Transcipher16::homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey, Ctxt& encA) 
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
        encSboxFuncFrobenius(eData, 4*j, encA);
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
      eData[j] += in[(j+4)%16];
      eData[j] += in[(j+9)%16];
      eData[j] += in[(j+10)%16];
      eData[j] += in[(j+11)%16];
      eData[j] += in_all;

      // add Round Key
      long key_id = BlockByte*i+j;
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
        encSboxFuncFrobenius(eData, 4*j, encA);
      }
    }
    // add Round Key
    for(long j=0; j<eData.size(); j++){
      long key_id = BlockByte*ROUND+j;
      eData[j] += symKey[key_id];
    }
  }
  cout << "homSymEnc Finish! \n";
}

void Transcipher16::homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo16Ctxt(encodedBytes, inBytes, ea); // encode as HE plaintext 
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
