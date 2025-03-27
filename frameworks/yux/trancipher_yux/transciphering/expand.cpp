#include <stdio.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <thread>

#include "trans-Yu2x-8-C16.h"
#include "params.h"

#define expandMultiThreads

// Encode plaintext/ciphertext bytes as native HE plaintext
// packing
// only for ea.size() > 240, encode to a single ciphertext
void Transcipher16::encodeToKeysForExpand(ZZX& encData, const Vec<uint8_t>& data, const int32_t len,
		const EncryptedArrayDerived<PA_GF2>& ea)
{
  vector<GF2X> slots(ea.size(), GF2X::zero());
  long repeats = 1;
  // faster expand for 1920 and 960. Other sizes can also be customized.
  if (ea.size() == 1920 || ea.size() == 960) { 
    repeats = ea.size()/len;
  }

  for (long j=0; j<len; j++) // j is the block number in this ctxt
    for (long l=0; l<repeats; l++) {
    GF2XFromBytes(slots[j*repeats + l], &data[j], 1);// copy byte as poly
  }
  ea.encode(encData, slots);
}

// run the Yux key-expansion and then encrypt the expanded key.
void Transcipher16::encryptSymKeyForExpand(Ctxt& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec)
{
    // Round Key length
    long round_key_length = BlockByte;
    // Compute the key expansion 
    long length_s = round_key_length * (ROUND+1);
    std::cout << "length_s = " << length_s << std::endl;
    unsigned char encRoundKeySchedule[length_s];
    KeyExpansion(encRoundKeySchedule, ROUND, BlockByte, symKey.data()); // symKey.length() =16
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
    ZZX encoded;
    encodeToKeysForExpand(encoded, expanded, length_s, ea);      // encode as HE plaintext

    // encrypt the encoded key
    hePK.Encrypt(eKey, encoded);

#ifndef NO_SAVE_ROUNDKEY
    ofstream myfile;
    stringstream filename;
    filename << "result/roundKey16.txt";
    myfile.open(filename.str(), ios::app);
    myfile << "This is roundKey:\n";
      myfile << eKey << std::endl;
    myfile.close();
#endif

}


// speical case for slots = 1920, where m = 53261. 1920 = 1024 + 512 + 256 +128
void fasterSingleRoundKeyFor1920(Ctxt& ekey, vector<Ctxt>& temp, const Ctxt& input,
  const EncryptedArrayDerived<PA_GF2>& ea, const int32_t slots, const int32_t logOfSlots)
{
  // rotate (0, 1, 2, 4, 8, ..., 2^7)
  temp[0] = input;
  for (size_t i = 1; i <= 4; i++)
  {
    temp[i] = temp[i-1];
    long shiftNums = std::pow(2, i+2);
    ea.rotate(temp[i], shiftNums);
    temp[i] += temp[i-1];
  }
  
  Ctxt rotated128 = temp[4];
  ea.rotate(rotated128, 128);
  
  temp[5] = temp[4]; temp[5] += rotated128;
  ea.rotate(temp[5], 256);

  temp[6] = temp[4]; temp[6] += rotated128; temp[6] += temp[5];
  ea.rotate(temp[6], 512);

  temp[7] = temp[4]; temp[7] += rotated128; temp[7] += temp[5]; temp[7] += temp[6];
  ea.rotate(temp[7], 1024);

  ekey = rotated128; ekey += temp[5]; ekey += temp[6]; ekey += temp[7];
}

// speical case for slots = 960, where m = 53261. 960 = 512 + 256 + 128 + 64
void fasterSingleRoundKeyFor960(Ctxt& ekey, vector<Ctxt>& temp, const Ctxt& input,
  const EncryptedArrayDerived<PA_GF2>& ea, const int32_t slots, const int32_t logOfSlots)
{
  // rotate (0, 1, 2, 4, 8, ..., 2^7)
  temp[0] = input;
  for (size_t i = 1; i <= 4; i++)
  {
    temp[i] = temp[i-1];
    long shiftNums = std::pow(2, i+2);
    ea.rotate(temp[i], shiftNums);
    temp[i] += temp[i-1];
  }
  
  Ctxt rotated128 = temp[4];
  ea.rotate(rotated128, 128);
  
  temp[5] = temp[4]; temp[5] += rotated128;
  ea.rotate(temp[5], 256);

  temp[6] = temp[4]; temp[6] += rotated128; temp[6] += temp[5];
  ea.rotate(temp[6], 512);

  temp[7] = temp[4]; temp[7] += rotated128; temp[7] += temp[5]; temp[7] += temp[6];
  ea.rotate(temp[7], 1024);

  ekey = rotated128; ekey += temp[5]; ekey += temp[6]; ekey += temp[7];
}

// 
void Transcipher16::handleSingleRoundKey(Ctxt& ekey, const Ctxt& input, const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea)
{
  // we sppuose that a < 65536, which is sufficiently large
  int32_t slots = ea.size();
  int32_t logOfSlots = std::floor(std::log2(slots));


  vector<Ctxt> temp;
  {
    Ctxt tmpCtxt(hePK);
    temp.resize(logOfSlots+1, tmpCtxt);
  }
  
  if (slots == 1920) {
    fasterSingleRoundKeyFor1920(ekey, temp, input, ea, slots, logOfSlots);
    return;
  } else if (slots == 960) {
    fasterSingleRoundKeyFor960(ekey, temp, input, ea, slots, logOfSlots);
    return;
  }
  
  // rotate (0, 1, 2, 4, 8, ..., logOfaSubTwo)
  temp[0] = input;
  for (size_t i = 1; i <= logOfSlots; i++)
  {
    temp[i] = temp[i-1];
    long shiftNums = std::pow(2, i-1);
    ea.rotate(temp[i], shiftNums);
    temp[i] += temp[i-1];
  }

  // Add all rotated ciphertexts, where the last ciphertext is always valid.
  // In other words, ((a>>logOfaSubTwo) & 0x0001) is always equal to 1.
  ekey = temp[logOfSlots];
  int32_t startPoint = (int32_t)0x0001 << logOfSlots;
  for (size_t i = 0; i < logOfSlots; i++)
  {
    if (((slots >> i) & 0x0001) == 1) {
      ea.rotate(temp[i], startPoint);
      ekey += temp[i];
      startPoint += ((int32_t)0x0001 << i);
    }
  }
  ekey.cleanUp();
}


void Transcipher16::handleRoundKeyForThreads(vector<Ctxt>& ekey, const Ctxt& input, const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea, const int32_t len,
  const uint8_t data, const size_t first, const size_t last)
{
  for (size_t i = first; i < last; i++)
  {
    ZZX encodeData;
    vector<GF2X> slots(ea.size(), GF2X::zero());

    long repeats = 1;
    // faster expand for 1920 and 960. Other sizes can also be customized.
    if (ea.size() == 1920 || ea.size() == 960) { 
      repeats = ea.size()/len;
    }
    for (long j=0; j<repeats; j++)
    GF2XFromBytes(slots[i*repeats + j], &data, 1);
    
    ea.encode(encodeData, slots);

    Ctxt tempCtxt(input);
    tempCtxt.multByConstant(encodeData);
    //tempCtxt.cleanUp();

    printf("%3ld ", i); fflush(0);
    handleSingleRoundKey(ekey[i], tempCtxt, hePK, ea);
    slots.clear();
  }
}

void Transcipher16::handleRoundKey(vector<Ctxt>& ekey, const Ctxt& input, const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea, const int32_t len)
{
  uint8_t data = 0x01;// 0x01

  {   
    Ctxt tmpCtxt(hePK);
    ekey.resize(len, tmpCtxt); // len = 240
  } // allocate space
  cout << "handleSingleRoundKey(i-th/" << len << "): (" << endl;
#ifdef expandMultiThreads
  size_t threadsNum = 16; //8, 16, 30
  thread threads[threadsNum];
  size_t threadPerCount = ceil((double)len/threadsNum);

  threadsNum = ceil((double)len / threadPerCount); // update thread numbers
  for (int i=0; i<threadsNum; i++) {
    size_t first = threadPerCount*i;
    size_t last = (i != threadsNum-1)? (threadPerCount*(i+1)): len;
    threads[i] = std::thread(handleRoundKeyForThreads, ref(ekey), ref(input),
      ref(hePK), ref(ea), len, data, first, last);
  }
  for (int i=0; i<threadsNum; i++)
    threads[i].join();

#else // else expandMultiThreads
  for (size_t i = 0; i < len; i++)
  {
    ZZX encodeData;
    vector<GF2X> slots(ea.size(), GF2X::zero());

    long repeats = 1;
    // faster expand for 1920 and 960. Other sizes can also be customized.
    if (ea.size() == 1920 || ea.size() == 960) { 
      repeats = ea.size()/len;
    }
    for (long j=0; j<repeats; j++)
    GF2XFromBytes(slots[i*repeats + j], &data, 1);
    ea.encode(encodeData, slots);

    Ctxt tempCtxt = input;
    tempCtxt.multByConstant(encodeData);

    printf("%3ld ", i); fflush(0);
    handleSingleRoundKey(ekey[i], tempCtxt, hePK, ea);
  }

#endif // end expandMultiThreads

  std::cout << ")" << std::endl;
}
