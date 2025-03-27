#include <cstring>
#include <stdint.h>
#include <chrono>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>

#include "../Yux/Yu2x-8.h"
#include "params.h"

using namespace helib;
using namespace std;
using namespace NTL;

// #define multiThreads // 4 threads

static long nBlocks = 20;

// lm: I have set the parameters of idx = 0, 4
static long mValues[][5] = { 
//{ p, phi(m),  m,   d, bits}
  { 2,  512,    771, 16, 420}, // m=(3)*{257}
  { 2, 4096,   4369, 16, 360}, // m=17*(257)
  { 2, 16384, 21845, 16, 410}, // m=5*17*(257)
  { 2, 23040, 28679, 24, 500}, // m=7*17*(241) bits: 600
  { 2, 46080, 53261, 24, 630}, // m=13*17*(241) bits: 630 
  { 2, 64512, 65281, 48, 480}  // m=97*(673)
};

class Transcipher16 
{
public:

// Encode plaintext/ciphertext bytes as native HE plaintext
// packing
void encodeToKeys(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea);

// Encode plaintext/ciphertext bytes as native HE plaintext
// packing
void encodeTo16Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea);


// Decode native HE plaintext as Yux plaintext/ciphertext bytes
void decodeTo16Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea);

void buildRoundConstant(Ctxt& encA,
		const EncryptedArrayDerived<PA_GF2>& ea);

// run the Yux key-expansion and then encrypt the expanded key.
void encryptSymKey(vector<Ctxt>& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
    const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec);

static void decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA);

struct thread_data{
   vector<Ctxt> *eData;
   long j;
   Ctxt *encA;
};

static void *decSbox_Pre(void *threadarg);

static void decSbox(vector<Ctxt>& eData, long j, Ctxt& encA);

void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, Ctxt& encA);

// Perform sym encryption on plaintext bytes (ECB mode). The input are
// raw plaintext bytes, and the sym key encrypted under HE. The output
// is a doubly-encrypted ciphertext, out=Enc_HE(Enc_Sym(X)). The symKey
// array contains an encryption of the expanded sym key, the number of
// sym rounds is YuxKey.size() -1.
// NOTE: This is a rather useless method, other than for benchmarking
void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea);

void encSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA);

void encSboxFuncFrobenius(vector<Ctxt>& eData, long begin, Ctxt& encA);

void homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey, Ctxt& encA);

void homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea);


/** 
 * The blow four function help to expand a single ciphertext to multiple ciphertexts
 * who encrypt the round key of block cipher.
 */

// Encode  plaintext/ciphertext bytes as native HE plaintext
// packing
// only for ea.size() > 240, encode to a single ciphertext
void encodeToKeysForExpand(ZZX& encData, const Vec<uint8_t>& data, const int32_t len,
  const EncryptedArrayDerived<PA_GF2>& ea);

// run the Yux key-expansion and then encrypt the expanded key.
void encryptSymKeyForExpand(Ctxt& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec);

static void handleSingleRoundKey(Ctxt& ekey, const Ctxt& input, const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea);

static void handleRoundKeyForThreads(std::vector<Ctxt>& ekey, const Ctxt& input, const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea, const int32_t len,
  const uint8_t data, const size_t first, const size_t last);

void handleRoundKey(std::vector<Ctxt>& ekey, const Ctxt& input, const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea, const int32_t len);

};
