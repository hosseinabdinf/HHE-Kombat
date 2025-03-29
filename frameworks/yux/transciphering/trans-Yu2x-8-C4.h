#include <cstring>
#include <stdint.h>
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

static long nBlocks = 12;

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

class Transcipher4
{
public:

// Encode plaintext/ciphertext bytes as native HE plaintext
void encodeTo4Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
		const EncryptedArrayDerived<PA_GF2>& ea);

// Decode native HE plaintext as Yux plaintext/ciphertext bytes
void decodeTo4Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea);

void buildRoundConstant(Ctxt& encA,
			const EncryptedArrayDerived<PA_GF2>& ea);

// run the Yux key-expansion and then encrypt the expanded key.
void encryptSymKey(vector<Ctxt>& eKey, Vec<uint8_t>& symKey, const PubKey& hePK,
    const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec);

void decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea);

void decLinearFunc(vector<Ctxt>& eData, long begin, const EncryptedArrayDerived<PA_GF2>& ea);

void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const EncryptedArrayDerived<PA_GF2>& ea);

// Perform sym encryption on plaintext bytes (ECB mode). The input are
// raw plaintext bytes, and the sym key encrypted under HE. The output
// is a doubly-encrypted ciphertext, out=Enc_HE(Enc_Sym(X)). The symKey
// array contains an encryption of the expanded sym key, the number of
// sym rounds is YuxKey.size() -1.
// NOTE: This is a rather useless method, other than for benchmarking
void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea);

void encSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA, const EncryptedArrayDerived<PA_GF2>& ea);

void encLinearFunc(vector<Ctxt>& eData, long begin, const EncryptedArrayDerived<PA_GF2>& ea);

void homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const EncryptedArrayDerived<PA_GF2>& ea);

void homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
		       const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea);

};
