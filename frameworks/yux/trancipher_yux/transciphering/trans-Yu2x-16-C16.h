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

static long nBlocks = 1;

// lm: I have set the parameters of idx = 0, 4
static long mValues[][5] = { 
//{ p, phi(m),  m,   d, bits}
  { 2,  512,    771, 16, 420}, // m=(3)*{257}
  { 2, 4096,   4369, 16, 360}, // m=17*(257)
  { 2, 16384, 21845, 16, 500}, // m=5*17*(257)
  { 2, 32768, 65535, 16, 620},  // m=97*(673)
  { 2, 23040, 23377, 48, 500},  // m=97*(673)
  { 2, 24576, 30583, 48, 500},
  { 2, 65538, 65537, 32, 700}
};

class Trans_Yu2x_16_16
{
  private:
  long BlockSize_16 = 256;
  long NkGF16 = 16;


  public:

  // Encode plaintext/ciphertext bytes as native HE plaintext
  // packing
  void encodeToKeys(Vec<ZZX>& encData, const Vec<GF2E>& data,
      const EncryptedArrayDerived<PA_GF2>& ea);

  // Encode plaintext/ciphertext bytes as native HE plaintext
  // packing
  void encodeTo32Ctxt(Vec<ZZX>& encData, const Vec<uint8_t>& data,
      const EncryptedArrayDerived<PA_GF2>& ea);

  void decodeTo32Ctxt(Vec<uint8_t>& data, const Vec<ZZX>& encData,
		const EncryptedArrayDerived<PA_GF2>& ea);

  void buildRoundConstant(Ctxt& encA,
    const EncryptedArrayDerived<PA_GF2>& ea);

  void encryptSymKey(vector<Ctxt>& eKey, unsigned char encRoundKeySchedule[], const PubKey& hePK,
  const EncryptedArrayDerived<PA_GF2>& ea, bool key2dec);

  void decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA);

  void homYuxDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey, Ctxt& encA);

  void homSymDec(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
            const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea);

  void encSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA);


  void encSboxFuncV2(vector<Ctxt>& eData, long begin, Ctxt& encA);

  void homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey, Ctxt& encA);

  void homSymEnc(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
            const Vec<uint8_t> inBytes, const EncryptedArrayDerived<PA_GF2>& ea);



};
