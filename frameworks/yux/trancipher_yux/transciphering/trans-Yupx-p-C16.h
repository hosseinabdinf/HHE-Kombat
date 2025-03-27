#include <cstring>
#include <stdint.h>
#include <chrono>
#include <NTL/ZZX.h>
#include <NTL/ZZ.h>
#include <vector>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>

#include "../Yux/Yupx-p.h"
#include "params.h"
#include "utils.h"

using namespace helib;
using namespace std;
using namespace NTL;

// #define multiThreads // 4 threads

// static long nBlocks = 20;

// lm: I have set the parameters of idx = 0, 4
// static long mValues[][5] = { 
// //{ p, phi(m),  m,   d, bits}
//   { 2,  512,    771, 16, 420}, // m=(3)*{257}
//   { 2, 4096,   4369, 16, 360}, // m=17*(257)
//   { 2, 16384, 21845, 16, 410}, // m=5*17*(257)
//   { 2, 23040, 28679, 24, 500}, // m=7*17*(241) bits: 600
//   { 2, 46080, 53261, 24, 630}, // m=13*17*(241) bits: 630 
//   { 2, 64512, 65281, 48, 480}  // m=97*(673)
// };

class Transcipher16_F_p
{


  protected:
  // std::vector<uint64_t> secret_key;
  uint64_t plain_mod;

  std::shared_ptr<helib::Context> context;
  uint64_t nslots;

  // std::vector<helib::Ctxt> secret_key_encrypted;

  helib::SecKey he_sk;
  std::unique_ptr<helib::PubKey> he_pk;
  const helib::EncryptedArray& ea;



public:
  static std::shared_ptr<helib::Context> create_context(
      uint64_t m, uint64_t p, uint64_t r, uint64_t L, uint64_t c,
      uint64_t d = 1, uint64_t k = 128, uint64_t s = 1);
 
  Transcipher16_F_p(std::shared_ptr<helib::Context> con);
  int print_noise();
  int print_noise(vector<Ctxt>& ciphs);
  void print_parameters();
  void create_pk();


  helib::EncryptedArray getEa();
  // run the Yux key-expansion and then encrypt the expanded key.
  void encryptSymKey(vector<Ctxt>& eKey, vector<uint64_t>& roundKeySchedule);

  
  void FHE_YuxDecrypt(vector<Ctxt>& eData, const vector<Ctxt>& symKey);
  void buildRoundConstant(Ctxt& encA);
  // Perform sym encryption on plaintext bytes (ECB mode). The input are
  // raw plaintext bytes, and the sym key encrypted under HE. The output
  // is a doubly-encrypted ciphertext, out=Enc_HE(Enc_Sym(X)). The symKey
  // array contains an encryption of the expanded sym key, the number of
  // sym rounds is YuxKey.size() -1.
  // NOTE: This is a rather useless method, other than for benchmarking
  void FHE_YuxDecrypt(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
      const Vec<uint64_t> inBytes);

  // Encode plaintext/ciphertext bytes as native HE plaintext
  // packing
  void encodeTo16Ctxt(Vec<ZZX>& encData, const Vec<uint64_t>& data, long s);
  void decodeTo16Ctxt(Vec<uint64_t>& data, const Vec<ZZX>& encData);
  void decrypt(helib::Ctxt& in, ZZX& out);
  static void decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA);


};
