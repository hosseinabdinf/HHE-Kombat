#include "trans-Yupx-p-C16.h"

using namespace helib;
using namespace std;
using namespace NTL;

Transcipher16_F_p::Transcipher16_F_p(std::shared_ptr<helib::Context> con)
    : context(con),
      he_sk(*context),
      ea(context->getEA()) {
  
  cout << "Transcipher16_F_p init ..." <<endl;
        
  plain_mod = con->getP();

  if (plain_mod > (uint64_t)std::numeric_limits<long>::max())
    throw std::runtime_error("plain size to big for long");

  nslots = ea.size();

  he_sk.GenSecKey();

  // power_of_2_ring = isPowerOfTwo(context->getM());
}

/************************************************************************
  long m;          // m-th cyclotomic polynomial
  long p;          // plaintext primeplain_mod;
  long r;          // Lifting [defualt = 1]
  long L;          // bits in the ciphertext modulus chain
  long c;          // columns in the key-switching matrix [default=2]
  long d;          // Degree of the field extension [default=1]
  long k;          // Security parameter [default=80]
  long s;          // Minimum number of slots [default=0]
************************************************************************/

shared_ptr<Context> Transcipher16_F_p::create_context(
    uint64_t m, uint64_t p, uint64_t r, uint64_t L, uint64_t c, uint64_t d,
    uint64_t k, uint64_t s) {
    cout << "create_context... ";
  if (!m) m = FindM(k, L, c, p, d, s, 0);
    cout << " m =  " << m<<endl;
  return shared_ptr<Context>(ContextBuilder<BGV>()
                                             .m(m)
                                             .p(p)
                                             .r(r)
                                             .bits(L)
                                             .c(c)
                                             .buildPtr());

}

//----------------------------------------------------------------

// int Transcipher16_F_p::print_noise() { return print_noise(secret_key_encrypted); }

//----------------------------------------------------------------

int Transcipher16_F_p::print_noise(vector<Ctxt>& ciphs) {
  int min = ciphs[0].bitCapacity();
  int max = min;
  for (uint64_t i = 1; i < ciphs.size(); i++) {
    int budget = ciphs[i].bitCapacity();
    if (budget > max) max = budget;
    if (budget < min) min = budget;
  }
  cout << "min noise budget: " << min << endl;
  cout << "max noise budget: " << max << endl;
  return min;
}


void Transcipher16_F_p::print_parameters() {
  if (!context) {
    throw std::invalid_argument("context is not set");
  }

  std::cout << "/" << std::endl;
  std::cout << "| Encryption parameters:" << std::endl;
  std::cout << "|   scheme: BGV " << std::endl;
  std::cout << "|   slots: " << context->getNSlots() << std::endl;
  std::cout << "|   bootstrappable: " << context->isBootstrappable()
            << std::endl;
  std::cout << "|   m: " << context->getM() << std::endl;
  std::cout << "|   phi(m): " << context->getPhiM() << std::endl;
  std::cout << "|   plain_modulus: " << context->getP() << std::endl;
  std::cout << "|   cipher mod size (bits): " << context->bitSizeOfQ()
            << std::endl;
  std::cout << "|   total bits: " << context->logOfProduct(context->allPrimes())
            << std::endl;
  std::cout << "|   r: " << context->getR() << std::endl;
  std::cout << "|   sec level: " << context->securityLevel() << std::endl;
  std::cout << "\\" << std::endl;
}

//----------------------------------------------------------------

void Transcipher16_F_p::create_pk() {
  he_pk = std::make_unique<helib::PubKey>(he_sk);
  return;
}


helib::EncryptedArray Transcipher16_F_p::getEa() {
  return ea;
}



//----------------------------------------------------------------
// encrypt the expanded key roundKeySchedule.
void Transcipher16_F_p::encryptSymKey(vector<Ctxt>& eKey, vector<uint64_t>& roundKeySchedule)
{   
    eKey.resize(roundKeySchedule.size(), Ctxt(*he_pk));
    cout<< "ekey.size() = " <<eKey.size() <<endl;

    for (long i=0; i<eKey.size(); i++){ // encrypt the encoded key
      vector<long> slotsData(nslots, roundKeySchedule[i]);
      // cout<<(i+1)%16;
      // printf(". %05lx ",slotsData[0]);
      // if((i+1)%16 ==0) cout<<endl;
      ea.encrypt(eKey[i], *he_pk, slotsData);
    }
      // he_pk.Encrypt(eKey[i], encoded[i]);
}


void Transcipher16_F_p::FHE_YuxDecrypt(vector<Ctxt>& eData, const vector<Ctxt>& symKey) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;
  
  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA);

  // apply the symmetric rounds
  // cout << "homSymDec Begin\n";
  
  for (long j=0; j<(long)eData.size(); j++) eData[j] -= symKey[j];  // initial key addition
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<pROUND; i++){ 
    // S Layer -- 4 sbox

    for(long j = 0; j<4; j++){
      //  decSbox(eData, j, encA);
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
      eData[j] += in[(j+3)%16];
      eData[j] += in[(j+4)%16];
      eData[j] += in[(j+8)%16];
      eData[j] += in[(j+9)%16];
      eData[j] += in[(j+12)%16];
      eData[j] += in[(j+14)%16];

      // add Round Key
      long key_id = BlockWords*i+j;
      eData[j] -= symKey[key_id];
      
    } 
    cout<< "round "<< i << " ";
    print_noise(eData);
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
      long key_id = BlockWords*pROUND+j;
      eData[j] -= symKey[key_id];
    }
  }
  // cout << "homSymDec Finish! \n";
  // return to natural PrimeSet to save memery
  for (int i = 0; i < eData.size(); i++)
    eData[i].bringToSet(eData[i].naturalPrimeSet());
}

void Transcipher16_F_p::FHE_YuxDecrypt(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const Vec<uint64_t> inBytes)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo16Ctxt(encodedBytes, inBytes, nslots); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }

  FHE_YuxDecrypt(eData, symKey); // do the real work
}

// Encode  plaintext/ciphertext bytes as native HE plaintext
// packing
void Transcipher16_F_p::encodeTo16Ctxt(Vec<ZZX>& encData, const Vec<uint64_t>& data, long s)
{
  // 一个分组有16个字
  long nAllBlocks = divc(data.length(), BlockWords); // ceil( data.length()/16 ) =(a + b - 1)/b
  long nCtxt = BlockWords;

  encData.SetLength(nCtxt);

  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<long> slots(ea.size(), 0);
    for (long j=0; j<nAllBlocks; j++) { // j is the block number in this ctxt
      long byteIdx = j*BlockWords+ i; 
      if (byteIdx < data.length()) {
          slots[j] = data[byteIdx];// copy byte as poly
        }
    }
    ea.encode(encData[i], slots);
  }
}



void Transcipher16_F_p::buildRoundConstant(Ctxt& encA)
{
  // long --> ZZX -->Ctxt 
  vector<long> slots(ea.size(), roundConstant);
  ZZX ZZXConstant;
  ea.encode(ZZXConstant, slots);
  encA.DummyEncrypt(ZZXConstant);
}


void Transcipher16_F_p::decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA)
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


void Transcipher16_F_p::decrypt(helib::Ctxt& in, ZZX& out) {
  std::vector<long> p;
  // Vec<ZZX> pp(INIT_SIZE, nslots);
  // ea.decrypt(in, he_sk, out);
  // ea.decrypt(in, he_sk, pp);
  he_sk.Decrypt(out, in);
  // out = p[0];
}

// void Transcipher16_F_p::decrypt(helib::Ctxt& in, Vec<ZZX>& out) {
//   std::vector<long> p;
//   ea.decrypt(in, he_sk, out);
//   // out = p[0];
// }


void Transcipher16_F_p::decodeTo16Ctxt(Vec<uint64_t>& data, const Vec<ZZX>& encData)
{
  long nAllWords = encData.length() * nslots; // ceil( data.length()/16 ) =(a + b - 1)/b
  if (data.length()<=0 || data.length()>nAllWords)
    data.SetLength(nAllWords);


  // 一个分组有16个字
  long nWords = BlockWords;
  long nAllBlocks = divc(data.length(), nWords); // ceil( data.length()/16 ) =(a + b - 1)/b

  long nCtxt = nWords;

  vector<long> slots(ea.size(), 0);
  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    ea.decode(slots, encData[i]);
    for (long j=0; j<nAllBlocks; j++) { // j is the block number in this ctxt
      // long slotIdx = j;
      long byteIdx = i + nWords*j;
      // long byteIdx = j*BlockWords+ i; 
      if (byteIdx < data.length()) {
          data[byteIdx] = slots[j];
          // printf(". %05llx ",data[byteIdx]);
        }
    }  
  }
}
