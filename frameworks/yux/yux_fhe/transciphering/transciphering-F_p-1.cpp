#include "transciphering-F_p-1.h"

using namespace helib;
using namespace std;
using namespace NTL;

Transcipher1_F_p::Transcipher1_F_p(std::shared_ptr<helib::Context> con)
    : context(con), he_sk(*context), ea(context->getEA()) {

  cout << "Transcipher1_F_p init ..." << endl;

  plain_mod = con->getP();

  if (plain_mod > (uint64_t)std::numeric_limits<long>::max())
    throw std::runtime_error("plain size to big for long");

  nslots = ea.size();

  he_sk.GenSecKey();
  // Add key-switching matrices for the automorphisms that we need

  long ord = con->getZMStar().OrderOf(0);
  for (long i = 1; i < 16; i++) { // rotation along 1st dim by size i*ord/16
    long exp = i * ord / 16;
    long val = PowerMod(con->getZMStar().ZmStarGen(0), exp,
                        con->getM()); // val = g^exp

    // From s(X^val) to s(X)
    he_sk.GenKeySWmatrix(1, val);
    if (!con->getZMStar().SameOrd(0))
      // also from s(X^{1/val}) to s(X)
      he_sk.GenKeySWmatrix(1, InvMod(val, con->getM()));
  }

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

shared_ptr<Context> Transcipher1_F_p::create_context(uint64_t m, uint64_t p,
                                                     uint64_t r, uint64_t L,
                                                     uint64_t c, uint64_t d,
                                                     uint64_t k, uint64_t s) {
  cout << "create_context... ";
  if (!m)
    m = FindM(k, L, c, p, d, s, 0);
  cout << " m =  " << m << endl;
  bool TTT = m && (!(m & (m - 1)));
  cout << "!!!!!!!!!!!!!!!!!!!!!!!!TTT = " << TTT << endl;
  return shared_ptr<Context>(
      ContextBuilder<BGV>().m(m).p(p).r(r).bits(L).c(c).buildPtr());
}

//----------------------------------------------------------------

// int Transcipher1_F_p::print_noise() { return
// print_noise(secret_key_encrypted); }

//----------------------------------------------------------------

int Transcipher1_F_p::print_noise(vector<Ctxt> &ciphs) {
  int min = ciphs[0].bitCapacity();
  int max = min;
  for (uint64_t i = 1; i < ciphs.size(); i++) {
    int budget = ciphs[i].bitCapacity();
    if (budget > max)
      max = budget;
    if (budget < min)
      min = budget;
  }
  cout << "min noise budget: " << min << endl;
  cout << "max noise budget: " << max << endl;
  return min;
}

void Transcipher1_F_p::print_parameters() {
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
  std::cout << "|   r: " << context->getR() << std::endl;
  std::cout << "|   sec level: " << context->securityLevel() << std::endl;
  std::cout << "\\" << std::endl;
}

//----------------------------------------------------------------

void Transcipher1_F_p::create_pk() {
  addSome1DMatrices(he_sk);
  he_pk = std::make_unique<helib::PubKey>(he_sk);
  return;
}

helib::EncryptedArray Transcipher1_F_p::getEa() { return ea; }

//----------------------------------------------------------------
// encrypt the expanded key roundKeySchedule.
void Transcipher1_F_p::encryptSymKey(vector<Ctxt> &eKey,
                                     vector<uint64_t> &roundKeySchedule) {
  eKey.resize(pROUND + 1, Ctxt(*he_pk));
  cout << "ekey.size() = " << eKey.size() << endl;

  long blocksPerCtxt = ea.size() / BlockWords;

  for (long i = 0; i < eKey.size(); i++) { // encrypt the encoded key
    vector<long> slotsData(0);
    for (long j = 0; j < blocksPerCtxt; j++) {
      slotsData.insert(slotsData.begin() + j * BlockWords,
                       roundKeySchedule.begin() + i * BlockWords,
                       roundKeySchedule.begin() + (i + 1) * BlockWords);
    }
    slotsData.resize(nslots);
    // if(i<=10) {
    //   printState_p(slotsData);
    // }
    ea.encrypt(eKey[i], *he_pk, slotsData);
  }
  // he_pk.Encrypt(eKey[i], encoded[i]);
}

// Compute the constants for Sbox
void Transcipher1_F_p::buildLinEnc2(vector<ZZX> &encLinTran) {
  // encLinTran[0]: The constants only have nonzero entires in their slots
  // corresponding to bytes 3,7,11,15 of each blocks // 0001000100010001
  // encLinTran[1]: The constants only have nonzero entires in their slots
  // corresponding to bytes 2,6,10,14 of each blocks // 0010001000100010
  // encLinTran[1]: The constants only have zero entires in their slots
  // corresponding to bytes 01,45,89,1213 of each blocks, others is 1;
  // //1100110011001100

  Vec<uint64_t> locates(INIT_SIZE, ea.size());
  long blocksPerCtxt = ea.size() / 16;
  Vec<ZZX> tmp;

  memset(locates.data(), 0, locates.length());
  /*
    void Transcipher1::*memset(void Transcipher1::*s, int ch, size_t n);
    函数解释：将s中前n个字节 （typedef unsigned int size_t）用 ch 替换并返回 s
    讲bytes设置为0
  */
  for (long j = 0; j < blocksPerCtxt; j++) {
    uint64_t *bptr = &locates[16 * j];
    bptr[3] = bptr[7] = bptr[11] = bptr[15] = 1;
  }
  encodeTo1Ctxt(tmp, locates);
  encLinTran[0] = tmp[0];

  memset(locates.data(), 0, locates.length());
  for (long j = 0; j < blocksPerCtxt; j++) {
    uint64_t *bptr = &locates[16 * j];
    bptr[2] = bptr[6] = bptr[10] = bptr[14] = 1;
  }
  encodeTo1Ctxt(tmp, locates);
  encLinTran[1] = tmp[0];

  memset(locates.data(), 0, locates.length());
  for (long j = 0; j < blocksPerCtxt; j++) {
    uint64_t *bptr = &locates[16 * j];
    bptr[0] = bptr[1] = bptr[4] = bptr[5] = 1;
    bptr[8] = bptr[9] = bptr[12] = bptr[13] = 1;
  }
  encodeTo1Ctxt(tmp, locates);
  encLinTran[2] = tmp[0];
}

void Transcipher1_F_p::decSboxFunc2(Ctxt &c, vector<ZZX> encLinTran,
                                    Ctxt &encA) {
  // The basic rotation amount along the 1st dimension
  long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 16;

  const ZZX &p3 = encLinTran[0];  // 0001000100010001
  const ZZX &p2 = encLinTran[1];  // 0010001000100010
  const ZZX &p01 = encLinTran[2]; // 1100110011001100

  c.cleanUp();
  Ctxt c1(c), c2(c), c15(c);
  ea.shift(c1, 1);
  ea.shift(c2, 2);
  ea.rotate(c15, -1);
  c1.cleanUp();
  c2.cleanUp();
  c15.cleanUp();

  c1.multiplyBy(c);
  c1 += c2;
  c1 += encA;

  Ctxt y3(c1);

  y3.multByConstant(p3);

  c15 += c1;
  c15.multByConstant(p2);
  Ctxt y2(c15);
  ea.shift(c15, 1);
  c15.cleanUp();
  y3 += c15;

  ea.rotate(c, 14);
  c.cleanUp();
  c.multByConstant(p01);
  c += y2;
  c += y3;
  c.cleanUp();
}

void Transcipher1_F_p::FHE_YuxDecrypt(vector<Ctxt> &eData,
                                      const vector<Ctxt> &symKey) {
  if (1 > (long)eData.size() || 1 > (long)symKey.size())
    return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;

  Ctxt encA(ZeroCtxtLike, symKey[0]);
  buildRoundConstant(encA);

  vector<ZZX> encLinTran;
  encLinTran.resize(3);
  buildLinEnc2(encLinTran);

  // apply the symmetric rounds
  // cout << "homSymDec Begin\n";

  for (long j = 0; j < (long)eData.size(); j++)
    eData[j] -= symKey[0]; // initial key addition

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i = 1; i < pROUND; i++) {
    for (long j = 0; j < (long)eData.size(); j++) {
      // // S Layer
      for (long step = 0; step < 2; step++)
        decSboxFunc2(eData[j], encLinTran, encA);
      // Linear Layer
      // Linear_function(eData[j]);
      // Add round key
      eData[j] -= symKey[i];
    }
    cout << "round " << i << " ";
    print_noise(eData);
  }
  // The last round is given below.
  // Linear layer is not here in the last round
  {
    for (long j = 0; j < (long)eData.size(); j++) {

      // S Layer
      for (long step = 0; step < 2; step++)
        decSboxFunc2(eData[j], encLinTran, encA);
      // Add round key
      eData[j] -= symKey[pROUND];
    }
  }
  // cout << "homSymDec Finish! \n";
  // return to natural PrimeSet to save memery
  for (int i = 0; i < eData.size(); i++)
    eData[i].bringToSet(eData[i].naturalPrimeSet());
}

void Transcipher1_F_p::Linear_function(Ctxt &c) {
  // The basic rotation amount along the 1st dimension
  long rotAmount = ea.getContext().getZMStar().OrderOf(0) / BlockWords;
  cout << "rotAmount " << rotAmount << endl;
  c.cleanUp();
  // 循环左移   3  4  8 9 12 14
  // 即循环右移 13 12 8 7  4  2
  Ctxt c3(c), c4(c), c8(c), c9(c), c12(c), c14(c);
  // ea.rotate1D(c3, 0, 13*rotAmount);
  // ea.rotate1D(c4, 0, 12*rotAmount);
  // ea.rotate1D(c8, 0, 8*rotAmount);
  // ea.rotate1D(c9, 0, 7*rotAmount);
  // ea.rotate1D(c12, 0, 4*rotAmount);
  ea.rotate1D(c14, 0, 2 * rotAmount);

  // c3.cleanUp();  c4.cleanUp(); c8.cleanUp();
  // c9.cleanUp();  c12.cleanUp();  c14.cleanUp();

  // c +=c3;
  // c +=c4; c +=c8; c +=c9; c +=c12;
  c += c14;
  c.cleanUp();
}

void Transcipher1_F_p::FHE_YuxDecrypt(vector<Ctxt> &eData,
                                      const vector<Ctxt> &symKey,
                                      const Vec<uint64_t> inBytes) {
  {
    Vec<ZZX> encodedBytes;
    encodeTo1Ctxt(encodedBytes, inBytes); // encode as HE plaintext
    // Allocate space for the output ciphertexts, initialized to zero
    // eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike, symKey[0]));
    for (long i = 0; i < (long)eData.size(); i++) // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }
  //-----------------------------------------------------------------------------
  long rotAmount = ea.getContext().getZMStar().OrderOf(0) / 16;
  cout << " dimension() = " << ea.dimension() << endl;
  // ea.rotate(eData[0],1);
  ea.rotate1D(eData[0], 0, 1);

  eData[0].cleanUp();

  // eData[0].smartAutomorph(context->getPhiM()-1);
  // rotate(eData[0], 13);

  //------------------------------------------------------------------------

  // FHE_YuxDecrypt(eData, symKey); // do the real work
}

//----------------------------------------------------------------
void Transcipher1_F_p::rotate_rows(helib::Ctxt &ctxt, long step) {
  ctxt.smartAutomorph(get_elt_from_step(step));
}

//----------------------------------------------------------------

void Transcipher1_F_p::rotate_columns(helib::Ctxt &ctxt) {
  ctxt.smartAutomorph(context->getPhiM() - 1);
}

//----------------------------------------------------------------

void Transcipher1_F_p::rotate(helib::Ctxt &ctxt, long step) {
  rotate_rows(ctxt, step);
}

//----------------------------------------------------------------

long Transcipher1_F_p::get_elt_from_step(long step) {
  long n2 = nslots << 1;
  long row_size = nslots >> 1;
  if (!step)
    return context->getPhiM() - 1;
  long sign = step < 0;
  long step_abs = sign ? -step : step;
  if (step_abs >= row_size)
    throw std::runtime_error("error: step count too large!");
  step = sign ? row_size - step_abs : step_abs;

  long gen = 3;
  long elt = 1;
  for (long i = 0; i < step; i++)
    elt = (elt * gen) % n2;
  return elt;
}

// Encode plaintext/ciphertext bytes as native HE plaintext
void Transcipher1_F_p::encodeTo1Ctxt(Vec<ZZX> &encData,
                                     const Vec<uint64_t> &data) {
  long nAllBlocks = divc(data.length(), BlockWords); // ceil( data.length()/16 )
  cout << "nBlocks = " << nAllBlocks << endl;
  long blocksPerCtxt = ea.size() / 16; // = nSlots/16
  long nCtxt = divc(nAllBlocks, blocksPerCtxt);

  // We encode blocksPerCtxt = n/16 blocks in the slots of one ctxt.
  encData.SetLength(nCtxt);

  for (long i = 0; i < nCtxt; i++) { // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<long> slotsData(0);
    for (long j = 0; j < blocksPerCtxt;
         j++) { // j is the block number in this ctxt
      long beginIdx = (i * blocksPerCtxt + j) * BlockWords; // point to block
      slotsData.insert(slotsData.begin() + j * BlockWords,
                       data.begin() + beginIdx + i * BlockWords,
                       data.begin() + beginIdx + (i + 1) * BlockWords);
    }
    slotsData.resize(nslots);
    if (i <= 10) {
      printState_p(slotsData);
    }
    ea.encode(encData[i], slotsData);
  }
}

void Transcipher1_F_p::buildRoundConstant(Ctxt &encA) {
  // long --> ZZX -->Ctxt
  vector<long> slots(ea.size(), roundConstant);
  ZZX ZZXConstant;
  ea.encode(ZZXConstant, slots);
  encA.DummyEncrypt(ZZXConstant);
}

vector<long> Transcipher1_F_p::decrypt(helib::Ctxt &in, long n) {
  vector<long> p;
  ea.decrypt(in, he_sk, p);
  p.resize(n);
  return p;
}
